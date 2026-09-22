import concurrent.futures
import ipaddress
import urllib.error
import urllib.parse
import urllib.request

import defusedxml.ElementTree
from defusedxml import DefusedXmlException
from scapy.all import IP, UDP, AsyncSniffer, Ether, Raw, sendp

from lantern.constants import ENCODING, SSDP, WEB
from lantern.logger import logger
from lantern.sanitize import sanitize_name
from lantern.scope import is_in_scope, require_read_only

# Scan-scoped caches. ``_locations`` maps a responder IP to its description
# URL and ``_names`` to the name parsed from it. ``_discovery_done`` records
# whether a single broadcast M-SEARCH already covered the whole subnet.
_locations = {}
_names = {}
_discovery_done = False


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse redirects so a LAN device cannot bounce the fetch off-subnet."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        logger.debug("Refusing SSDP description redirect to {}", newurl)
        return None


_opener = urllib.request.build_opener(_NoRedirects)


def _allowed_location(location):
    """Return ``location`` when it is a safe, in-scope description URL.

    The URL comes from an untrusted SSDP response, so it must be plain HTTP(S),
    carry no embedded credentials, and name an in-scope IP literal. This blocks
    ``file://`` (and other local schemes), loopback/link-local targets such as
    the cloud metadata service, and hostnames that could rebound off-subnet.
    """
    if not location:
        return None

    try:
        parsed = urllib.parse.urlparse(location)
    except ValueError:
        logger.debug("Ignoring unparseable SSDP location {!r}", location)
        return None

    if parsed.scheme.lower() not in SSDP.ALLOWED_SCHEMES:
        logger.debug("Ignoring SSDP location with scheme {!r}", parsed.scheme)
        return None
    if parsed.username or parsed.password:
        logger.debug("Ignoring SSDP location with embedded credentials")
        return None

    host = parsed.hostname
    try:
        ipaddress.ip_address(host)
    except (TypeError, ValueError):
        logger.debug("Ignoring SSDP location with non-IP host {!r}", host)
        return None
    if not is_in_scope(host):
        logger.debug("Ignoring out-of-scope SSDP location {}", location)
        return None

    return location


def reset_ssdp_cache():
    """Drop scan-scoped SSDP results before a new scan."""
    global _discovery_done
    _locations.clear()
    _names.clear()
    _discovery_done = False


def parse_ssdp_location(payload):
    """Pull the LOCATION header URL out of an SSDP M-SEARCH response."""
    try:
        text = payload.decode(ENCODING, errors="ignore")
    except Exception:
        return None

    for line in text.splitlines():
        if line.lower().startswith(SSDP.LOCATION_HEADER):
            return line.split(":", 1)[1].strip()

    logger.trace("No LOCATION header in SSDP response")
    return None


def parse_ssdp_description(body):
    """Extract a device name from a UPnP device description XML document."""
    try:
        # defusedxml rejects DTDs/entities, so a hostile description cannot
        # trigger entity-expansion ("billion laughs") memory exhaustion.
        root = defusedxml.ElementTree.fromstring(body)
    except (defusedxml.ElementTree.ParseError, DefusedXmlException) as error:
        logger.trace("Malformed SSDP description: {}", error)
        return None

    fields = {}
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1].lower()
        if tag in SSDP.NAME_FIELDS and element.text and tag not in fields:
            text = sanitize_name(element.text)
            if text:
                fields[tag] = text

    for field in SSDP.NAME_FIELDS:
        if field in fields:
            return fields[field]

    logger.trace("SSDP description had no usable name fields")
    return None


def get_ssdp_description(location, timeout=SSDP.HTTP_TIMEOUT):
    """Download a UPnP device description and pull a friendly name from it."""
    location = _allowed_location(location)
    if location is None:
        return None

    logger.debug("Fetching SSDP description from {}", location)
    request = urllib.request.Request(
        location,
        headers={WEB.USER_AGENT_HEADER: WEB.USER_AGENT},
    )
    try:
        response = _opener.open(request, timeout=timeout)
    except Exception as error:
        logger.trace("SSDP description request to {} failed: {}", location, error)
        return None

    try:
        body = response.read(SSDP.MAX_BYTES)
    except Exception as error:
        logger.trace("Could not read SSDP description from {}: {}", location, error)
        return None
    finally:
        response.close()

    return parse_ssdp_description(body)


def _ssdp_search(timeout):
    """Broadcast one M-SEARCH and return every ``(ip, location)`` seen."""
    require_read_only("ssdp search")

    request = (
        f"{SSDP.SEARCH_METHOD} {SSDP.SEARCH_TARGET} HTTP/1.1\r\n"
        f"HOST: {SSDP.ADDR}:{SSDP.PORT}\r\n"
        f'MAN: "{SSDP.MAN}"\r\n'
        f"MX: {SSDP.MX}\r\n"
        f"ST: {SSDP.SEARCH_ST}\r\n"
        "\r\n"
    ).encode(ENCODING)

    # Like mDNS, UPnP replies are delivered asynchronously (after a random MX
    # delay) and may not be unicast to a connected socket, so send the query at
    # the link layer and sniff the multicast group for answers ourselves.
    query = (
        Ether(dst=SSDP.MAC)
        / IP(dst=SSDP.ADDR, ttl=SSDP.TTL)
        / UDP(sport=SSDP.PORT, dport=SSDP.PORT)
        / Raw(load=request)
    )

    found = []

    def handle(pkt):
        if (
            pkt.haslayer(IP)
            and pkt.haslayer(UDP)
            and pkt.haslayer(Raw)
            and pkt[UDP].sport == SSDP.PORT
        ):
            location = parse_ssdp_location(pkt[Raw].load)
            if location:
                found.append((pkt[IP].src, location))

    sniffer = AsyncSniffer(
        filter=f"udp port {SSDP.PORT}",
        prn=handle,
        store=False,
        timeout=timeout,
        started_callback=lambda: sendp(query, verbose=False),
    )
    sniffer.start()
    sniffer.join()
    return found


def discover_ssdp(timeout=SSDP.TIMEOUT):
    """Cover the whole subnet with one M-SEARCH and cache IPs to locations."""
    global _discovery_done
    logger.debug("Discovering SSDP/UPnP devices on the LAN")
    for ip_address, location in _ssdp_search(timeout):
        if not is_in_scope(ip_address):
            logger.debug("Ignoring out-of-scope SSDP responder {}", ip_address)
            continue
        _locations.setdefault(ip_address, location)
    _discovery_done = True
    logger.debug("SSDP discovery found {} device(s)", len(_locations))
    return dict(_locations)


def resolve_ssdp_names():
    """Fetch every discovered description once and cache the parsed names.

    Descriptions are independent HTTP round-trips, so they are fetched
    concurrently; names are merged on this thread to keep the cache single-writer.
    """
    targets = [
        (ip_address, location)
        for ip_address, location in list(_locations.items())
        if ip_address not in _names and is_in_scope(ip_address)
    ]
    if not targets:
        return dict(_names)

    workers = min(SSDP.MAX_FETCH_WORKERS, len(targets))
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=workers, thread_name_prefix="ssdp-name"
    ) as pool:
        fetched = pool.map(
            lambda pair: (pair[0], get_ssdp_description(pair[1])), targets
        )
        for ip_address, name in fetched:
            if name:
                _names[ip_address] = name

    return dict(_names)


def get_ssdp_name(ip_address, timeout=SSDP.TIMEOUT):
    """Return a device's UPnP name, reusing the scan-scoped discovery cache."""
    if ip_address in _names:
        return _names[ip_address]

    location = _locations.get(ip_address)
    if location:
        name = get_ssdp_description(location)
        if name:
            logger.debug("SSDP resolved {} as {!r}", ip_address, name)
            _names[ip_address] = name
        return name

    if _discovery_done:
        return None

    # No scan-scoped discovery ran: fall back to a targeted per-host search.
    logger.debug("Querying SSDP/UPnP for IP: {}", ip_address)
    for found_ip, found_location in _ssdp_search(timeout):
        if found_ip != ip_address:
            continue
        name = get_ssdp_description(found_location)
        if name:
            logger.debug("SSDP resolved {} as {!r}", ip_address, name)
            _names[ip_address] = name
            return name

    logger.debug("No SSDP response for {}", ip_address)
    return None
