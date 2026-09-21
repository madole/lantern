import urllib.error
import urllib.request
import xml.etree.ElementTree

from scapy.all import IP, UDP, AsyncSniffer, Ether, Raw, sendp

from network_lister.constants import ENCODING, SSDP, WEB
from network_lister.logger import logger


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
        root = xml.etree.ElementTree.fromstring(body)
    except xml.etree.ElementTree.ParseError as error:
        logger.trace("Malformed SSDP description: {}", error)
        return None

    fields = {}
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1].lower()
        if tag in SSDP.NAME_FIELDS and element.text and tag not in fields:
            text = element.text.strip()
            if text:
                fields[tag] = text

    for field in SSDP.NAME_FIELDS:
        if field in fields:
            return fields[field]

    logger.trace("SSDP description had no usable name fields")
    return None


def get_ssdp_description(location, timeout=SSDP.HTTP_TIMEOUT):
    """Download a UPnP device description and pull a friendly name from it."""
    logger.debug("Fetching SSDP description from {}", location)
    request = urllib.request.Request(
        location,
        headers={WEB.USER_AGENT_HEADER: WEB.USER_AGENT},
    )
    try:
        response = urllib.request.urlopen(request, timeout=timeout)
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


def get_ssdp_name(ip_address, timeout=SSDP.TIMEOUT):
    """Discover a device's UPnP name by broadcasting an SSDP search on the LAN."""
    logger.debug("Querying SSDP/UPnP for IP: {}", ip_address)
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

    locations = []

    def handle(pkt):
        if (
            pkt.haslayer(IP)
            and pkt.haslayer(UDP)
            and pkt.haslayer(Raw)
            and pkt[IP].src == ip_address
            and pkt[UDP].sport == SSDP.PORT
        ):
            location = parse_ssdp_location(pkt[Raw].load)
            if location:
                locations.append(location)

    sniffer = AsyncSniffer(
        filter=f"udp port {SSDP.PORT}",
        prn=handle,
        store=False,
        timeout=timeout,
        started_callback=lambda: sendp(query, verbose=False),
    )
    sniffer.start()
    sniffer.join()

    for location in locations:
        name = get_ssdp_description(location)
        if name:
            logger.debug("SSDP resolved {} as {!r}", ip_address, name)
            return name

    if not locations:
        logger.debug("No SSDP response for {}", ip_address)
    return None
