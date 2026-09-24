from scapy.all import DNS, DNSQR, IP, UDP, AsyncSniffer, Ether, sendp

from lantern.constants import ENCODING, MDNS
from lantern.logger import logger
from lantern.metadata import MODEL, OS, SERIAL, SERVICES, VERSION, record
from lantern.resolvers.dns_common import dns_answers, ptr_name, reverse_arpa
from lantern.sanitize import sanitize_name


def _mdns_query(qnames, timeout):
    """Send link-layer mDNS PTR queries and return the responses seen.

    mDNS queries go to a multicast group at the link layer with TTL 255, and
    answers are multicast back rather than unicast to the sender. scapy's
    sr1/srp cannot match those replies, so send the query and sniff for the
    responses ourselves.
    """
    responses = []

    def handle(pkt):
        if (
            pkt.haslayer(IP)
            and pkt.haslayer(DNS)
            and pkt[DNS].qr == MDNS.DNS_RESPONSE
            and pkt[DNS].ancount > 0
        ):
            responses.append(pkt)

    def send_queries():
        for qname in qnames:
            query = (
                Ether(dst=MDNS.MAC)
                / IP(dst=MDNS.ADDR, ttl=MDNS.TTL)
                / UDP(sport=MDNS.PORT, dport=MDNS.PORT)
                / DNS(
                    id=MDNS.QUERY_ID,
                    qr=MDNS.DNS_QUERY,
                    qd=DNSQR(qname=qname, qtype=MDNS.PTR_RECORD),
                )
            )
            sendp(query, verbose=False)

    sniffer = AsyncSniffer(
        filter=f"udp port {MDNS.PORT}",
        prn=handle,
        store=False,
        timeout=timeout,
        started_callback=send_queries,
    )
    sniffer.start()
    sniffer.join()
    return responses


def get_mdns_name(ip_address, timeout=MDNS.TIMEOUT):
    """Ask nearby devices to reverse-resolve an IP over mDNS (Bonjour)."""
    logger.debug("Querying mDNS name for IP: {}", ip_address)
    arpa_ip = reverse_arpa(ip_address, MDNS.REVERSE_SUFFIX)

    responses = _mdns_query([arpa_ip], timeout)

    replies = [pkt for pkt in responses if pkt[IP].src == ip_address]
    if not replies:
        logger.debug("No mDNS response for {}", ip_address)
        return None

    for reply in replies:
        name = ptr_name(reply)
        if name:
            return name
    return None


def _mdns_instance_name(answer):
    """Turn a service PTR answer into the friendly instance label."""
    rdata = getattr(answer, "rdata", None)
    if not isinstance(rdata, bytes):
        return None

    instance = rdata.decode(ENCODING).rstrip(".")
    if not instance:
        return None

    service = getattr(answer, "rrname", None)
    if isinstance(service, bytes):
        service = service.decode(ENCODING).rstrip(".")
        suffix = f".{service}"
        if service and instance.lower().endswith(suffix.lower()):
            instance = instance[: -len(suffix)]

    return sanitize_name(instance.rstrip("."))


# TXT keys mDNS responders advertise, mapped to the canonical fact they name.
_TXT_KEY_TO_METADATA = {
    "model": MODEL,
    "am": MODEL,
    "md": MODEL,
    "os": OS,
    "osvers": OS,
    "ver": VERSION,
    "version": VERSION,
    "deviceid": SERIAL,
}


def _txt_chunks(rdata):
    """Split length-prefixed TXT rdata into its strings; [] if malformed."""
    chunks = []
    offset = 0
    while offset < len(rdata):
        length = rdata[offset]
        offset += 1
        if offset + length > len(rdata):
            return []
        chunks.append(rdata[offset : offset + length])
        offset += length
    return chunks


def _txt_pairs(rdata):
    """Parse TXT record data into ``(key, value)`` pairs; malformed yields [].

    On the wire TXT is a sequence of length-prefixed strings, but scapy may
    hand us the raw blob, a list of already-unpacked strings, or a plain
    string, so every shape is handled defensively.
    """
    if isinstance(rdata, bytes):
        chunks = _txt_chunks(rdata)
    elif isinstance(rdata, (list, tuple)):
        chunks = []
        for item in rdata:
            if isinstance(item, bytes):
                parsed = _txt_chunks(item)
                chunks.extend(parsed if parsed else [item])
            elif isinstance(item, str):
                chunks.append(item)
            else:
                return []
    elif isinstance(rdata, str):
        chunks = rdata.split("\x00")
    else:
        return []

    pairs = []
    for chunk in chunks:
        text = chunk if isinstance(chunk, str) else chunk.decode(ENCODING, "replace")
        key, sep, value = text.partition("=")
        if sep and key:
            pairs.append((key, value))
    return pairs


def _service_type(rrname):
    """Extract the service type ("_airplay._tcp") from a record name, or None."""
    if isinstance(rrname, bytes):
        try:
            rrname = rrname.decode(ENCODING)
        except UnicodeDecodeError:
            return None
    if not isinstance(rrname, str):
        return None

    labels = rrname.rstrip(".").split(".")
    if not labels or labels[-1].lower() != "local":
        return None
    for index, label in enumerate(labels[:-1]):
        if label.lower() not in ("_tcp", "_udp"):
            continue
        if index == 0:
            return None
        return ".".join(labels[index - 1 : -1])
    return None


def _discovered_service_types(responses):
    """Service types named by the meta-query (`_services._dns-sd._udp.local`).

    The meta-query answers are PTR records whose owner name is the browse
    service and whose rdata is a service type (`_miio._udp.local`). Those are
    the types the LAN actually advertises, so they let the browse cover devices
    whose type is not in the static list without hardcoding every one.
    """
    discovered = set()
    for reply in responses:
        for answer in dns_answers(reply):
            if getattr(answer, "type", None) != MDNS.PTR_TYPE:
                continue
            rrname = getattr(answer, "rrname", None)
            if isinstance(rrname, bytes):
                try:
                    rrname = rrname.decode(ENCODING)
                except UnicodeDecodeError:
                    continue
            if not isinstance(rrname, str) or rrname.rstrip(".") != MDNS.SERVICE_BROWSE:
                continue
            service = _full_service_type(getattr(answer, "rdata", None))
            if service:
                discovered.add(service)
    return discovered


def _full_service_type(rdata):
    """Decode a meta-query rdata into a full ``_x._tcp.local`` name, or None."""
    if isinstance(rdata, bytes):
        try:
            rdata = rdata.decode(ENCODING)
        except UnicodeDecodeError:
            return None
    if not isinstance(rdata, str):
        return None
    name = rdata.rstrip(".")
    if not name.endswith(".local") or _service_type(name) is None:
        return None
    return name


def _record_txt_metadata(ip_address, rdata):
    """Record model/OS/version/serial facts from a service's TXT record."""
    try:
        for key, value in _txt_pairs(rdata):
            fact = _TXT_KEY_TO_METADATA.get(key.lower())
            if fact:
                record(ip_address, fact, value, "mDNS")
    except Exception:
        logger.debug("Ignoring malformed mDNS TXT record from {}", ip_address)


_mdns_service_cache = None


def reset_mdns_service_cache():
    """Drop the per-scan mDNS browse results before a new scan."""
    global _mdns_service_cache
    _mdns_service_cache = None


def browse_mdns_services(timeout=MDNS.BROWSE_TIMEOUT):
    """Browse common mDNS service types once and map responder IPs to names."""
    global _mdns_service_cache
    if _mdns_service_cache is not None:
        return _mdns_service_cache

    logger.debug("Browsing mDNS services on the LAN")
    qnames = [MDNS.SERVICE_BROWSE, *MDNS.SERVICE_TYPES]
    responses = _mdns_query(qnames, timeout)

    # The meta-query answer tells us which types this LAN advertises; browse
    # any we did not already ask for in a second pass, so new or unusual stacks
    # are discovered instead of being missed by a hardcoded list.
    known = {service.lower() for service in MDNS.SERVICE_TYPES}
    extra = sorted(
        service
        for service in _discovered_service_types(responses)
        if service.lower() not in known
    )[: MDNS.MAX_DISCOVERED_TYPES]
    if extra:
        logger.debug("Browsing {} extra mDNS service type(s): {}", len(extra), extra)
        responses = [*responses, *_mdns_query(extra, timeout)]

    services = {}
    service_types = {}
    for reply in responses:
        ip = reply[IP].src
        for answer in dns_answers(reply):
            answer_type = getattr(answer, "type", None)
            if answer_type == MDNS.TXT_TYPE:
                _record_txt_metadata(ip, getattr(answer, "rdata", None))
                continue

            if answer_type == MDNS.SRV_TYPE:
                service = _service_type(getattr(answer, "rrname", None))
                if service:
                    seen = service_types.setdefault(ip, [])
                    if service not in seen:
                        seen.append(service)
                continue

            if answer_type != MDNS.PTR_TYPE:
                continue

            service = getattr(answer, "rrname", b"")
            if isinstance(service, bytes):
                service = service.decode(ENCODING)
            # Meta-query answers list service types, not device instances.
            if service.rstrip(".") == MDNS.SERVICE_BROWSE:
                continue

            name = _mdns_instance_name(answer)
            if name and ip not in services:
                services[ip] = name

    for ip, types in service_types.items():
        if types:
            record(ip, SERVICES, "; ".join(types), "mDNS")

    logger.debug("mDNS browse identified {} device(s)", len(services))
    _mdns_service_cache = services
    return services


def get_mdns_service_name(ip_address):
    """Look up a name from the mDNS service browse (e.g. "Living Room TV")."""
    logger.debug("Checking mDNS service browse for IP: {}", ip_address)
    name = browse_mdns_services().get(ip_address)
    if name:
        logger.debug("mDNS service browse resolved {} as {!r}", ip_address, name)
    return name
