from scapy.all import DNS, DNSQR, IP, UDP, AsyncSniffer, Ether, sendp

from lantern.constants import ENCODING, MDNS
from lantern.logger import logger
from lantern.resolvers.dns_common import dns_answers, ptr_name, reverse_arpa


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

    return instance.rstrip(".") or None


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

    services = {}
    for reply in responses:
        ip = reply[IP].src
        for answer in dns_answers(reply):
            if getattr(answer, "type", None) != MDNS.PTR_TYPE:
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
