from scapy.all import DNS, DNSQR, IP, UDP, AsyncSniffer, Ether, sendp

from lantern.constants import LLMNR
from lantern.logger import logger
from lantern.resolvers.dns_common import ptr_name, reverse_arpa


def _llmnr_query(qname, timeout):
    """Send a link-layer LLMNR PTR query and collect the responses.

    LLMNR queries target a link-scope multicast group, but responders unicast
    their answers back to the query's source port. Send the query ourselves and
    sniff the wire so we see the reply regardless of socket bookkeeping.
    """
    responses = []

    def handle(pkt):
        if (
            pkt.haslayer(IP)
            and pkt.haslayer(DNS)
            and pkt[DNS].qr == LLMNR.DNS_RESPONSE
            and pkt[DNS].an
        ):
            responses.append(pkt)

    def send_query():
        query = (
            Ether(dst=LLMNR.MAC)
            / IP(dst=LLMNR.ADDR, ttl=LLMNR.TTL)
            / UDP(sport=LLMNR.PORT, dport=LLMNR.PORT)
            / DNS(
                id=LLMNR.QUERY_ID,
                qr=LLMNR.DNS_QUERY,
                qd=DNSQR(qname=qname, qtype=LLMNR.PTR_RECORD),
            )
        )
        sendp(query, verbose=False)

    sniffer = AsyncSniffer(
        filter=f"udp port {LLMNR.PORT}",
        prn=handle,
        store=False,
        timeout=timeout,
        started_callback=send_query,
    )
    sniffer.start()
    sniffer.join()
    return responses


def get_llmnr_name(ip_address, timeout=LLMNR.TIMEOUT):
    """Ask Windows-style devices to reverse-resolve an IP over LLMNR."""
    logger.debug("Querying LLMNR name for IP: {}", ip_address)
    arpa_ip = reverse_arpa(ip_address, LLMNR.REVERSE_SUFFIX)

    responses = _llmnr_query(arpa_ip, timeout)

    replies = [pkt for pkt in responses if pkt[IP].src == ip_address]
    if not replies:
        logger.debug("No LLMNR response for {}", ip_address)
        return None

    for reply in replies:
        name = ptr_name(reply)
        if name:
            logger.debug("LLMNR resolved {} as {!r}", ip_address, name)
            return name
    return None
