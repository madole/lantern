from scapy.all import DNS, DNSQR, IP, UDP, conf, sr1

from network_lister.constants import ROUTER_DNS
from network_lister.logger import logger
from network_lister.resolvers.dns_common import ptr_name, reverse_arpa


def get_gateway_ip():
    """Return the LAN default gateway, or None when it cannot be found."""
    try:
        _iface, _source, gateway = conf.route.route("0.0.0.0")
    except Exception as error:
        logger.debug("Could not determine the default gateway: {}", error)
        return None

    if not gateway or gateway == "0.0.0.0":
        return None
    return gateway


def get_router_dns_name(ip_address, timeout=ROUTER_DNS.TIMEOUT):
    """Ask the default gateway's DNS server to reverse-resolve an IP.

    Home routers usually keep the DHCP client-name list and answer PTR queries
    for hosts that refuse direct reverse DNS.
    """
    logger.debug("Querying router DNS for IP: {}", ip_address)

    gateway = get_gateway_ip()
    if not gateway:
        logger.debug("No default gateway available for router DNS lookup")
        return None

    arpa_ip = reverse_arpa(ip_address, ROUTER_DNS.REVERSE_SUFFIX)
    pkt = (
        IP(dst=gateway)
        / UDP(sport=ROUTER_DNS.PORT, dport=ROUTER_DNS.PORT)
        / DNS(rd=1, qd=DNSQR(qname=arpa_ip, qtype=ROUTER_DNS.PTR_RECORD))
    )

    reply = sr1(pkt, timeout=timeout, verbose=False)
    if reply is None or not reply.haslayer(DNS):
        logger.debug("No router DNS response for {}", ip_address)
        return None

    if reply[DNS].rcode != 0:
        logger.debug(
            "Router DNS returned rcode {} for {}", reply[DNS].rcode, ip_address
        )
        return None

    name = ptr_name(reply)
    if name:
        logger.debug("Router DNS resolved {} as {!r}", ip_address, name)
    return name
