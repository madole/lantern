from scapy.all import IP, UDP, NBNSQueryRequest, NBNSQueryResponse, sr1

from lantern.constants import ENCODING, NETBIOS
from lantern.logger import logger


def get_net_bios_name(ip_address):
    """Ask a Windows device for its NetBIOS name (the old short computer name)."""
    logger.debug("Querying NetBIOS name for IP: {}", ip_address)
    pkt = (
        IP(dst=ip_address)
        / UDP(sport=NETBIOS.PORT, dport=NETBIOS.PORT)
        / NBNSQueryRequest(QUESTION_NAME=NETBIOS.WILDCARD_NAME)
    )

    reply = sr1(pkt, timeout=NETBIOS.TIMEOUT, verbose=False)

    if reply and reply.haslayer(NBNSQueryResponse):
        try:
            return reply.ADDR_ENTRY[0].RR_NAME.strip().decode(ENCODING)
        except Exception as error:
            logger.debug("Malformed NetBIOS response from {}: {}", ip_address, error)
    return None
