from scapy.all import DNS

from lantern.constants import ENCODING


def dns_answers(pkt):
    """Return a DNS reply's answers as a list, even when there is only one."""
    answers = pkt[DNS].an
    return answers if isinstance(answers, list) else [answers]


def reverse_arpa(ip_address, suffix):
    """Build the reverse-DNS lookup name for an IP (1.2.168.192.in-addr.arpa)."""
    return ".".join(reversed(ip_address.split("."))) + suffix


def ptr_name(pkt):
    """Pull the hostname out of a DNS PTR ("pointer") reply, or None."""
    for answer in dns_answers(pkt):
        rdata = getattr(answer, "rdata", None)
        if isinstance(rdata, bytes):
            return rdata.decode(ENCODING).rstrip(".")
    return None
