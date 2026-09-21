from network_lister.constants import FALLBACK
from network_lister.logger import logger
from network_lister.passive import get_passive_name
from network_lister.resolvers.hostname import get_hostname
from network_lister.resolvers.llmnr import get_llmnr_name
from network_lister.resolvers.mdns import get_mdns_name, get_mdns_service_name
from network_lister.resolvers.netbios import get_net_bios_name
from network_lister.resolvers.router_dns import get_router_dns_name
from network_lister.resolvers.ssdp import get_ssdp_name
from network_lister.resolvers.tls import get_tls_name
from network_lister.resolvers.web import get_web_title

NAME_SOURCES = (
    ("passive", get_passive_name),
    ("hostname", get_hostname),
    ("router DNS", get_router_dns_name),
    ("mDNS", get_mdns_name),
    ("SSDP", get_ssdp_name),
    ("mDNS services", get_mdns_service_name),
    ("NetBIOS", get_net_bios_name),
    ("LLMNR", get_llmnr_name),
    ("TLS certificate", get_tls_name),
    ("web title", get_web_title),
)


def resolve_name(ip_address):
    """Walk the name sources in order, logging the outcome of each attempt."""
    for source, resolver in NAME_SOURCES:
        try:
            name = resolver(ip_address)
        except Exception as error:
            logger.opt(exception=error).debug(
                "{} lookup raised for {}: {}", source, ip_address, error
            )
            continue

        if name:
            logger.debug("{} resolved {} as {!r}", source, ip_address, name)
            return name

        logger.debug("{} found no name for {}", source, ip_address)

    logger.debug("No name source matched {}; using {}", ip_address, FALLBACK.NAME)
    return FALLBACK.NAME
