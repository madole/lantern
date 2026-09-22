"""Name and vendor resolution for LAN devices.

The implementation is split by protocol, but the public surface stays here so
callers can keep importing from ``lantern.resolvers``.
"""

from lantern.resolvers.banner import get_service_banner, parse_smb_name
from lantern.resolvers.hostname import get_hostname
from lantern.resolvers.llmnr import get_llmnr_name
from lantern.resolvers.mdns import (
    browse_mdns_services,
    get_mdns_name,
    get_mdns_service_name,
    reset_mdns_service_cache,
)
from lantern.resolvers.name import (
    NAME_SOURCES,
    SCAN_SOURCES,
    finish_prefetch_broadcast,
    prefetch_broadcast_names,
    prefetch_scan_names,
    reset_name_state,
    resolve_name,
    shutdown_name_state,
    start_prefetch_broadcast,
)
from lantern.resolvers.netbios import get_net_bios_name
from lantern.resolvers.router_dns import get_gateway_ip, get_router_dns_name
from lantern.resolvers.snmp import get_snmp_name
from lantern.resolvers.ssdp import (
    discover_ssdp,
    get_ssdp_description,
    get_ssdp_name,
    parse_ssdp_description,
    parse_ssdp_location,
    reset_ssdp_cache,
    resolve_ssdp_names,
)
from lantern.resolvers.tls import (
    certificate_names,
    clean_cert_name,
    get_tls_name,
)
from lantern.resolvers.vendor import get_vendor, is_locally_administered
from lantern.resolvers.web import get_web_title, is_generic_title

__all__ = [
    "NAME_SOURCES",
    "SCAN_SOURCES",
    "browse_mdns_services",
    "certificate_names",
    "clean_cert_name",
    "discover_ssdp",
    "finish_prefetch_broadcast",
    "get_gateway_ip",
    "get_hostname",
    "get_llmnr_name",
    "get_mdns_name",
    "get_mdns_service_name",
    "get_net_bios_name",
    "get_router_dns_name",
    "get_service_banner",
    "get_snmp_name",
    "get_ssdp_description",
    "get_ssdp_name",
    "get_tls_name",
    "get_vendor",
    "get_web_title",
    "is_generic_title",
    "is_locally_administered",
    "parse_ssdp_description",
    "parse_ssdp_location",
    "parse_smb_name",
    "prefetch_broadcast_names",
    "prefetch_scan_names",
    "reset_mdns_service_cache",
    "reset_name_state",
    "reset_ssdp_cache",
    "resolve_name",
    "resolve_ssdp_names",
    "shutdown_name_state",
    "start_prefetch_broadcast",
]
