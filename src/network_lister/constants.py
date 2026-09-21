class LOGGING:
    LEVEL_DEBUG = "DEBUG"
    LEVEL_INFO = "INFO"
    COLOR_DEBUG = "<cyan>"
    COLOR_INFO = "<green>"
    DEFAULT_LEVEL = LEVEL_DEBUG
    ENV_LEVEL = "LOG_LEVEL"
    FORMAT = (
        "<green>{time:HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{extra[device]}</cyan> | "
        "<level>{message}</level>"
    )
    DEFAULT_EXTRA = {"device": "-"}


class NETWORK:
    BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
    ARP_TIMEOUT = 2
    PUBLIC_DNS_ADDR = "8.8.8.8"
    PUBLIC_DNS_PORT = 53
    LOCALHOST = "127.0.0.1"
    DEFAULT_PREFIX_LENGTH = 24


class NETBIOS:
    PORT = 137
    TIMEOUT = 2
    WILDCARD_NAME = b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


class MDNS:
    ADDR = "224.0.0.251"
    MAC = "01:00:5e:00:00:fb"
    PORT = 5353
    TTL = 255
    QUERY_ID = 0
    TIMEOUT = 2
    BROWSE_TIMEOUT = 3
    # DNS wire values used by the mDNS query/response handling.
    DNS_QUERY = 0
    DNS_RESPONSE = 1
    PTR_RECORD = "PTR"
    PTR_TYPE = 12
    REVERSE_SUFFIX = ".in-addr.arpa"
    # Service browsing: the meta-query lists service types, the rest are
    # common instance-bearing service types to map names back to IPs.
    SERVICE_BROWSE = "_services._dns-sd._udp.local"
    SERVICE_TYPES = (
        "_http._tcp.local",
        "_https._tcp.local",
        "_airplay._tcp.local",
        "_raop._tcp.local",
        "_googlecast._tcp.local",
        "_spotify-connect._tcp.local",
        "_printer._tcp.local",
        "_ipp._tcp.local",
        "_ipps._tcp.local",
        "_workstation._tcp.local",
        "_smb._tcp.local",
        "_afpovertcp._tcp.local",
        "_ssh._tcp.local",
        "_companion-link._tcp.local",
        "_device-info._tcp.local",
    )


class LLMNR:
    ADDR = "224.0.0.252"
    MAC = "01:00:5e:00:00:fc"
    PORT = 5355
    TTL = 1
    TIMEOUT = 2
    QUERY_ID = 0
    DNS_QUERY = 0
    DNS_RESPONSE = 1
    PTR_RECORD = "PTR"
    REVERSE_SUFFIX = ".in-addr.arpa"


class ROUTER_DNS:
    PORT = 53
    TIMEOUT = 2
    PTR_RECORD = "PTR"
    REVERSE_SUFFIX = ".in-addr.arpa"


class PASSIVE:
    TIMEOUT = 30
    FILTER = (
        "arp or udp port 5353 or udp port 1900 "
        "or udp port 67 or udp port 68 or udp port 5355"
    )
    LLMNR_PORT = 5355
    DHCP_HOSTNAME_OPTIONS = ("hostname", 12)


class SSDP:
    ADDR = "239.255.255.250"
    MAC = "01:00:5e:7f:ff:fa"
    PORT = 1900
    TTL = 2
    TIMEOUT = 3
    HTTP_TIMEOUT = 1
    MAX_BYTES = 65536
    SEARCH_METHOD = "M-SEARCH"
    SEARCH_TARGET = "*"
    SEARCH_ST = "ssdp:all"
    MAN = "ssdp:discover"
    MX = 1
    LOCATION_HEADER = "location:"
    # Preferred order for picking a human-meaningful name from a description.
    NAME_FIELDS = ("friendlyname", "modelname", "manufacturer")


class WEB:
    TIMEOUT = 1
    # Scheme/port pairs tried in order; defaults first, then common alternates.
    CANDIDATES = (
        ("http", 80),
        ("https", 443),
        ("http", 8080),
        ("https", 8443),
        ("http", 8000),
        ("http", 8081),
        ("http", 8888),
    )
    USER_AGENT_HEADER = "User-Agent"
    USER_AGENT = "Mozilla/5.0"
    MAX_BYTES = 65536
    HTML_PARSER = "html.parser"
    TITLE_TAG = "title"
    GENERIC_TITLE_PATTERNS = (
        "404",
        "302",
        "403",
        "401",
        "400",
        "500",
        "501",
        "502",
        "503",
        "bad request",
        "unauthorized",
        "forbidden",
        "not found",
        "page not found",
        "site not found",
        "error",
        "default page",
        "index of /",
        "it works!",
        "welcome to nginx",
        "apache2",
        "iis windows server",
    )


class TLS:
    TIMEOUT = WEB.TIMEOUT
    PORTS = (443, 8443)
    SAN_KINDS = ("DNS",)
    COMMON_NAME = "commonName"


class TABLE:
    HEADERS = ("IP", "MAC", "Name", "Vendor")
    FORMAT = "grid"


class FALLBACK:
    NAME = "Unknown"
    VENDOR = "Unknown Vendor"


ENCODING = "utf-8"
