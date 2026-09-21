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


class SNMP:
    PORT = 161
    TIMEOUT = 2
    COMMUNITY = "public"
    # Scalar OIDs for the two name-ish values: sysName is the configured name,
    # sysDescr is the free-form description (model/OS/firmware).
    SYS_NAME = "1.3.6.1.2.1.1.5.0"
    SYS_DESCR = "1.3.6.1.2.1.1.1.0"
    NAME_OIDS = (SYS_NAME, SYS_DESCR)
    MAX_NAME_LENGTH = 60


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


class NAME:
    # Total wall-clock budget for one device's device-scoped name lookups.
    DEADLINE = 10.0
    # Devices resolved in parallel; each runs its sources concurrently.
    MAX_DEVICE_WORKERS = 4
    # Shared pool for per-device sources; large enough that a device's whole
    # chain runs without queuing behind another device's lookups.
    MAX_WORKERS = 64
    # Slow, low-yield sources only tried when every faster source came up empty.
    DEFERRED_SOURCES = frozenset({"TLS certificate", "web title", "service banner"})


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
    # A description URL is attacker-controlled: only fetch plain HTTP(S) so a
    # responder cannot point us at file:// or another local scheme.
    ALLOWED_SCHEMES = ("http", "https")
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


class BANNER:
    # Tight per-port budget: banners are a last resort, so a dead port must not
    # stall the chain. Every port is probed concurrently, so this is also the
    # whole banner lookup's wall-clock bound.
    TIMEOUT = 0.75
    MAX_BYTES = 512
    # Protocols that announce a banner immediately on connect.
    TEXT_PORTS = (22, 21, 25, 23, 110, 143)
    SMB_PORT = 445
    # SMB2 dialects offered in the negotiate request: 2.0.2 through 3.0.2.
    # 3.1.1 is omitted because it requires negotiate contexts we do not send.
    SMB_DIALECTS = (0x0202, 0x0210, 0x0300, 0x0302)
    NTLM_SIGNATURE = b"NTLMSSP\x00"
    NTLM_CHALLENGE = 2
    # NTLM target-info AV pair ids that carry the server's computer name.
    AV_NB_COMPUTER_NAME = 1
    AV_DNS_COMPUTER_NAME = 3


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
