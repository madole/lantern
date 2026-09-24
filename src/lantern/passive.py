"""Passive LAN listener.

Sniff a bounded window of link-local chatter (ARP, mDNS, SSDP, DHCP, LLMNR)
and harvest names and MACs that devices announce about themselves. Some
devices ignore active probes but still broadcast, so this runs alongside the
ARP scan and feeds the normal name-resolution chain.
"""

import concurrent.futures
import sys
import threading
import time

from scapy.all import ARP, BOOTP, DHCP, DNS, IP, UDP, AsyncSniffer, Raw
from yaspin import yaspin

from lantern.constants import ENCODING, MDNS, PASSIVE, SSDP
from lantern.logger import attach_spinner, detach_spinner, logger
from lantern.sanitize import sanitize_name
from lantern.scope import is_in_scope

_names = {}
_macs = {}
_locations = {}
_sniffer = None
_spinner = None
# Wall-clock bookkeeping for the adaptive listening window. ``_last_observation``
# is written by the sniffer thread and read by the joining thread, so it is
# guarded; ``_listen_started`` is only touched by the caller thread.
_observation_lock = threading.Lock()
_last_observation = 0.0
_listen_started = 0.0


def _stop_spinner():
    global _spinner
    if _spinner is not None:
        # Clear the global first so a re-entrant stop cannot double-release,
        # then stop while still attached: any log racing the teardown is drawn
        # above the spinner rather than interleaved with its final frame.
        spinner, _spinner = _spinner, None
        try:
            spinner.stop()
        finally:
            detach_spinner(spinner)


def reset_passive_cache():
    """Drop everything the previous scan learned before a new one starts."""
    global _sniffer, _last_observation, _listen_started
    _stop_spinner()
    _names.clear()
    _macs.clear()
    _locations.clear()
    _sniffer = None
    with _observation_lock:
        _last_observation = 0.0
    _listen_started = 0.0


def _note_observation():
    """Record that the wire is active right now; keeps the window open."""
    global _last_observation
    with _observation_lock:
        _last_observation = time.monotonic()


def _quiet_reached():
    """Whether the listener may stop: minimum window served and wire silent."""
    with _observation_lock:
        last = _last_observation
    now = time.monotonic()
    if now - _listen_started < PASSIVE.MIN_WINDOW:
        return False
    return now - last >= PASSIVE.QUIET_PERIOD


def _decode(value):
    value = sanitize_name(value)
    if value is None:
        return None
    return value.rstrip(".") or None


def _dns_answers(dns):
    answers = dns.an
    if answers is None:
        return []
    return answers if isinstance(answers, list) else [answers]


def parse_arp(pkt):
    """Harvest the sender of an ARP packet as (ip, mac)."""
    if not pkt.haslayer(ARP):
        return None

    arp = pkt[ARP]
    if not arp.psrc or arp.psrc == "0.0.0.0":
        return None
    if not arp.hwsrc or arp.hwsrc == "00:00:00:00:00:00":
        return None

    return arp.psrc, arp.hwsrc


def parse_dhcp(pkt):
    """Pull the hostname option (12) and leased IP out of DHCP traffic."""
    if not (pkt.haslayer(BOOTP) and pkt.haslayer(DHCP)):
        return None

    bootp = pkt[BOOTP]
    ip = bootp.yiaddr if bootp.yiaddr and bootp.yiaddr != "0.0.0.0" else bootp.ciaddr
    if not ip or ip == "0.0.0.0":
        return None

    name = None
    for option in pkt[DHCP].options:
        if not isinstance(option, tuple) or len(option) < 2:
            continue
        if option[0] in PASSIVE.DHCP_HOSTNAME_OPTIONS:
            name = _decode(option[1]) or name
    if not name:
        return None

    return ip, [name]


def parse_llmnr(pkt):
    """Map the responder of an LLMNR answer to the queried name."""
    if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
        return None

    udp = pkt[UDP]
    if PASSIVE.LLMNR_PORT not in (udp.sport, udp.dport):
        return None

    dns = pkt[DNS]
    if dns.qr != MDNS.DNS_RESPONSE or not dns.an:
        return None

    names = []
    for answer in _dns_answers(dns):
        name = _decode(getattr(answer, "rrname", None))
        if name and name not in names:
            names.append(name)

    return (pkt[IP].src, names) if names else None


def _mdns_instance(answer):
    """Turn a service PTR answer into the friendly instance label."""
    if getattr(answer, "type", None) != MDNS.PTR_TYPE:
        return None

    instance = _decode(getattr(answer, "rdata", None))
    if not instance or instance.startswith("_"):
        return None

    service = _decode(getattr(answer, "rrname", None))
    if service and service == MDNS.SERVICE_BROWSE:
        return None
    if service:
        suffix = f".{service}"
        if instance.lower().endswith(suffix.lower()):
            instance = instance[: -len(suffix)].rstrip(".")

    return instance or None


def parse_mdns(pkt):
    """Harvest mDNS instance labels and `.local` hostnames as (ip, names)."""
    if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
        return None

    if MDNS.PORT not in (pkt[UDP].sport, pkt[UDP].dport):
        return None

    dns = pkt[DNS]
    if dns.qr != MDNS.DNS_RESPONSE or not dns.an:
        return None

    instances = []
    hostnames = []
    for answer in _dns_answers(dns):
        instance = _mdns_instance(answer)
        if instance:
            instances.append(instance)
            continue

        rrname = _decode(getattr(answer, "rrname", None))
        if rrname and rrname.lower().endswith(".local"):
            host = rrname[: -len(".local")]
            if host and not host.startswith("_"):
                hostnames.append(host)

    names = instances + hostnames
    return (pkt[IP].src, names) if names else None


def parse_ssdp(pkt):
    """Record the LOCATION URL announced by an SSDP device."""
    if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(Raw)):
        return None

    if pkt[UDP].sport != SSDP.PORT:
        return None

    text = pkt[Raw].load.decode(ENCODING, errors="ignore")
    for line in text.splitlines():
        if line.lower().startswith(SSDP.LOCATION_HEADER):
            location = line.split(":", 1)[1].strip()
            if location:
                return pkt[IP].src, location

    return None


def _remember(ip_address, names):
    if ip_address and names and ip_address not in _names:
        _names[ip_address] = names[0]
        _note_observation()


def _handle(pkt):
    try:
        arp = parse_arp(pkt)
        if arp:
            ip_address, mac = arp
            if ip_address not in _macs:
                _macs[ip_address] = mac
                _note_observation()
            return

        for parser in (parse_dhcp, parse_mdns, parse_llmnr):
            result = parser(pkt)
            if result:
                _remember(*result)
                return

        ssdp = parse_ssdp(pkt)
        if ssdp:
            ip_address, location = ssdp
            if ip_address not in _locations:
                _locations[ip_address] = location
                _note_observation()
    except Exception as error:
        logger.trace("Passive listener ignored a packet: {}", error)


def _fetch_ssdp_description(location):
    # Imported lazily so this module stays importable from resolvers.
    from lantern.resolvers import get_ssdp_description

    return get_ssdp_description(location)


def get_passive_name(ip_address):
    """Name learned passively for an IP, fetching SSDP descriptions on demand."""
    if ip_address in _names:
        return _names[ip_address]

    location = _locations.get(ip_address)
    if location:
        name = _fetch_ssdp_description(location)
        if name:
            _names[ip_address] = name
            return name

    return None


def resolve_passive_names():
    """Fetch every passively-observed SSDP description once, up front.

    The fetches are independent HTTP round-trips, so they run concurrently;
    parsed names are merged back on this thread to keep the cache single-writer.
    """
    targets = [
        (ip_address, location)
        for ip_address, location in list(_locations.items())
        if ip_address not in _names and is_in_scope(ip_address)
    ]
    if not targets:
        return dict(_names)

    workers = min(PASSIVE.MAX_FETCH_WORKERS, len(targets))
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=workers, thread_name_prefix="passive-name"
    ) as pool:
        fetched = pool.map(
            lambda pair: (pair[0], _fetch_ssdp_description(pair[1])), targets
        )
        for ip_address, name in fetched:
            if name:
                _names[ip_address] = name

    return dict(_names)


def get_passive_macs():
    return dict(_macs)


def start_passive_scan(timeout=PASSIVE.TIMEOUT):
    """Start sniffing in the background; returns the running sniffer."""
    global _sniffer, _spinner, _last_observation, _listen_started
    reset_passive_cache()
    _listen_started = time.monotonic()
    with _observation_lock:
        _last_observation = _listen_started
    _sniffer = AsyncSniffer(
        filter=PASSIVE.FILTER,
        prn=_handle,
        store=False,
        timeout=timeout,
    )
    logger.info("Listening passively for up to {}s", timeout)
    _spinner = yaspin(
        text=f"Listening passively for up to {timeout}s",
        color="cyan",
        stream=sys.stderr,
    )
    _spinner.start()
    # Logs from every thread are drawn above the spinner instead of through it.
    attach_spinner(_spinner)
    _sniffer.start()
    return _sniffer


def _listener_alive(sniffer):
    """Whether the sniffer's capture thread is still running.

    ``AsyncSniffer`` exposes its thread; tests substitute a lighter fake that
    only carries ``running``.
    """
    thread = getattr(sniffer, "thread", None)
    if thread is not None:
        return thread.is_alive()
    return getattr(sniffer, "running", False)


def _drain_until_quiet(sniffer):
    """Block until the sniffer stops on its own or the wire has gone quiet.

    The ARP scan is a burst of traffic the listener also sees, so on a quiet
    LAN the window closes shortly after the scan finishes instead of always
    waiting out ``PASSIVE.TIMEOUT``. A chatty network keeps resetting the
    quiet timer and runs to the ceiling.
    """
    while _listener_alive(sniffer):
        sniffer.join(timeout=PASSIVE.POLL_INTERVAL)
        if not _listener_alive(sniffer):
            break
        if _quiet_reached():
            sniffer.stop()
            logger.debug("Passive listener stopping early: wire has gone quiet")
            break


def finish_passive_scan(sniffer=None):
    """Wait out the sniffing window and report what was learned."""
    global _sniffer
    sniffer = sniffer or _sniffer
    if sniffer is None:
        _stop_spinner()
        return

    try:
        _drain_until_quiet(sniffer)
    except Exception as error:
        logger.debug("Passive listener stopped with an error: {}", error)
    finally:
        _sniffer = None
        _stop_spinner()

    logger.info(
        "Passive listener found {} host(s) and {} name(s)",
        len(_macs),
        len(_names),
    )
