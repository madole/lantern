import socket
import time
from concurrent.futures import ThreadPoolExecutor

from scapy.all import ARP, Ether, srp
from tabulate import tabulate

from lantern.constants import NAME, NETWORK, TABLE
from lantern.logger import logger
from lantern.passive import (
    finish_passive_scan,
    get_passive_macs,
    resolve_passive_names,
    start_passive_scan,
)
from lantern.resolvers import (
    finish_prefetch_broadcast,
    get_vendor,
    reset_mdns_service_cache,
    reset_name_state,
    reset_ssdp_cache,
    resolve_name,
    shutdown_name_state,
    start_prefetch_broadcast,
)
from lantern.scope import clear_scan_network, is_in_scope, set_scan_network


def _resolve_device(entry):
    """Resolve one host's name and vendor, tagged with its logging context."""
    ip, mac = entry
    device = f"{ip} ({mac})"
    with logger.contextualize(device=device):
        name = resolve_name(ip, device=device)
        vendor = get_vendor(mac)
        logger.info("Identified {!r} (vendor: {})", name, vendor)
    return {"ip": ip, "mac": mac, "name": name, "vendor": vendor}


def scan_network(ip_range: str):
    # Use scapy to perform a network scan on the given IP range
    logger.info("Starting ARP scan of {}", ip_range)
    started = time.monotonic()

    # Confine every active probe to the requested subnet.
    set_scan_network(ip_range)

    reset_mdns_service_cache()
    reset_ssdp_cache()
    reset_name_state()

    try:
        # Listen for self-announcements in parallel with the active ARP probe.
        sniffer = start_passive_scan()

        # The scan-wide broadcasts also depend only on the network, not on the
        # ARP results or the passive cache, so start them now and let them
        # overlap the listening window instead of running after it.
        broadcast = start_prefetch_broadcast()

        try:
            arp_request = ARP(pdst=ip_range)

            ether_frame = Ether(dst=NETWORK.BROADCAST_MAC)

            packet = ether_frame / arp_request

            results = srp(packet, timeout=NETWORK.ARP_TIMEOUT, verbose=False)

            hosts = results[0]
            logger.info("ARP scan found {} host(s)", len(hosts))

            finish_passive_scan(sniffer)
        finally:
            # Always drain the broadcasts, even if the probe raised, so no
            # prefetch thread outlives the scan and races the next one.
            finish_prefetch_broadcast(broadcast)

        found = {received.psrc: received.hwsrc for _sent, received in hosts}
        for ip, mac in get_passive_macs().items():
            if is_in_scope(ip):
                found.setdefault(ip, mac)

        # The passive listener's own SSDP descriptions can only be fetched once
        # it has been joined; the broadcast sources already ran above.
        resolve_passive_names()

        with ThreadPoolExecutor(max_workers=NAME.MAX_DEVICE_WORKERS) as pool:
            devices = list(pool.map(_resolve_device, found.items()))

        # Let any lookups still in flight finish before reporting, so nothing
        # continues after the table is printed.
        shutdown_name_state()
    finally:
        clear_scan_network()

    elapsed = time.monotonic() - started
    if devices:
        print(
            tabulate(
                [device.values() for device in devices],
                headers=TABLE.HEADERS,
                tablefmt=TABLE.FORMAT,
            )
        )
    else:
        logger.warning("No devices found.")
    logger.info("Scan complete: {} device(s) in {:.2f}s", len(devices), elapsed)

    return devices


def get_local_ip():
    logger.debug("Determining local IP address...")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # Doesn't actually send packets
        s.connect((NETWORK.PUBLIC_DNS_ADDR, NETWORK.PUBLIC_DNS_PORT))
        local_ip = s.getsockname()[0]
        logger.debug("Local IP address: {}", local_ip)
    except Exception as error:
        logger.warning(
            "Could not determine local IP ({}); using {}",
            error,
            NETWORK.LOCALHOST,
        )
        local_ip = NETWORK.LOCALHOST
    finally:
        s.close()

    return local_ip


if __name__ == "__main__":
    target_ip_range = f"{get_local_ip()}/{NETWORK.DEFAULT_PREFIX_LENGTH}"

    scan_network(target_ip_range)
