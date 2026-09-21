import ipaddress
import socket
import time

from scapy.all import ARP, Ether, srp
from tabulate import tabulate

from network_lister.constants import NETWORK, TABLE
from network_lister.logger import logger
from network_lister.passive import (
    finish_passive_scan,
    get_passive_macs,
    start_passive_scan,
)
from network_lister.resolvers import (
    get_vendor,
    reset_mdns_service_cache,
    resolve_name,
)


def scan_network(ip_range: str):
    # Use scapy to perform a network scan on the given IP range
    logger.info("Starting ARP scan of {}", ip_range)
    started = time.monotonic()

    reset_mdns_service_cache()

    # Listen for self-announcements in parallel with the active ARP probe.
    sniffer = start_passive_scan()

    arp_request = ARP(pdst=ip_range)

    ether_frame = Ether(dst=NETWORK.BROADCAST_MAC)

    packet = ether_frame / arp_request

    results = srp(packet, timeout=NETWORK.ARP_TIMEOUT, verbose=False)

    hosts = results[0]
    logger.info("ARP scan found {} host(s)", len(hosts))

    finish_passive_scan(sniffer)

    found = {received.psrc: received.hwsrc for _sent, received in hosts}
    network = ipaddress.ip_network(ip_range, strict=False)
    for ip, mac in get_passive_macs().items():
        if ipaddress.ip_address(ip) in network:
            found.setdefault(ip, mac)

    devices = []
    for index, (ip, mac) in enumerate(found.items(), start=1):
        with logger.contextualize(device=f"{ip} ({mac})"):
            logger.debug("Resolving host {}/{}", index, len(found))
            name = resolve_name(ip)
            vendor = get_vendor(mac)
            logger.info("Identified {!r} (vendor: {})", name, vendor)
        devices.append({"ip": ip, "mac": mac, "name": name, "vendor": vendor})

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
