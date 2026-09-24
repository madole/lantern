import argparse
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor

from scapy.all import ARP, Ether, srp
from tabulate import tabulate

from lantern.constants import METADATA, NAME, NETWORK, TABLE
from lantern.logger import logger
from lantern.metadata import get_metadata, record, reset_metadata
from lantern.passive import (
    finish_passive_scan,
    get_passive_macs,
    resolve_passive_names,
    start_passive_scan,
)
from lantern.resolvers import (
    finish_prefetch_broadcast,
    get_vendor,
    is_locally_administered,
    reset_mdns_service_cache,
    reset_name_state,
    reset_ssdp_cache,
    resolve_name,
    shutdown_name_state,
    start_prefetch_broadcast,
)
from lantern.resolvers.ports import record_open_ports
from lantern.scope import clear_scan_network, is_in_scope, set_scan_network
from lantern.summary import summarize


def _resolve_device(entry):
    """Resolve one host's name and vendor, tagged with its logging context."""
    ip, mac = entry
    device = f"{ip} ({mac})"
    with logger.contextualize(device=device):
        name = resolve_name(ip, device=device)
        vendor = get_vendor(mac)
        # A locally administered MAC means a privacy-randomized endpoint or a
        # VM. `get_vendor` cannot say where it is, so record it here.
        if is_locally_administered(mac):
            record(ip, "randomized_mac", "true", source="vendor")
        # A per-device service inventory, independent of the name chain.
        record_open_ports(ip)
        logger.info("Identified {!r} (vendor: {})", name, vendor)
    return {"ip": ip, "mac": mac, "name": name, "vendor": vendor}


def _format_metadata(metadata):
    """Render per-device facts as one compact, ordered details string."""
    if not metadata:
        return ""

    order = METADATA.DISPLAY_ORDER
    keys = sorted(
        metadata,
        key=lambda key: (order.index(key) if key in order else len(order), key),
    )
    text = METADATA.SEPARATOR.join(f"{key}={metadata[key]}" for key in keys)
    if len(text) > METADATA.MAX_DISPLAY:
        text = text[: METADATA.MAX_DISPLAY - 3].rstrip() + "..."
    return text


def run_scan(ip_range: str):
    """Run one scan and return its structured, JSON-serializable result.

    This is the shared core behind the CLI and the MCP server. It performs the
    scan and returns ``{"range", "elapsed_seconds", "device_count", "devices",
    "summary"}`` without printing anything, so each caller owns presentation.
    """
    logger.info("Starting ARP scan of {}", ip_range)
    started = time.monotonic()

    # Confine every active probe to the requested subnet.
    set_scan_network(ip_range)

    reset_mdns_service_cache()
    reset_ssdp_cache()
    reset_name_state()
    reset_metadata()

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
        # Keep every ip/mac pairing, not just the first per ip: duplicate IPs
        # with different MACs (and vice versa) are the anomaly summary's input.
        observations = [
            (received.psrc, received.hwsrc, "arp") for _sent, received in hosts
        ]
        for ip, mac in get_passive_macs().items():
            if is_in_scope(ip):
                found.setdefault(ip, mac)
                observations.append((ip, mac, "passive"))

        # The passive listener's own SSDP descriptions can only be fetched once
        # it has been joined; the broadcast sources already ran above.
        resolve_passive_names()

        with ThreadPoolExecutor(max_workers=NAME.MAX_DEVICE_WORKERS) as pool:
            devices = list(pool.map(_resolve_device, found.items()))

        # Let any lookups still in flight finish before reporting, so nothing
        # continues after the table is printed. Metadata is read only after
        # that drain so facts a slow source records still make the table.
        shutdown_name_state()

        for device in devices:
            facts = get_metadata(device["ip"])
            device["metadata"] = facts
            device["details"] = _format_metadata(facts)
    finally:
        clear_scan_network()

    elapsed = time.monotonic() - started
    if not devices:
        logger.warning("No devices found.")
    logger.info("Scan complete: {} device(s) in {:.2f}s", len(devices), elapsed)

    return {
        "range": ip_range,
        "elapsed_seconds": round(elapsed, 3),
        "device_count": len(devices),
        "devices": devices,
        "summary": summarize(devices, observations),
    }


def format_table(devices):
    """Render the device list as the stdout grid table, or "" when empty."""
    if not devices:
        return ""
    return tabulate(
        [
            (
                device["ip"],
                device["mac"],
                device["name"],
                device["vendor"],
                device["details"],
            )
            for device in devices
        ],
        headers=TABLE.HEADERS,
        tablefmt=TABLE.FORMAT,
    )


def log_summary(summary):
    """Log a ``summarize`` result's ready-to-log lines to stderr."""
    for line in summary.get("lines", ()):
        logger.info(line)


def scan_network(ip_range: str):
    """Scan, print the table and log the summary; return the device list.

    The command-line entry point: ``run_scan`` does the work, and this wrapper
    adds the human-facing table on stdout and summary lines on stderr.
    """
    result = run_scan(ip_range)
    table = format_table(result["devices"])
    if table:
        print(table)
    log_summary(result["summary"])
    return result["devices"]


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


def default_scan_range():
    """Return the /24 around this machine's local IP."""
    return f"{get_local_ip()}/{NETWORK.DEFAULT_PREFIX_LENGTH}"


def main(argv=None):
    """Command-line entry point: scan and print the table (or JSON)."""
    parser = argparse.ArgumentParser(
        prog="lantern",
        description="Identify and name every device on the local network.",
    )
    parser.add_argument(
        "--range",
        dest="ip_range",
        default=None,
        help="CIDR to scan (default: the /24 around the local IP)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the full scan result as JSON instead of a table",
    )
    args = parser.parse_args(argv)

    ip_range = args.ip_range or default_scan_range()
    if args.json:
        print(json.dumps(run_scan(ip_range)))
    else:
        scan_network(ip_range)


if __name__ == "__main__":
    main()
