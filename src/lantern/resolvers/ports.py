"""Read-only TCP connect probe of common service ports.

Which ports answer is a per-device service inventory, independent of whether a
name was found. The probe is strictly read-only and LAN-scoped: it only ever
attempts ``connect()`` on the candidate ports (no payload is sent, nothing is
written) and it skips addresses outside the scanned subnet. Concurrency is
bounded and there are no retries, so the probe cannot flood the segment.
"""

import concurrent.futures
import socket

from lantern.constants import PORTS
from lantern.logger import logger
from lantern.metadata import OPEN_PORTS, record
from lantern.scope import is_in_scope, require_read_only

# Source label recorded with the open_ports fact.
SOURCE = "ports"


def _is_open(ip_address, port, timeout):
    """Whether a TCP ``connect()`` to ``port`` succeeds.

    Read-only: nothing is sent and the connection is closed immediately.
    """
    try:
        with socket.create_connection((ip_address, port), timeout=timeout):
            pass
    except OSError as error:
        logger.trace("Connect to {}:{} failed: {}", ip_address, port, error)
        return False
    return True


def open_ports(ip_address, timeout=PORTS.TIMEOUT):
    """Return the sorted open ports among :data:`PORTS.CANDIDATES`.

    Out-of-scope addresses are skipped rather than probed. Candidate ports are
    probed concurrently on a bounded pool; any per-port exception counts as
    "closed", so the whole call never raises.
    """
    require_read_only("service banner")
    if not is_in_scope(ip_address):
        logger.debug("Skipping port probe for out-of-scope IP: {}", ip_address)
        return []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(PORTS.MAX_WORKERS, len(PORTS.CANDIDATES)),
        thread_name_prefix="ports",
    ) as executor:
        futures = {
            executor.submit(_is_open, ip_address, port, timeout): port
            for port in PORTS.CANDIDATES
        }
        found = []
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    found.append(port)
            except Exception as error:
                logger.trace("Port probe for {}:{} raised: {}", ip_address, port, error)
    return sorted(found)


def record_open_ports(ip_address, timeout=PORTS.TIMEOUT):
    """Probe a device and record its open ports; never raises.

    When at least one candidate port answers, the ascending, comma-joined list
    (e.g. ``"22,80,443"``) is stored under :data:`lantern.metadata.OPEN_PORTS`.
    Recording is best-effort: a failure there leaves the scan untouched.
    """
    found = open_ports(ip_address, timeout=timeout)
    if not found:
        return found

    try:
        record(ip_address, OPEN_PORTS, ",".join(str(port) for port in found), SOURCE)
    except Exception as error:
        logger.trace("Recording open ports for {} failed: {}", ip_address, error)
    return found
