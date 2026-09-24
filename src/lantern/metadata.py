"""Best-effort device metadata collected by probes.

The name chain decides the single name shown for a device; this module collects
the supplementary facts a probe learns along the way (model, OS/version hints,
serial numbers, exposed services). Facts are keyed by IP, written by resolver
threads while devices are being resolved, and read once after the scan has
drained, so every access is lock-guarded and the store is reset per scan.

Values learned from a device are untrusted and are sanitized here, so callers
cannot forget to. Nothing in this module participates in name resolution: a
missing or late fact never blocks a name, it only leaves the details column
sparser.
"""

import threading

from lantern.sanitize import sanitize_name

# Canonical fact keys. Probes should reuse these so the same concept learned
# from two protocols (say a model from mDNS TXT and from SSDP) lands in one
# column instead of two. Keys are stable, human-readable identifiers.
MODEL = "model"
MANUFACTURER = "manufacturer"
OS = "os"
VERSION = "version"
SERIAL = "serial"
DEVICE_TYPE = "device_type"
UUID = "uuid"
UPTIME = "uptime"
SERVER = "server"
SERVICES = "services"
# A bare HTTP server that answers without naming itself is typical of an
# embedded appliance (no mDNS/SSDP, no Server header, no usable title).
APPLIANCE = "appliance"
# Scan-level facts: which name source won and which sources answered at all
# (the latter is best-effort because the chain exits early), plus the device's
# open TCP ports.
NAME_SOURCE = "name_source"
RESPONDED = "responded"
OPEN_PORTS = "open_ports"
# DHCP-learned facts: the client's requested FQDN, vendor class (OS hint), and
# parameter-request-list fingerprint.
FQDN = "fqdn"
VENDOR_CLASS = "vendor_class"
DHCP_FINGERPRINT = "dhcp_fingerprint"

_lock = threading.Lock()
_facts = {}


def reset_metadata():
    """Drop everything the previous scan collected."""
    with _lock:
        _facts.clear()


def record(ip_address, key, value, source):
    """Remember one fact about a device; the first value for a key wins.

    ``source`` names the probe that learned the fact so its origin stays
    visible. Empty, blank, or unsanitizable values are ignored rather than
    stored, so a device that answers with nothing useful leaves no empty
    columns behind.
    """
    if not ip_address or not key:
        return

    text = sanitize_name(value)
    if not text:
        return

    with _lock:
        facts = _facts.setdefault(ip_address, {})
        facts.setdefault(str(key), {"value": text, "source": source})


def get_metadata(ip_address):
    """Return ``{key: value}`` for a device, or ``{}`` when none was collected."""
    with _lock:
        facts = _facts.get(ip_address, {})
        return {key: entry["value"] for key, entry in facts.items()}


def get_metadata_records(ip_address):
    """Return ``{key: {"value": ..., "source": ...}}`` for auditing a device."""
    with _lock:
        facts = _facts.get(ip_address, {})
        return {key: dict(entry) for key, entry in facts.items()}
