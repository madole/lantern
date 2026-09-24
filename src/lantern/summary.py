"""Pure scan-level insights over already-collected data.

This module summarizes what a scan learned (vendors, device classes,
anomalies, security signals) from the per-device metadata dict ``metadata.py``
collects. It performs no I/O of its own: everything is read from the device
dicts passed in (``ip``, ``mac``, ``name``, ``vendor``, ``metadata``) and the
scan-level ``observations`` of ``(ip, mac, source)`` pairs, so the caller
remains responsible for logging or printing the returned lines.
"""

from collections import Counter

from lantern.constants import FALLBACK, PORTS, SNMP

VM_VENDOR_MARKERS = ("vmware", "qemu", "virtualbox", "xen", "parallels")
WINDOWS_NAME_SOURCES = frozenset({"NetBIOS", "LLMNR"})
APPLE_NAME_SOURCES = frozenset({"mDNS", "mDNS services"})
MDNS_PRINTER_MARKERS = ("printer", "ipp")
IOT_MAKERS = ("espressif", "tuya", "shelly", "sonos", "amazon", "google", "raspberry")
# Advertised mDNS service types that identify a device family. These are more
# specific than a name source, so they are checked before the name-source and
# vendor fallbacks (a HomeKit light answers `_hap`, not "Apple").
APPLE_SERVICE_MARKERS = (
    "_airplay",
    "_raop",
    "_companion-link",
    "_device-info",
    "_afpovertcp",
    "_rdlink",
    "_airport",
)
MEDIA_SERVICE_MARKERS = (
    "_googlecast",
    "_spotify-connect",
    "_sonos",
    "_mediarenderer",
    "_dlna",
)
IOT_SERVICE_MARKERS = (
    "_hap",
    "_miio",
    "_yeelight",
    "_matter",
    "_tuya",
    "_shelly",
    "_esphomelib",
    "_dkapi",
)


def _has_service_marker(services, markers):
    """True when the joined service-type string names any of ``markers``."""
    return any(marker in services for marker in markers)


def _metadata(device):
    """Return the device's metadata dict, tolerating missing/malformed input."""
    metadata = device.get("metadata") if isinstance(device, dict) else None
    return metadata if isinstance(metadata, dict) else {}


def _mfield(device, key):
    """Return a metadata field as text, or "" when absent/malformed."""
    value = _metadata(device).get(key)
    return value if isinstance(value, str) else ""


def _open_ports(device):
    """Return the open-port metadata as a set of int ports, ignoring junk."""
    fields = _mfield(device, "open_ports").split(",")
    return {int(text.strip()) for text in fields if text.strip().isdigit()}


def _name_source(device):
    return _mfield(device, "name_source")


def _services(device):
    return _mfield(device, "services")


def _vendor_text(device):
    vendor = device.get("vendor") if isinstance(device, dict) else None
    vendor_class = device.get("vendor_class") if isinstance(device, dict) else None
    if not isinstance(vendor, str):
        vendor = ""
    if not isinstance(vendor_class, str):
        vendor_class = _mfield(device, "vendor_class")
    return vendor, vendor_class


def classify(device):
    """Return one short class label for a device, first rule that matches."""
    if not isinstance(device, dict):
        return "unknown"

    vendor_text, vendor_class_text = _vendor_text(device)
    for text in (vendor_text, vendor_class_text):
        lowered = text.lower()
        if any(marker in lowered for marker in VM_VENDOR_MARKERS):
            return "virtual machine"

    ports = _open_ports(device)
    services = _services(device).lower()
    if any(port in ports for port in PORTS.PRINTER) or any(
        marker in services for marker in MDNS_PRINTER_MARKERS
    ):
        return "printer"

    name_source = _name_source(device)
    if 3389 in ports or (445 in ports and name_source in WINDOWS_NAME_SOURCES):
        return "windows host"

    if 22 in ports:
        return "unix host"

    # Service-type fingerprints are the most specific signal available, so they
    # are checked before the coarser name-source and vendor fallbacks.
    if _has_service_marker(services, IOT_SERVICE_MARKERS):
        return "iot"

    if _has_service_marker(services, MEDIA_SERVICE_MARKERS):
        return "media/iot"

    if _has_service_marker(services, APPLE_SERVICE_MARKERS) or (
        name_source in APPLE_NAME_SOURCES
    ):
        return "apple/consumer"

    if _mfield(device, "device_type") or name_source == "SSDP":
        return "media/iot"

    if any(marker in vendor_text.lower() for marker in IOT_MAKERS) or any(
        marker in vendor_class_text.lower() for marker in IOT_MAKERS
    ):
        return "iot"

    if _mfield(device, "appliance"):
        return "appliance"

    return "unknown"


def _count(values):
    counts = Counter(value for value in values if isinstance(value, str) and value)
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def _risky_ports(device):
    ports = _open_ports(device)
    return sorted((port, label) for port, label in PORTS.RISKY.items() if port in ports)


def _security_findings(devices, snmp_community):
    findings = []
    for device in devices:
        ip = device.get("ip")
        if not isinstance(ip, str) or not ip:
            continue
        for port, label in _risky_ports(device):
            findings.append(f"{ip} exposes {label}({port})")
        metadata_text = _metadata(device)
        if snmp_community == "public" and (
            "sys_descr" in metadata_text or "sys_object_id" in metadata_text
        ):
            findings.append(f"{ip} answers SNMP with the default community 'public'")
    return sorted(findings)


def _anomalies(observations):
    """Return anomaly strings for conflicting ip/mac pairs, sorted."""
    by_ip = {}
    by_mac = {}
    for observation in observations:
        if not isinstance(observation, (tuple, list)) or len(observation) != 3:
            continue
        ip, mac, _source = observation
        ip = ip if isinstance(ip, str) else str(ip)
        mac = mac if isinstance(mac, str) else str(mac)
        if ip and mac:
            by_ip.setdefault(ip, set()).add(mac)
            by_mac.setdefault(mac, set()).add(ip)

    lines = []
    for ip, macs in sorted(by_ip.items()):
        if len(macs) > 1:
            ordered = ", ".join(sorted(macs))
            lines.append(f"IP {ip} seen with multiple MACs: {ordered}")
    for mac, ips in sorted(by_mac.items()):
        if len(ips) > 1:
            ordered = ", ".join(sorted(ips))
            lines.append(f"MAC {mac} seen on multiple IPs: {ordered}")
    return sorted(lines)


def summarize(devices, observations=()):
    """Summarize iterable ``devices`` (each a dict with ``metadata``) into a dict."""
    devices = [device for device in devices if isinstance(device, dict)]
    result = {
        "total": len(devices),
        "named": sum(
            1
            for device in devices
            if isinstance(device.get("name"), str)
            and device.get("name") != FALLBACK.NAME
        ),
        "unknown": sum(
            1
            for device in devices
            if isinstance(device.get("name"), str)
            and device.get("name") == FALLBACK.NAME
        ),
        "randomized": sum(
            1 for device in devices if _metadata(device).get("randomized_mac") == "true"
        ),
        "vendors": _count(
            device.get("vendor")
            for device in devices
            if isinstance(device.get("vendor"), str) and device.get("vendor")
        ),
        "device_classes": _count(classify(device) for device in devices),
        "anomalies": _anomalies(observations),
        "security": _security_findings(devices, SNMP.COMMUNITY),
    }
    result["lines"] = format_summary(result)
    return result


def format_summary(summary):
    """Render a ``summarize`` result as ready-to-log summary lines."""
    if not isinstance(summary, dict):
        summary = {}
    devices = summary.get("total")
    if not isinstance(devices, int) or devices < 0:
        devices = 0
    named = summary.get("named")
    if not isinstance(named, int) or named < 0:
        named = 0
    unknown = summary.get("unknown")
    if not isinstance(unknown, int) or unknown < 0:
        unknown = 0
    randomized = summary.get("randomized")
    if not isinstance(randomized, int) or randomized < 0:
        randomized = 0

    def _pair_text(rows):
        return ", ".join(f"{name} {count}" for name, count in rows)

    vendors = summary.get("vendors")
    if not isinstance(vendors, list):
        vendors = []
    vendor_rows = [
        row for row in vendors if isinstance(row, (tuple, list)) and len(row) == 2
    ]
    classes = summary.get("device_classes")
    if not isinstance(classes, list):
        classes = []
    class_rows = [
        row for row in classes if isinstance(row, (tuple, list)) and len(row) == 2
    ]
    anomalies = summary.get("anomalies")
    if not isinstance(anomalies, list) or not all(
        isinstance(line, str) for line in anomalies
    ):
        anomalies = []
    security = summary.get("security")
    if not isinstance(security, list) or not all(
        isinstance(line, str) for line in security
    ):
        security = []

    lines = [
        f"Scan summary: {devices} device(s), {named} named, "
        f"{unknown} unknown, {randomized} randomized MAC(s)"
    ]
    lines.append(
        f"Vendors: {_pair_text(vendor_rows)}" if vendor_rows else "Vendors: none"
    )
    lines.append(
        f"Device classes: {_pair_text(class_rows)}"
        if class_rows
        else "Device classes: none"
    )
    if anomalies:
        lines.extend(f"Anomaly: {row}" for row in anomalies)
    else:
        lines.append("Anomalies: none")
    if security:
        lines.extend(f"Security: {row}" for row in security)
    else:
        lines.append("Security: none")
    return lines
