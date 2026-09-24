"""Tests for the pure summary module (no network I/O)."""

from lantern import summary
from lantern.constants import FALLBACK, SNMP


def device(
    ip="192.168.1.5", mac="aa:bb:cc:dd:ee:01", name="device", vendor=None, **meta
):
    metadata = {"name_source": "ARP", "responded": "ARP"}
    extra = meta.pop("metadata", {})
    if isinstance(extra, dict):
        metadata.update(extra)
    metadata.update(meta)
    base = {"ip": ip, "mac": mac, "name": name, "metadata": metadata}
    if vendor is not None:
        base["vendor"] = vendor
    return base


# --- classify -----------------------------------------------------------


def test_classify_virtual_machine_by_vendor_case_insensitive():
    assert summary.classify(device(vendor="VMware, Inc.")) == "virtual machine"
    assert summary.classify(device(vendor="QEMU")) == "virtual machine"
    assert summary.classify(device(vendor="parallels virtual")) == "virtual machine"


def test_classify_virtual_machine_by_vendor_class_metadata():
    assert (
        summary.classify(device(metadata={"vendor_class": "VirtualBox"}))
        == "virtual machine"
    )


def test_classify_printer_by_port_and_service():
    assert summary.classify(device(metadata={"open_ports": "631"})) == "printer"
    assert summary.classify(device(metadata={"open_ports": "80,9100"})) == "printer"
    assert (
        summary.classify(device(metadata={"services": "_printer._tcp.local"}))
        == "printer"
    )
    assert (
        summary.classify(device(metadata={"services": "_ipp._tcp.local"})) == "printer"
    )


def test_classify_windows_host_rdp_or_smb_with_netbios_name():
    assert summary.classify(device(metadata={"open_ports": "3389"})) == "windows host"
    assert (
        summary.classify(
            device(
                metadata={"open_ports": "445", "name_source": "NetBIOS"},
            )
        )
        == "windows host"
    )
    assert (
        summary.classify(device(metadata={"open_ports": "445", "name_source": "LLMNR"}))
        == "windows host"
    )


def test_classify_smb_without_netbios_name_is_not_windows():
    assert summary.classify(device(metadata={"open_ports": "445"})) != "windows host"


def test_classify_unix_host_ssh():
    assert summary.classify(device(metadata={"open_ports": "22"})) == "unix host"


def test_classify_apple_consumer_by_mdns_source_or_services():
    assert (
        summary.classify(device(metadata={"name_source": "mDNS"})) == "apple/consumer"
    )
    assert (
        summary.classify(device(metadata={"name_source": "mDNS services"}))
        == "apple/consumer"
    )
    assert (
        summary.classify(device(metadata={"services": "_airplay._tcp.local"}))
        == "apple/consumer"
    )


def test_classify_media_iot_by_device_type_or_ssdp():
    assert (
        summary.classify(device(metadata={"device_type": "television"})) == "media/iot"
    )
    assert summary.classify(device(metadata={"name_source": "SSDP"})) == "media/iot"


def test_classify_iot_makers_in_vendor_or_vendor_class():
    assert summary.classify(device(vendor="Espressif Inc.")) == "iot"
    assert summary.classify(device(vendor="Raspberry Pi Trading")) == "iot"
    assert summary.classify(device(metadata={"vendor_class": "tuya"})) == "iot"


def test_classify_unknown_when_nothing_matches():
    assert summary.classify(device(vendor="Acme Corp")) == "unknown"


def test_classify_iot_service_types():
    assert summary.classify(device(metadata={"services": "_miio._udp.local"})) == "iot"
    assert summary.classify(device(metadata={"services": "_hap._tcp.local"})) == "iot"
    assert summary.classify(device(metadata={"services": "_dkapi._tcp.local"})) == "iot"


def test_classify_media_service_types():
    assert (
        summary.classify(device(metadata={"services": "_googlecast._tcp.local"}))
        == "media/iot"
    )
    assert (
        summary.classify(device(metadata={"services": "_spotify-connect._tcp.local"}))
        == "media/iot"
    )


def test_classify_apple_service_type():
    assert (
        summary.classify(device(metadata={"services": "_companion-link._tcp.local"}))
        == "apple/consumer"
    )


def test_classify_service_type_beats_mdns_name_source():
    # A HomeKit light answers mDNS, but its service type is the better signal.
    assert (
        summary.classify(
            device(metadata={"name_source": "mDNS services", "services": "_hap._tcp"})
        )
        == "iot"
    )


def test_classify_appliance_from_web_fingerprint():
    assert (
        summary.classify(device(metadata={"appliance": "embedded http server"}))
        == "appliance"
    )


def test_classify_defaults_on_missing_and_malformed_input():
    assert summary.classify({}) == "unknown"
    assert summary.classify({"metadata": None}) == "unknown"
    assert summary.classify(None) == "unknown"
    assert summary.classify("not a dict") == "unknown"


def test_classify_rule_order_precedence():
    # Printer rule (2) beats windows host (3) and unix (4).
    assert summary.classify(device(metadata={"open_ports": "22,631,3389"})) == "printer"
    # Windows (3) beats unix (4).
    assert (
        summary.classify(device(metadata={"open_ports": "22,3389"})) == "windows host"
    )


# --- summarize ----------------------------------------------------------


def test_summarize_counts_named_unknown_randomized():
    devices = [
        device(ip="192.168.1.1", name="router", vendor="OpenWrt"),
        device(ip="192.168.1.2", name=FALLBACK.NAME, vendor=FALLBACK.VENDOR),
        device(
            ip="192.168.1.3",
            name="phone",
            vendor="Apple",
            metadata={"name_source": "mDNS", "randomized_mac": "true"},
        ),
    ]
    result = summary.summarize(devices)
    assert result["total"] == 3
    assert result["named"] == 2
    assert result["unknown"] == 1
    assert result["randomized"] == 1


def test_summarize_vendor_counts_include_unknown_vendor_and_sorting():
    devices = [
        device(ip="192.168.1.1", vendor="Apple"),
        device(ip="192.168.1.2", vendor="Apple"),
        device(ip="192.168.1.3", vendor="Espressif"),
        device(ip="192.168.1.4", vendor=FALLBACK.VENDOR),
        device(ip="192.168.1.5", vendor=FALLBACK.VENDOR),
    ]
    result = summary.summarize(devices)
    assert result["vendors"] == [
        ("Apple", 2),
        ("Unknown Vendor", 2),
        ("Espressif", 1),
    ]


def test_summarize_vendor_ties_broken_by_name():
    devices = [
        device(ip="192.168.1.1", vendor="zebra"),
        device(ip="192.168.1.2", vendor="alpha"),
    ]
    assert summary.summarize(devices)["vendors"] == [("alpha", 1), ("zebra", 1)]


def test_summarize_device_classes_sorted_by_count_then_name():
    devices = [
        device(ip="192.168.1.1", vendor="Acme"),
        device(ip="192.168.1.2", vendor="Acme"),
        device(ip="192.168.1.3", vendor="Acme", metadata={"open_ports": "22"}),
        device(ip="192.168.1.4", vendor="Acme", metadata={"open_ports": "631"}),
        device(ip="192.168.1.5", vendor="Acme"),
    ]
    result = summary.summarize(devices)
    assert result["device_classes"] == [
        ("unknown", 3),
        ("printer", 1),
        ("unix host", 1),
    ]


def test_summarize_anomaly_conflicting_macs_for_one_ip():
    observations = [
        ("192.168.1.5", "aa:bb:cc:dd:ee:01", "ARP"),
        ("192.168.1.5", "aa:bb:cc:dd:ee:02", "passive"),
        ("192.168.1.6", "aa:bb:cc:dd:ee:03", "ARP"),
    ]
    result = summary.summarize([], observations)
    assert result["anomalies"] == [
        "IP 192.168.1.5 seen with multiple MACs: aa:bb:cc:dd:ee:01, aa:bb:cc:dd:ee:02",
    ]


def test_summarize_anomaly_one_mac_on_multiple_ips():
    observations = [
        ("192.168.1.5", "aa:bb:cc:dd:ee:01", "ARP"),
        ("192.168.1.6", "aa:bb:cc:dd:ee:01", "ARP"),
    ]
    result = summary.summarize([], observations)
    assert result["anomalies"] == [
        "MAC aa:bb:cc:dd:ee:01 seen on multiple IPs: 192.168.1.5, 192.168.1.6",
    ]


def test_summarize_anomalies_are_sorted_and_deduped():
    observations = [
        ("192.168.1.9", "aa:bb:cc:dd:ee:09", "ARP"),
        ("192.168.1.9", "aa:bb:cc:dd:ee:10", "ARP"),
        ("192.168.1.2", "aa:bb:cc:dd:ee:01", "ARP"),
        ("192.168.1.3", "aa:bb:cc:dd:ee:01", "ARP"),
    ]
    result = summary.summarize([], observations)
    assert result["anomalies"] == sorted(result["anomalies"])
    assert len(result["anomalies"]) == 2


def test_summarize_security_risky_ports():
    devices = [
        device(ip="192.168.1.5", metadata={"open_ports": "23,445"}),
        device(ip="192.168.1.6", metadata={"open_ports": "80"}),
    ]
    result = summary.summarize(devices)
    assert result["security"] == [
        "192.168.1.5 exposes smb(445)",
        "192.168.1.5 exposes telnet(23)",
    ]


def test_summarize_security_snmp_public_community():
    devices = [
        device(ip="192.168.1.5", sys_descr="Linux router 5.15"),
        device(ip="192.168.1.6", sys_object_id="1.3.6.1"),
        device(ip="192.168.1.7"),  # no SNMP facts -> no finding
    ]
    result = summary.summarize(devices)
    if SNMP.COMMUNITY == "public":
        assert result["security"] == [
            "192.168.1.5 answers SNMP with the default community 'public'",
            "192.168.1.6 answers SNMP with the default community 'public'",
        ]
    else:
        assert result["security"] == []


def test_summarize_security_snmp_non_public_community(monkeypatch):
    monkeypatch.setattr(summary.SNMP, "COMMUNITY", "lantern-secret")
    devices = [device(ip="192.168.1.5", sys_descr="Linux router 5.15")]
    assert summary.summarize(devices)["security"] == []


def test_summarize_empty_input():
    result = summary.summarize([])
    assert result["total"] == 0
    assert result["named"] == 0
    assert result["unknown"] == 0
    assert result["randomized"] == 0
    assert result["vendors"] == []
    assert result["device_classes"] == []
    assert result["anomalies"] == []
    assert result["security"] == []
    assert result["lines"] == summary.format_summary(result)


def test_summarize_malformed_metadata_does_not_raise():
    devices = [
        device(ip="192.168.1.5", open_ports="not,even,ports,,junk"),
        device(ip="192.168.1.6", metadata=None),
        {"ip": "192.168.1.7", "mac": None, "name": None},
    ]
    result = summary.summarize(devices, observations=[("bad", None, "x")])
    assert result["total"] == 3
    # Junk open_ports parses to no ports at all -> nothing matched.
    assert ("unknown", 3) in result["device_classes"]


def test_summarize_open_ports_junk_ignored_but_valid_parsed():
    assert summary.classify(device(open_ports="22,junk,631")) == "printer"


# --- format_summary -----------------------------------------------------


def test_format_summary_empty_scan_line_shapes():
    lines = summary.format_summary(summary.summarize([]))
    assert lines == [
        "Scan summary: 0 device(s), 0 named, 0 unknown, 0 randomized MAC(s)",
        "Vendors: none",
        "Device classes: none",
        "Anomalies: none",
        "Security: none",
    ]


def test_format_summary_counts_line():
    devices = [
        device(ip="192.168.1.1", name="router", vendor="OpenWrt"),
        device(
            ip="192.168.1.2",
            name=FALLBACK.NAME,
            vendor=FALLBACK.VENDOR,
            metadata={"randomized_mac": "true"},
        ),
    ]
    lines = summary.format_summary(summary.summarize(devices))
    assert (
        lines[0] == "Scan summary: 2 device(s), 1 named, 1 unknown, 1 randomized MAC(s)"
    )
    assert lines[1] == "Vendors: OpenWrt 1, Unknown Vendor 1"


def test_format_summary_vendor_and_class_lines():
    devices = [
        device(ip="192.168.1.1", vendor="Apple", metadata={"open_ports": "22"}),
        device(ip="192.168.1.2", vendor="Apple", metadata={"open_ports": "22"}),
        device(ip="192.168.1.3", vendor="Espressif"),
    ]
    lines = summary.format_summary(summary.summarize(devices))
    assert "Vendors: Apple 2, Espressif 1" in lines
    assert "Device classes: unix host 2, iot 1" in lines


def test_format_summary_anomaly_and_security_lines():
    devices = [device(ip="192.168.1.5", metadata={"open_ports": "23"})]
    observations = [
        ("192.168.1.5", "aa:bb:cc:dd:ee:01", "ARP"),
        ("192.168.1.5", "aa:bb:cc:dd:ee:02", "ARP"),
    ]
    lines = summary.format_summary(summary.summarize(devices, observations))
    expected_anomaly = (
        "Anomaly: IP 192.168.1.5 seen with multiple MACs: "
        "aa:bb:cc:dd:ee:01, aa:bb:cc:dd:ee:02"
    )
    assert expected_anomaly in lines
    assert "Security: 192.168.1.5 exposes telnet(23)" in lines
    assert "Anomalies: none" not in lines
    assert "Security: none" not in lines
