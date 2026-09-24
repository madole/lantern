import lantern.main as main
import lantern.metadata as metadata


class _Host:
    def __init__(self, ip, mac):
        self.psrc = ip
        self.hwsrc = mac


def test_scan_records_open_ports_and_attaches_metadata(monkeypatch):
    port_probes = []

    monkeypatch.setattr(main, "start_passive_scan", lambda: object())
    monkeypatch.setattr(main, "finish_passive_scan", lambda _sniffer: None)
    monkeypatch.setattr(main, "start_prefetch_broadcast", lambda: object())
    monkeypatch.setattr(main, "finish_prefetch_broadcast", lambda _thread: None)
    monkeypatch.setattr(main, "resolve_passive_names", lambda: None)
    monkeypatch.setattr(main, "get_passive_macs", lambda: {})
    monkeypatch.setattr(
        main, "srp", lambda *a, **k: ([(None, _Host("192.168.1.10", "aa:bb"))], [])
    )
    monkeypatch.setattr(main, "resolve_name", lambda ip, device=None: "tv")
    monkeypatch.setattr(main, "get_vendor", lambda mac: "Acme")
    monkeypatch.setattr(main, "is_locally_administered", lambda mac: False)

    def fake_open_ports(ip_address, timeout=None):
        port_probes.append(ip_address)
        metadata.record(ip_address, metadata.OPEN_PORTS, "22,80", "ports")

    monkeypatch.setattr(main, "record_open_ports", fake_open_ports)

    devices = main.scan_network("192.168.1.0/24")

    # The port inventory runs once per discovered device and its facts reach
    # the device record that main reads after the drain.
    assert port_probes == ["192.168.1.10"]
    assert devices[0]["metadata"]["open_ports"] == "22,80"


def test_scan_summary_handles_no_devices(monkeypatch):
    monkeypatch.setattr(main, "start_passive_scan", lambda: object())
    monkeypatch.setattr(main, "finish_passive_scan", lambda _sniffer: None)
    monkeypatch.setattr(main, "start_prefetch_broadcast", lambda: object())
    monkeypatch.setattr(main, "finish_prefetch_broadcast", lambda _thread: None)
    monkeypatch.setattr(main, "resolve_passive_names", lambda: None)
    monkeypatch.setattr(main, "get_passive_macs", lambda: {})
    monkeypatch.setattr(main, "srp", lambda *a, **k: ([], []))

    # An empty scan still summarizes cleanly rather than raising.
    assert main.scan_network("192.168.1.0/24") == []
