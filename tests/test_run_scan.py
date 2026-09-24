import json

import lantern.main as main
import lantern.metadata as metadata


class _Host:
    def __init__(self, ip, mac):
        self.psrc = ip
        self.hwsrc = mac


def _patch_scan(monkeypatch):
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
        metadata.record(ip_address, metadata.OPEN_PORTS, "22,80", "ports")

    monkeypatch.setattr(main, "record_open_ports", fake_open_ports)


def test_run_scan_returns_json_serializable_result(monkeypatch):
    _patch_scan(monkeypatch)

    result = main.run_scan("192.168.1.0/24")

    assert set(result) == {
        "range",
        "elapsed_seconds",
        "device_count",
        "devices",
        "summary",
    }
    assert result["range"] == "192.168.1.0/24"
    assert result["device_count"] == 1
    assert result["devices"][0]["name"] == "tv"
    assert result["devices"][0]["metadata"]["open_ports"] == "22,80"
    assert result["summary"]["total"] == 1

    # The whole result must survive JSON encoding, which is what the MCP tools
    # and `--json` rely on.
    assert json.loads(json.dumps(result))["device_count"] == 1


def test_run_scan_with_no_devices(monkeypatch):
    _patch_scan(monkeypatch)
    monkeypatch.setattr(main, "srp", lambda *a, **k: ([], []))

    result = main.run_scan("192.168.1.0/24")

    assert result["devices"] == []
    assert result["device_count"] == 0
    assert result["summary"]["total"] == 0
    json.dumps(result)
