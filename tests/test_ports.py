import pytest

from lantern import scope
from lantern.metadata import OPEN_PORTS, get_metadata_records, reset_metadata
from lantern.resolvers import ports


@pytest.fixture(autouse=True)
def clean_metadata():
    reset_metadata()
    yield
    reset_metadata()


def test_open_ports_sorted(monkeypatch):
    open_answered = {8080, 22, 443, 80}
    monkeypatch.setattr(
        ports, "_is_open", lambda ip, port, timeout: port in open_answered
    )

    assert ports.open_ports("192.168.1.10") == [22, 80, 443, 8080]


def test_open_ports_closed_excluded(monkeypatch):
    monkeypatch.setattr(ports, "_is_open", lambda ip, port, timeout: False)

    assert ports.open_ports("192.168.1.10") == []


def test_open_ports_exception_is_treated_as_closed(monkeypatch):
    def fake_is_open(ip_address, port, timeout):
        if port == 80:
            raise RuntimeError("boom")
        return port == 22

    monkeypatch.setattr(ports, "_is_open", fake_is_open)

    # The failing port does not abort the others.
    assert ports.open_ports("192.168.1.10") == [22]


def test_open_ports_out_of_scope_skips_probe(monkeypatch):
    scope.set_scan_network("192.168.1.0/24")
    try:
        probed = []

        def fake_is_open(ip_address, port, timeout):
            probed.append(port)
            return True

        monkeypatch.setattr(ports, "_is_open", fake_is_open)

        assert ports.open_ports("10.0.0.5") == []
        assert probed == []
    finally:
        scope.clear_scan_network()


def test_record_open_ports_writes_metadata(monkeypatch):
    open_answered = {443, 22}
    monkeypatch.setattr(
        ports, "_is_open", lambda ip, port, timeout: port in open_answered
    )

    assert ports.record_open_ports("192.168.1.10") == [22, 443]
    assert get_metadata_records("192.168.1.10") == {
        OPEN_PORTS: {"value": "22,443", "source": "ports"}
    }


def test_record_open_ports_records_nothing_when_closed(monkeypatch):
    monkeypatch.setattr(ports, "_is_open", lambda ip, port, timeout: False)

    assert ports.record_open_ports("192.168.1.10") == []
    assert get_metadata_records("192.168.1.10") == {}


def test_record_open_ports_survives_record_failure(monkeypatch):
    monkeypatch.setattr(ports, "_is_open", lambda ip, port, timeout: port == 22)

    def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(ports, "record", boom)

    assert ports.record_open_ports("192.168.1.10") == [22]
