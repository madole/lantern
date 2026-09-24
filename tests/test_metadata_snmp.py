import pytest
from scapy.all import IP, UDP
from scapy.layers.snmp import SNMP as SNMP_PACKET
from scapy.layers.snmp import SNMPresponse, SNMPvarbind

from lantern.constants import SNMP as SNMP_CONST
from lantern.metadata import UPTIME, get_metadata, reset_metadata
from lantern.resolvers import snmp


@pytest.fixture(autouse=True)
def _clean_metadata():
    reset_metadata()
    yield
    reset_metadata()


def _snmp_reply(ip, varbinds, error=0):
    return (
        IP(src=ip)
        / UDP()
        / SNMP_PACKET(
            community="public",
            PDU=SNMPresponse(error=error, varbindlist=varbinds),
        )
    )


def test_get_snmp_name_records_metadata(monkeypatch):
    reply = _snmp_reply(
        "192.168.1.10",
        [
            SNMPvarbind(oid=SNMP_CONST.SYS_NAME, value="core-switch"),
            SNMPvarbind(oid=SNMP_CONST.SYS_OBJECT_ID, value="1.3.6.1.4.1.9.1.222"),
            # 3d 4h 5m in TimeTicks centiseconds.
            SNMPvarbind(oid=SNMP_CONST.SYS_UPTIME, value=27390000),
            SNMPvarbind(oid=SNMP_CONST.SYS_CONTACT, value="netops@example.com"),
            SNMPvarbind(oid=SNMP_CONST.SYS_LOCATION, value="Rack 12"),
        ],
    )
    monkeypatch.setattr(snmp, "sr1", lambda *a, **k: reply)

    assert snmp.get_snmp_name("192.168.1.10") == "core-switch"

    metadata = get_metadata("192.168.1.10")
    assert metadata["sys_object_id"] == "1.3.6.1.4.1.9.1.222"
    assert metadata[UPTIME] == "3d 4h 5m"
    assert metadata["contact"] == "netops@example.com"
    assert metadata["location"] == "Rack 12"
    assert "sys_descr" not in metadata


def test_get_snmp_name_falls_back_and_records_uptime(monkeypatch):
    reply = _snmp_reply(
        "192.168.1.10",
        [
            SNMPvarbind(oid=SNMP_CONST.SYS_DESCR, value="Linux NAS 6.1"),
            # 15h 15m in TimeTicks centiseconds.
            SNMPvarbind(oid=SNMP_CONST.SYS_UPTIME, value=5493000),
        ],
    )
    monkeypatch.setattr(snmp, "sr1", lambda *a, **k: reply)

    assert snmp.get_snmp_name("192.168.1.10") == "Linux NAS 6.1"

    metadata = get_metadata("192.168.1.10")
    assert metadata["sys_descr"] == "Linux NAS 6.1"
    assert metadata[UPTIME] == "15h 15m"


def test_snmp_get_includes_metadata_oids(monkeypatch):
    captured = {}

    def fake_sr1(packet, *a, **k):
        captured["oids"] = tuple(
            snmp._varbind_oid(varbind)
            for varbind in packet[SNMP_PACKET].PDU.varbindlist
        )
        return None

    monkeypatch.setattr(snmp, "sr1", fake_sr1)

    assert snmp.get_snmp_name("192.168.1.10") is None

    assert captured["oids"] == SNMP_CONST.NAME_OIDS + SNMP_CONST.METADATA_OIDS


def test_error_reply_records_no_metadata(monkeypatch):
    reply = _snmp_reply(
        "192.168.1.10",
        [
            SNMPvarbind(oid=SNMP_CONST.SYS_DESCR, value="Linux NAS 6.1"),
            SNMPvarbind(oid=SNMP_CONST.SYS_CONTACT, value="netops@example.com"),
        ],
        error=2,
    )
    monkeypatch.setattr(snmp, "sr1", lambda *a, **k: reply)

    assert snmp.get_snmp_name("192.168.1.10") is None
    assert get_metadata("192.168.1.10") == {}


def test_non_numeric_uptime_records_nothing(monkeypatch):
    reply = _snmp_reply(
        "192.168.1.10",
        [SNMPvarbind(oid=SNMP_CONST.SYS_UPTIME, value="not ticks")],
    )
    monkeypatch.setattr(snmp, "sr1", lambda *a, **k: reply)

    assert snmp.get_snmp_name("192.168.1.10") is None
    assert get_metadata("192.168.1.10") == {}


def test_metadata_values_are_not_name_truncated(monkeypatch):
    long_descr = "B" * (SNMP_CONST.MAX_NAME_LENGTH + 40)
    reply = _snmp_reply(
        "192.168.1.10",
        [SNMPvarbind(oid=SNMP_CONST.SYS_DESCR, value=long_descr)],
    )
    monkeypatch.setattr(snmp, "sr1", lambda *a, **k: reply)

    assert snmp.get_snmp_name("192.168.1.10") == "B" * SNMP_CONST.MAX_NAME_LENGTH
    assert get_metadata("192.168.1.10")["sys_descr"] == long_descr
