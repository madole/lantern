"""DHCP metadata side effects of the passive listener."""

import pytest
from scapy.all import BOOTP, DHCP, IP, UDP

from lantern import metadata, passive


@pytest.fixture(autouse=True)
def _clean_metadata():
    metadata.reset_metadata()
    yield
    metadata.reset_metadata()


def _dhcp(ip, *options):
    return (
        IP(src="192.168.1.1", dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(yiaddr=ip)
        / DHCP(options=list(options))
    )


def test_parse_dhcp_records_metadata_options():
    pkt = _dhcp(
        "192.168.1.5",
        ("hostname", b"laptop"),
        ("vendor_class_id", b"PXEClient"),
        ("client_FQDN", b"\x00laptop.example"),
        ("client_id", b"\x01client-aa-bb"),
        ("param_req_list", b"\x01\x03\x06\x0f\x2c"),
    )

    assert passive.parse_dhcp(pkt) == ("192.168.1.5", ["laptop"])
    assert metadata.get_metadata("192.168.1.5") == {
        "vendor_class": "PXEClient",
        "fqdn": "laptop.example",
        "client_id": "client-aa-bb",
        "dhcp_fingerprint": "1,3,6,15,44",
    }


def test_parse_dhcp_metadata_sources_are_labeled():
    pkt = _dhcp(
        "192.168.1.5",
        ("hostname", b"laptop"),
        ("vendor_class_id", b"PXEClient"),
    )

    passive.parse_dhcp(pkt)

    assert metadata.get_metadata_records("192.168.1.5")["vendor_class"] == {
        "value": "PXEClient",
        "source": "DHCP",
    }


def test_parse_dhcp_matches_numeric_option_ids():
    pkt = _dhcp(
        "192.168.1.5",
        ("hostname", b"laptop"),
        (60, b"OtherOS"),
        (81, b"\x00host.local"),
        (61, b"\x01id-42"),
        (55, b"\x01\x1f"),
    )

    assert passive.parse_dhcp(pkt) == ("192.168.1.5", ["laptop"])
    assert metadata.get_metadata("192.168.1.5") == {
        "vendor_class": "OtherOS",
        "fqdn": "host.local",
        "client_id": "id-42",
        "dhcp_fingerprint": "1,31",
    }


def test_parse_dhcp_fingerprint_maps_known_option_names():
    pkt = _dhcp(
        "192.168.1.5",
        ("hostname", b"laptop"),
        ("param_req_list", ["hostname", "vendor_class_id", 7]),
    )

    passive.parse_dhcp(pkt)

    assert metadata.get_metadata("192.168.1.5")["dhcp_fingerprint"] == "12,60,7"


def test_handle_records_metadata_without_hostname():
    passive.reset_passive_cache()
    pkt = _dhcp("192.168.1.6", ("vendor_class_id", b"PXEClient"))

    assert passive.parse_dhcp(pkt) is None
    passive._handle(pkt)

    assert passive.get_passive_name("192.168.1.6") is None
    assert metadata.get_metadata("192.168.1.6") == {"vendor_class": "PXEClient"}


def test_parse_dhcp_without_metadata_options_records_nothing():
    pkt = _dhcp("192.168.1.5", ("hostname", b"laptop"))

    assert passive.parse_dhcp(pkt) == ("192.168.1.5", ["laptop"])
    assert metadata.get_metadata("192.168.1.5") == {}


def test_parse_dhcp_malformed_options_record_nothing():
    pkt = _dhcp(
        "192.168.1.5",
        ("hostname", b"laptop"),
        ("vendor_class_id",),
        ("param_req_list", "not-bytes"),
        ("client_id", 0),
        ("client_FQDN", b"\x00  \x00"),
    )

    assert passive.parse_dhcp(pkt) == ("192.168.1.5", ["laptop"])
    assert metadata.get_metadata("192.168.1.5") == {}


def test_parse_dhcp_metadata_never_lets_errors_escape(monkeypatch):
    pkt = _dhcp(
        "192.168.1.5",
        ("hostname", b"laptop"),
        ("vendor_class_id", b"PXEClient"),
    )

    def explode(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(metadata, "record", explode)

    assert passive.parse_dhcp(pkt) == ("192.168.1.5", ["laptop"])
