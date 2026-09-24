import pytest
from scapy.all import DNS, DNSRR, IP, UDP

import lantern.metadata as metadata
import lantern.resolvers.mdns as mdns
from lantern.constants import MDNS


@pytest.fixture(autouse=True)
def clean_scan():
    mdns.reset_mdns_service_cache()
    metadata.reset_metadata()
    yield
    mdns.reset_mdns_service_cache()
    metadata.reset_metadata()


def _mdns_response(ip, *answers):
    return IP(src=ip) / UDP(sport=5353, dport=5353) / DNS(qr=1, an=list(answers))


def _prefixed(*strings):
    """Build length-prefixed DNS TXT rdata bytes from plain strings."""
    return b"".join(bytes([len(s)]) + s for s in strings)


def test_txt_chunks_parses_length_prefixed_strings():
    rdata = _prefixed(b"md=AppleTV3,1", b"osvers=17.4")

    assert mdns._txt_chunks(rdata) == [b"md=AppleTV3,1", b"osvers=17.4"]
    assert mdns._txt_chunks(b"") == []


def test_txt_chunks_rejects_malformed_lengths():
    # First byte promises more bytes than the record carries.
    assert mdns._txt_chunks(b"\x0cmd=short") == []


def test_txt_pairs_handles_wire_bytes():
    rdata = _prefixed(b"md=AppleTV3,1", b"am=AirPlay", b"not-a-pair", b"=empty")

    assert mdns._txt_pairs(rdata) == [
        ("md", "AppleTV3,1"),
        ("am", "AirPlay"),
    ]


def test_txt_pairs_handles_scapy_list_and_plain_string():
    assert mdns._txt_pairs([b"md=AppleTV3,1", b"osvers=17.4"]) == [
        ("md", "AppleTV3,1"),
        ("osvers", "17.4"),
    ]
    assert mdns._txt_pairs("ver=1.2.3\x00deviceid=AB12") == [
        ("ver", "1.2.3"),
        ("deviceid", "AB12"),
    ]


def test_txt_pairs_rejects_unexpected_shapes():
    assert mdns._txt_pairs(None) == []
    assert mdns._txt_pairs(7) == []
    assert mdns._txt_pairs([b"ok=1", 42]) == []
    # A length prefix that overruns the blob records nothing.
    assert mdns._txt_pairs(b"\xffmd=AppleTV3,1") == []


def test_service_type_extracts_type_from_rrname():
    assert mdns._service_type("_airplay._tcp.local") == "_airplay._tcp"
    assert mdns._service_type(b"Office Printer._ipp._tcp.local.") == "_ipp._tcp"
    assert mdns._service_type("_googlecast._udp.local") == "_googlecast._udp"


def test_service_type_rejects_non_service_names():
    assert mdns._service_type("host-1.local") is None
    assert mdns._service_type("_tcp.local") is None
    assert mdns._service_type(b"\xff\xfe.local") is None
    assert mdns._service_type(None) is None


def _txt(rrname, rdata):
    return DNSRR(rrname=rrname, type="TXT", rdata=rdata)


def _srv(rrname):
    return DNSRR(rrname=rrname, type="SRV", rdata=b"\x00\x00\x1f\x90")


def test_browse_records_txt_metadata(monkeypatch):
    responses = [
        _mdns_response(
            "192.168.1.10",
            _txt(
                "Living Room TV._airplay._tcp.local",
                [b"md=AppleTV3,1", b"am=AirPlay", b"deviceid=AA:BB:CC:DD:EE:FF"],
            ),
        ),
        _mdns_response(
            "192.168.1.20",
            _txt(
                "Office Printer._printer._tcp.local",
                b"\x09ver=1.2.3\x09osvers=11",
            ),
        ),
    ]
    monkeypatch.setattr(mdns, "_mdns_query", lambda *a, **k: responses)

    assert mdns.browse_mdns_services() == {}

    assert metadata.get_metadata("192.168.1.10") == {
        "model": "AppleTV3,1",
        "serial": "AA:BB:CC:DD:EE:FF",
    }
    assert metadata.get_metadata("192.168.1.20") == {
        "version": "1.2.3",
        "os": "11",
    }


def test_browse_records_services_from_srv(monkeypatch):
    responses = [
        _mdns_response(
            "192.168.1.10",
            _srv("_airplay._tcp.local"),
            _srv("_raop._tcp.local"),
            _srv("_airplay._tcp.local."),
        ),
        _mdns_response("192.168.1.30", _srv("host-1.local")),
    ]
    monkeypatch.setattr(mdns, "_mdns_query", lambda *a, **k: responses)

    mdns.browse_mdns_services()

    assert metadata.get_metadata("192.168.1.10") == {
        "services": "_airplay._tcp; _raop._tcp"
    }
    assert metadata.get_metadata("192.168.1.30") == {}


def test_browse_ignores_malformed_txt(monkeypatch):
    responses = [
        _mdns_response(
            "192.168.1.10",
            _txt("Living Room TV._airplay._tcp.local", b"\xffmd=AppleTV3,1"),
        )
    ]
    monkeypatch.setattr(mdns, "_mdns_query", lambda *a, **k: responses)

    assert mdns.browse_mdns_services() == {}
    assert metadata.get_metadata("192.168.1.10") == {}


def test_browse_return_value_unchanged_with_metadata(monkeypatch):
    responses = [
        _mdns_response(
            "192.168.1.10",
            _txt("Living Room TV._airplay._tcp.local", [b"md=AppleTV3,1"]),
            DNSRR(
                rrname="_airplay._tcp.local",
                type="PTR",
                rdata=b"Living Room TV._airplay._tcp.local",
            ),
        )
    ]
    calls = []

    def fake_query(qnames, timeout):
        calls.append(qnames)
        return responses

    monkeypatch.setattr(mdns, "_mdns_query", fake_query)

    services = mdns.browse_mdns_services()

    assert services["192.168.1.10"] == "Living Room TV"
    assert metadata.get_metadata("192.168.1.10") == {"model": "AppleTV3,1"}
    # The browse result is cached per scan exactly as before.
    mdns.browse_mdns_services()
    assert len(calls) == 1


def test_browse_metadata_keys_are_case_insensitive(monkeypatch):
    responses = [
        _mdns_response(
            "192.168.1.10",
            _txt(
                "Living Room TV._airplay._tcp.local",
                [b"MD=AppleTV3,1"],
            ),
        )
    ]
    monkeypatch.setattr(mdns, "_mdns_query", lambda *a, **k: responses)

    mdns.browse_mdns_services()

    assert metadata.get_metadata("192.168.1.10") == {"model": "AppleTV3,1"}


def test_txt_metadata_constants_cover_all_keys():
    assert set(mdns._TXT_KEY_TO_METADATA) == set(MDNS.TXT_METADATA_KEYS)


def test_static_service_types_cover_smart_home_stacks():
    for service in ("_miio._udp.local", "_hap._tcp.local", "_dkapi._tcp.local"):
        assert service in MDNS.SERVICE_TYPES


def _meta_answer(service_type):
    return DNSRR(
        rrname="_services._dns-sd._udp.local",
        type="PTR",
        rdata=service_type.encode(),
    )


def test_browse_discovers_and_browses_extra_service_types(monkeypatch):
    # `_FC9F5ED42C8A._tcp` is a Google Nearby service named after the device's
    # MAC, so it can never be in the static list.
    meta = _mdns_response("192.168.1.30", _meta_answer("_FC9F5ED42C8A._tcp.local"))
    instance = _mdns_response(
        "192.168.1.30",
        DNSRR(
            rrname="_FC9F5ED42C8A._tcp.local",
            type="PTR",
            rdata=b"Android_JCMBDRVA._FC9F5ED42C8A._tcp.local",
        ),
    )
    calls = []

    def fake_query(qnames, timeout):
        calls.append(list(qnames))
        return [meta] if len(calls) == 1 else [instance]

    monkeypatch.setattr(mdns, "_mdns_query", fake_query)

    services = mdns.browse_mdns_services()

    assert calls[0] == [MDNS.SERVICE_BROWSE, *MDNS.SERVICE_TYPES]
    assert calls[1] == ["_FC9F5ED42C8A._tcp.local"]
    assert services["192.168.1.30"] == "Android_JCMBDRVA"


def test_browse_does_not_requery_known_service_types(monkeypatch):
    meta = _mdns_response("192.168.1.30", _meta_answer("_airplay._tcp.local"))
    calls = []

    def fake_query(qnames, timeout):
        calls.append(list(qnames))
        return [meta]

    monkeypatch.setattr(mdns, "_mdns_query", fake_query)

    mdns.browse_mdns_services()

    assert len(calls) == 1
