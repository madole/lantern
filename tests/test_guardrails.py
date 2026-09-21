import ipaddress

import pytest
from scapy.all import IP, Raw
from scapy.layers.snmp import SNMP as SNMP_PACKET
from scapy.layers.snmp import SNMPget, SNMPset

import lantern.passive as passive
import lantern.resolvers.name as name
import lantern.resolvers.snmp as snmp
import lantern.resolvers.ssdp as ssdp
from lantern import scope
from lantern.constants import FALLBACK
from lantern.constants import SNMP as SNMP_CONST
from lantern.resolvers import web


@pytest.fixture(autouse=True)
def clean_scope():
    scope.clear_scan_network()
    yield
    scope.clear_scan_network()


def test_is_in_scope_allows_everything_without_a_scan():
    assert scope.is_in_scope("192.168.1.10")
    assert scope.is_in_scope("garbage")


def test_set_scan_network_parses_membership():
    scope.set_scan_network("192.168.1.0/24")

    assert scope.get_scan_network() == ipaddress.ip_network("192.168.1.0/24")
    assert scope.is_in_scope("192.168.1.10")
    assert not scope.is_in_scope("10.0.0.1")
    assert not scope.is_in_scope("192.168.2.10")
    assert not scope.is_in_scope("not-an-ip")


def test_require_in_scope_rejects_outside_addresses():
    scope.set_scan_network("192.168.1.0/24")

    assert scope.require_in_scope("192.168.1.10") == "192.168.1.10"
    with pytest.raises(scope.OutOfScopeError):
        scope.require_in_scope("10.0.0.1")


def test_resolve_name_skips_out_of_scope_address(monkeypatch):
    probed = []
    monkeypatch.setattr(
        name, "NAME_SOURCES", (("spy", lambda ip: probed.append(ip) or "name"),)
    )
    scope.set_scan_network("192.168.1.0/24")

    assert name.resolve_name("10.0.0.5") == FALLBACK.NAME
    assert probed == []


def test_resolve_name_probes_in_scope_address(monkeypatch):
    monkeypatch.setattr(name, "NAME_SOURCES", (("spy", lambda ip: "name"),))
    scope.set_scan_network("192.168.1.0/24")

    assert name.resolve_name("192.168.1.10") == "name"


def test_run_source_skips_out_of_scope_address():
    probed = []
    scope.set_scan_network("192.168.1.0/24")

    result = name._run_source("spy", probed.append, "10.0.0.5", None)

    assert result is None
    assert probed == []


def test_discover_ssdp_ignores_out_of_scope_responders(monkeypatch):
    ssdp.reset_ssdp_cache()
    monkeypatch.setattr(
        ssdp,
        "_ssdp_search",
        lambda timeout: [
            ("192.168.1.5", "http://192.168.1.5/d.xml"),
            ("10.0.0.9", "http://10.0.0.9/d.xml"),
        ],
    )
    scope.set_scan_network("192.168.1.0/24")

    try:
        assert ssdp.discover_ssdp() == {
            "192.168.1.5": "http://192.168.1.5/d.xml",
        }
    finally:
        ssdp.reset_ssdp_cache()


def test_resolve_passive_names_skips_out_of_scope(monkeypatch):
    passive.reset_passive_cache()
    passive._locations["10.0.0.9"] = "http://10.0.0.9/d.xml"
    fetched = []
    monkeypatch.setattr(
        passive, "_fetch_ssdp_description", lambda location: fetched.append(location)
    )
    scope.set_scan_network("192.168.1.0/24")

    try:
        assert passive.resolve_passive_names() == {}
        assert fetched == []
    finally:
        passive.reset_passive_cache()


def test_snmp_query_is_read_only():
    query = snmp._build_query("192.168.1.10", SNMP_CONST.NAME_OIDS)
    pdu = query[SNMP_PACKET].PDU

    assert isinstance(pdu, SNMPget)
    assert not isinstance(pdu, SNMPset)


class _FakeSniffer:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def start(self):
        pass

    def join(self):
        self.kwargs["started_callback"]()


def test_ssdp_search_is_read_only(monkeypatch):
    sent = []
    monkeypatch.setattr(ssdp, "AsyncSniffer", _FakeSniffer)
    monkeypatch.setattr(ssdp, "sendp", lambda packet, **kwargs: sent.append(packet))

    ssdp._ssdp_search(timeout=0)

    assert len(sent) == 1
    assert sent[0][IP].dst == ssdp.SSDP.ADDR
    payload = sent[0][Raw].load.decode()
    assert payload.startswith("M-SEARCH")


def test_require_read_only_rejects_mutating_operations():
    scope.require_read_only("snmp get")

    with pytest.raises(scope.ReadOnlyViolation):
        scope.require_read_only("snmp set")


@pytest.fixture
def tracked_ssdp_fetch(monkeypatch):
    opened = []

    def fake_open(request, timeout=None):
        opened.append(request.full_url)
        return None

    monkeypatch.setattr(ssdp._opener, "open", fake_open)
    return opened


@pytest.mark.parametrize(
    "location",
    [
        "file:///etc/shadow",
        "ftp://192.168.1.5/desc.xml",
        "http://user:pass@192.168.1.5/desc.xml",
        "http://localhost/desc.xml",
        "http://attacker.example/desc.xml",
    ],
)
def test_get_ssdp_description_rejects_unsafe_locations(tracked_ssdp_fetch, location):
    scope.set_scan_network("192.168.1.0/24")

    assert ssdp.get_ssdp_description(location) is None
    assert tracked_ssdp_fetch == []


def test_get_ssdp_description_rejects_out_of_scope_host(tracked_ssdp_fetch):
    scope.set_scan_network("192.168.1.0/24")

    assert ssdp.get_ssdp_description("http://10.0.0.9/desc.xml") is None
    assert tracked_ssdp_fetch == []


def test_get_ssdp_description_fetches_in_scope_http_host(monkeypatch):
    fetched = []

    class FakeResponse:
        def read(self, amount=-1):
            return b"<root><friendlyName>Living Room TV</friendlyName></root>"

        def close(self):
            pass

    def fake_open(request, timeout=None):
        fetched.append(request.full_url)
        return FakeResponse()

    monkeypatch.setattr(ssdp._opener, "open", fake_open)
    scope.set_scan_network("192.168.1.0/24")

    assert ssdp.get_ssdp_description("http://192.168.1.5/desc.xml") == (
        "Living Room TV"
    )
    assert fetched == ["http://192.168.1.5/desc.xml"]


def test_get_web_title_ignores_off_subnet_redirect(monkeypatch):
    class FakeResponse:
        def read(self, amount=-1):
            return b"<html><title>cloud metadata</title></html>"

        def geturl(self):
            return "http://169.254.169.254/latest/meta-data/"

        def close(self):
            pass

    monkeypatch.setattr(web.urllib.request, "urlopen", lambda *a, **k: FakeResponse())
    scope.set_scan_network("192.168.1.0/24")

    assert web.get_web_title("192.168.1.5") is None
