import threading
import time

import pytest
from scapy.all import DNS, DNSRR, IP, UDP
from scapy.layers.snmp import SNMP as SNMP_PACKET
from scapy.layers.snmp import SNMPresponse, SNMPvarbind

import network_lister.resolvers.name as name
from network_lister.constants import BANNER, FALLBACK
from network_lister.constants import SNMP as SNMP_CONST
from network_lister.resolvers import (
    banner,
    llmnr,
    mdns,
    router_dns,
    snmp,
    ssdp,
    tls,
    vendor,
    web,
)
from network_lister.resolvers.name import NAME_SOURCES


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def read(self, amount=-1):
        return self.body

    def close(self):
        pass


def test_is_generic_title():
    assert web.is_generic_title("404 - Page not found")
    assert web.is_generic_title("Apache2 Ubuntu Default Page")
    assert web.is_generic_title("Index of /")
    assert not web.is_generic_title("Living Room TV")


def test_get_web_title_ignores_error_page(monkeypatch):
    body = b"<html><head><title>404 - Page not found</title></head></html>"
    monkeypatch.setattr(
        web.urllib.request, "urlopen", lambda *a, **k: FakeResponse(body)
    )

    assert web.get_web_title("192.168.1.10") is None


def test_get_web_title_returns_device_name(monkeypatch):
    body = b"<html><head><title>Living Room TV</title></head></html>"
    monkeypatch.setattr(
        web.urllib.request, "urlopen", lambda *a, **k: FakeResponse(body)
    )

    assert web.get_web_title("192.168.1.10") == "Living Room TV"


def test_get_web_title_falls_through_generic_page(monkeypatch):
    generic = b"<html><head><title>404 - Page not found</title></head></html>"
    named = b"<html><head><title>Office Printer</title></head></html>"
    responses = [generic, named]

    def fake_urlopen(request, *a, **k):
        return FakeResponse(responses.pop(0))

    monkeypatch.setattr(web.urllib.request, "urlopen", fake_urlopen)

    assert web.get_web_title("192.168.1.20") == "Office Printer"


def test_get_web_title_tries_alternate_ports(monkeypatch):
    urls = []

    def fake_urlopen(request, *a, **k):
        urls.append(request.full_url)
        raise OSError("connection refused")

    monkeypatch.setattr(web.urllib.request, "urlopen", fake_urlopen)

    assert web.get_web_title("192.168.1.20") is None
    assert "http://192.168.1.20:80" in urls
    assert "https://192.168.1.20:443" in urls
    assert "http://192.168.1.20:8080" in urls


def test_certificate_names_prefers_san():
    certificate = {
        "subjectAltName": (("DNS", "printer.local"),),
        "subject": ((("commonName", "ignored"),),),
    }

    assert tls.certificate_names(certificate) == ["printer.local", "ignored"]


def test_certificate_names_falls_back_to_common_name():
    certificate = {"subject": ((("commonName", "living-room-tv"),),)}

    assert tls.certificate_names(certificate) == ["living-room-tv"]


def test_certificate_names_without_certificate():
    assert tls.certificate_names(None) == []


def test_clean_cert_name_rejects_wildcards_and_ips():
    assert tls.clean_cert_name("Office Printer", "192.168.1.10") == "Office Printer"
    assert tls.clean_cert_name("*.example.com", "192.168.1.10") is None
    assert tls.clean_cert_name("192.168.1.10", "192.168.1.10") is None
    assert tls.clean_cert_name("192.168.1.10", "192.168.1.20") is None
    assert tls.clean_cert_name("", "192.168.1.10") is None


def test_get_tls_name(monkeypatch):
    monkeypatch.setattr(
        tls,
        "_fetch_certificate",
        lambda *a, **k: {"subjectAltName": (("DNS", "kitchen-speaker"),)},
    )

    assert tls.get_tls_name("192.168.1.10") == "kitchen-speaker"


def test_get_tls_name_tries_ports_until_match(monkeypatch):
    ports = []

    def fake_fetch(ip, port, timeout):
        ports.append(port)
        if port == tls.TLS.PORTS[-1]:
            return {"subject": ((("commonName", "nas"),),)}
        return None

    monkeypatch.setattr(tls, "_fetch_certificate", fake_fetch)

    assert tls.get_tls_name("192.168.1.10") == "nas"
    assert ports == list(tls.TLS.PORTS)


def test_tls_runs_after_snmp_before_web_title():
    sources = [source for source, _ in NAME_SOURCES]

    assert sources.index("TLS certificate") == sources.index("SNMP") + 1
    assert sources.index("TLS certificate") < sources.index("web title")


def test_parse_ssdp_location():
    payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"CACHE-CONTROL: max-age=1800\r\n"
        b"LOCATION: http://192.168.1.5:9197/dmr\r\n"
        b"ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n\r\n"
    )

    assert ssdp.parse_ssdp_location(payload) == "http://192.168.1.5:9197/dmr"


def test_parse_ssdp_location_missing_header():
    assert ssdp.parse_ssdp_location(b"HTTP/1.1 200 OK\r\n\r\n") is None


def test_parse_ssdp_description_prefers_friendly_name():
    body = b"""<?xml version="1.0"?>
    <root xmlns="urn:schemas-upnp-org:device-1-0">
      <device>
        <friendlyName>Living Room TV</friendlyName>
        <manufacturer>Samsung</manufacturer>
        <modelName>UE55</modelName>
      </device>
    </root>"""

    assert ssdp.parse_ssdp_description(body) == "Living Room TV"


def test_parse_ssdp_description_falls_back_to_model():
    body = b"""<?xml version="1.0"?>
    <root><device>
      <manufacturer>Samsung</manufacturer>
      <modelName>UE55</modelName>
    </device></root>"""

    assert ssdp.parse_ssdp_description(body) == "UE55"


def test_parse_ssdp_description_rejects_malformed_xml():
    assert ssdp.parse_ssdp_description(b"not xml") is None


def test_ssdp_runs_after_dns_sources():
    sources = [source for source, _ in NAME_SOURCES]

    assert sources.index("SSDP") == sources.index("mDNS") + 1
    assert sources.index("SSDP") < sources.index("NetBIOS")


def test_is_locally_administered():
    assert vendor.is_locally_administered("d2:46:f5:19:e2:1b")
    assert vendor.is_locally_administered("02:00:00:00:00:01")
    assert not vendor.is_locally_administered("00:1a:2b:3c:4d:5e")
    assert not vendor.is_locally_administered("not-a-mac")


def test_get_vendor_skips_locally_administered(monkeypatch):
    def fail_lookup(*args, **kwargs):
        raise AssertionError("OUI lookup should not run for locally administered MACs")

    monkeypatch.setattr(vendor.mac_lookup, "lookup", fail_lookup)

    assert vendor.get_vendor("d2:46:f5:19:e2:1b") == vendor.FALLBACK.VENDOR


def _mdns_response(ip, *answers):
    return IP(src=ip) / UDP(sport=5353, dport=5353) / DNS(qr=1, an=list(answers))


def _ptr(rrname, rdata):
    return DNSRR(rrname=rrname, type="PTR", rdata=rdata)


def test_mdns_instance_name_strips_service():
    answer = _ptr("_airplay._tcp.local", "Living Room TV._airplay._tcp.local")

    assert mdns._mdns_instance_name(answer) == "Living Room TV"


def test_browse_mdns_services_maps_instances_to_ips(monkeypatch):
    responses = [
        _mdns_response(
            "192.168.1.10",
            _ptr("_airplay._tcp.local", "Living Room TV._airplay._tcp.local"),
        ),
        _mdns_response(
            "192.168.1.20",
            _ptr("_printer._tcp.local", "Office Printer._printer._tcp.local"),
        ),
    ]
    monkeypatch.setattr(mdns, "_mdns_query", lambda *a, **k: responses)
    mdns.reset_mdns_service_cache()

    services = mdns.browse_mdns_services()

    assert services["192.168.1.10"] == "Living Room TV"
    assert services["192.168.1.20"] == "Office Printer"


def test_browse_mdns_services_ignores_meta_query(monkeypatch):
    responses = [
        _mdns_response(
            "192.168.1.10",
            _ptr("_services._dns-sd._udp.local", "_http._tcp.local"),
        )
    ]
    monkeypatch.setattr(mdns, "_mdns_query", lambda *a, **k: responses)
    mdns.reset_mdns_service_cache()

    assert mdns.browse_mdns_services() == {}


def test_browse_mdns_services_caches_per_scan(monkeypatch):
    calls = []

    def fake_query(qnames, timeout):
        calls.append(qnames)
        return []

    monkeypatch.setattr(mdns, "_mdns_query", fake_query)
    mdns.reset_mdns_service_cache()

    mdns.browse_mdns_services()
    mdns.browse_mdns_services()

    assert len(calls) == 1


def test_get_mdns_service_name_uses_browse(monkeypatch):
    responses = [
        _mdns_response(
            "192.168.1.10", _ptr("_raop._tcp.local", "Kitchen Speaker._raop._tcp.local")
        )
    ]
    monkeypatch.setattr(mdns, "_mdns_query", lambda *a, **k: responses)
    mdns.reset_mdns_service_cache()

    assert mdns.get_mdns_service_name("192.168.1.10") == "Kitchen Speaker"
    assert mdns.get_mdns_service_name("192.168.1.99") is None


def test_mdns_service_browse_runs_after_ssdp():
    sources = [source for source, _ in NAME_SOURCES]

    assert sources.index("mDNS services") == sources.index("SSDP") + 1
    assert sources.index("mDNS services") < sources.index("NetBIOS")


def _llmnr_response(ip, name):
    return (
        IP(src=ip)
        / UDP(sport=5355, dport=5355)
        / DNS(
            qr=1,
            an=DNSRR(rrname="4.3.2.1.in-addr.arpa", type="PTR", rdata=name),
        )
    )


def test_get_llmnr_name(monkeypatch):
    replies = [_llmnr_response("192.168.1.10", b"desktop.local")]
    monkeypatch.setattr(llmnr, "_llmnr_query", lambda *a, **k: replies)

    assert llmnr.get_llmnr_name("192.168.1.10") == "desktop.local"


def test_get_llmnr_name_ignores_other_responders(monkeypatch):
    replies = [_llmnr_response("192.168.1.99", b"someone-else")]
    monkeypatch.setattr(llmnr, "_llmnr_query", lambda *a, **k: replies)

    assert llmnr.get_llmnr_name("192.168.1.10") is None


def test_llmnr_queries_reverse_name(monkeypatch):
    captured = {}

    def fake_query(qname, timeout):
        captured["qname"] = qname
        return []

    monkeypatch.setattr(llmnr, "_llmnr_query", fake_query)

    llmnr.get_llmnr_name("192.168.1.10")

    assert captured["qname"] == "10.1.168.192.in-addr.arpa"


def test_llmnr_runs_after_netbios():
    sources = [source for source, _ in NAME_SOURCES]

    assert sources.index("LLMNR") == sources.index("NetBIOS") + 1
    assert sources.index("LLMNR") < sources.index("web title")


def _router_dns_response(ip, name):
    return (
        IP(src=ip)
        / UDP(sport=53, dport=53)
        / DNS(
            qr=1,
            an=DNSRR(rrname="10.1.168.192.in-addr.arpa", type="PTR", rdata=name),
        )
    )


def test_get_gateway_ip(monkeypatch):
    monkeypatch.setattr(
        router_dns.conf.route,
        "route",
        lambda target: ("eth0", "192.168.1.50", "192.168.1.1"),
    )

    assert router_dns.get_gateway_ip() == "192.168.1.1"


def test_get_gateway_ip_without_default_route(monkeypatch):
    monkeypatch.setattr(
        router_dns.conf.route,
        "route",
        lambda target: ("eth0", "192.168.1.50", "0.0.0.0"),
    )

    assert router_dns.get_gateway_ip() is None


def test_get_router_dns_name(monkeypatch):
    monkeypatch.setattr(router_dns, "get_gateway_ip", lambda: "192.168.1.1")
    monkeypatch.setattr(
        router_dns,
        "sr1",
        lambda *a, **k: _router_dns_response("192.168.1.1", b"laptop"),
    )

    assert router_dns.get_router_dns_name("192.168.1.10") == "laptop"


def test_get_router_dns_name_without_gateway(monkeypatch):
    monkeypatch.setattr(router_dns, "get_gateway_ip", lambda: None)
    monkeypatch.setattr(
        router_dns,
        "sr1",
        lambda *a, **k: pytest.fail("should not query without gateway"),
    )

    assert router_dns.get_router_dns_name("192.168.1.10") is None


def test_get_router_dns_name_rejects_error_rcode(monkeypatch):
    monkeypatch.setattr(router_dns, "get_gateway_ip", lambda: "192.168.1.1")
    monkeypatch.setattr(
        router_dns,
        "sr1",
        lambda *a, **k: IP(src="192.168.1.1") / UDP() / DNS(qr=1, rcode=3),
    )

    assert router_dns.get_router_dns_name("192.168.1.10") is None


def test_router_dns_runs_after_hostname():
    sources = [source for source, _ in NAME_SOURCES]

    assert sources.index("router DNS") == sources.index("hostname") + 1
    assert sources.index("router DNS") < sources.index("mDNS")


def test_resolve_name_returns_fallback(monkeypatch):
    monkeypatch.setattr(name, "NAME_SOURCES", (("none", lambda ip: None),))

    assert name.resolve_name("192.168.1.10") == FALLBACK.NAME


def test_resolve_name_waits_for_higher_priority(monkeypatch):
    def high(ip):
        time.sleep(0.05)
        return "high-name"

    def low(ip):
        return "low-name"

    monkeypatch.setattr(name, "NAME_SOURCES", (("high", high), ("low", low)))

    assert name.resolve_name("192.168.1.10") == "high-name"


def test_resolve_name_does_not_wait_for_lower_priority(monkeypatch):
    release = threading.Event()

    def low(ip):
        release.wait(5)
        return "low-name"

    monkeypatch.setattr(
        name, "NAME_SOURCES", (("high", lambda ip: "high-name"), ("low", low))
    )

    started = time.monotonic()
    try:
        assert name.resolve_name("192.168.1.10") == "high-name"
        assert time.monotonic() - started < 1.0
    finally:
        release.set()


def test_resolve_name_stops_at_deadline(monkeypatch):
    monkeypatch.setattr(name.NAME, "DEADLINE", 0.1)
    monkeypatch.setattr(
        name, "NAME_SOURCES", (("hang", lambda ip: (time.sleep(0.5), "late")[1]),)
    )

    started = time.monotonic()
    assert name.resolve_name("192.168.1.10") == FALLBACK.NAME
    assert time.monotonic() - started < 0.4


def test_resolve_name_skips_deferred_sources_when_fast_source_wins(monkeypatch):
    calls = []

    def deferred(ip):
        calls.append("web title")
        return "web-name"

    monkeypatch.setattr(
        name,
        "NAME_SOURCES",
        (("fast", lambda ip: "fast-name"), ("web title", deferred)),
    )

    assert name.resolve_name("192.168.1.10") == "fast-name"
    assert calls == []


def test_resolve_name_runs_deferred_sources_when_fast_sources_fail(monkeypatch):
    monkeypatch.setattr(
        name,
        "NAME_SOURCES",
        (("none", lambda ip: None), ("web title", lambda ip: "web-name")),
    )

    assert name.resolve_name("192.168.1.10") == "web-name"


def test_shutdown_name_state_resets_executor(monkeypatch):
    monkeypatch.setattr(name, "NAME_SOURCES", (("only", lambda ip: "name"),))

    name.resolve_name("192.168.1.10")
    first = name._get_executor()

    name.shutdown_name_state()

    assert name._executor is None
    assert name._get_executor() is not first
    name.shutdown_name_state()


def test_prefetch_scan_names_runs_scan_scoped_sources(monkeypatch):
    events = []
    monkeypatch.setattr(name, "browse_mdns_services", lambda: events.append("mdns"))
    monkeypatch.setattr(name, "discover_ssdp", lambda: events.append("ssdp"))
    monkeypatch.setattr(name, "resolve_ssdp_names", lambda: events.append("ssdp-names"))
    monkeypatch.setattr(name, "resolve_passive_names", lambda: events.append("passive"))

    name.prefetch_scan_names()

    assert events == ["mdns", "ssdp", "ssdp-names", "passive"]


def test_discover_ssdp_collects_locations(monkeypatch):
    ssdp.reset_ssdp_cache()
    monkeypatch.setattr(
        ssdp,
        "_ssdp_search",
        lambda timeout: [
            ("192.168.1.5", "http://192.168.1.5/d.xml"),
            ("192.168.1.6", "http://192.168.1.6/d.xml"),
        ],
    )

    try:
        assert ssdp.discover_ssdp() == {
            "192.168.1.5": "http://192.168.1.5/d.xml",
            "192.168.1.6": "http://192.168.1.6/d.xml",
        }
    finally:
        ssdp.reset_ssdp_cache()


def test_resolve_ssdp_names_caches_across_devices(monkeypatch):
    ssdp.reset_ssdp_cache()
    monkeypatch.setattr(
        ssdp,
        "_ssdp_search",
        lambda timeout: [("192.168.1.5", "http://192.168.1.5/d.xml")],
    )
    monkeypatch.setattr(
        ssdp,
        "get_ssdp_description",
        lambda location: {"http://192.168.1.5/d.xml": "Living Room TV"}.get(location),
    )

    try:
        ssdp.discover_ssdp()
        ssdp.resolve_ssdp_names()

        assert ssdp.get_ssdp_name("192.168.1.5") == "Living Room TV"
        assert ssdp.get_ssdp_name("192.168.1.99") is None
    finally:
        ssdp.reset_ssdp_cache()


def test_get_ssdp_name_searches_targeted_without_discovery(monkeypatch):
    ssdp.reset_ssdp_cache()
    monkeypatch.setattr(
        ssdp,
        "_ssdp_search",
        lambda timeout: [("192.168.1.5", "http://192.168.1.5/d.xml")],
    )
    monkeypatch.setattr(ssdp, "get_ssdp_description", lambda location: "TV")

    try:
        assert ssdp.get_ssdp_name("192.168.1.5") == "TV"
        assert ssdp.get_ssdp_name("192.168.1.5") == "TV"
    finally:
        ssdp.reset_ssdp_cache()


def _snmp_reply(ip, varbinds, error=0):
    return (
        IP(src=ip)
        / UDP()
        / SNMP_PACKET(
            community="public",
            PDU=SNMPresponse(error=error, varbindlist=varbinds),
        )
    )


def test_get_snmp_name_prefers_sys_name(monkeypatch):
    reply = _snmp_reply(
        "192.168.1.10",
        [
            SNMPvarbind(oid=SNMP_CONST.SYS_DESCR, value="Cisco IOS"),
            SNMPvarbind(oid=SNMP_CONST.SYS_NAME, value="core-switch"),
        ],
    )
    monkeypatch.setattr(snmp, "sr1", lambda *a, **k: reply)

    assert snmp.get_snmp_name("192.168.1.10") == "core-switch"


def test_get_snmp_name_falls_back_to_sys_descr(monkeypatch):
    reply = _snmp_reply(
        "192.168.1.10",
        [SNMPvarbind(oid=SNMP_CONST.SYS_DESCR, value="Linux NAS 6.1")],
    )
    monkeypatch.setattr(snmp, "sr1", lambda *a, **k: reply)

    assert snmp.get_snmp_name("192.168.1.10") == "Linux NAS 6.1"


def test_get_snmp_name_without_response(monkeypatch):
    monkeypatch.setattr(snmp, "sr1", lambda *a, **k: None)

    assert snmp.get_snmp_name("192.168.1.10") is None


def test_get_snmp_name_ignores_error_status(monkeypatch):
    reply = _snmp_reply(
        "192.168.1.10",
        [SNMPvarbind(oid=SNMP_CONST.SYS_NAME, value="switch")],
        error=2,
    )
    monkeypatch.setattr(snmp, "sr1", lambda *a, **k: reply)

    assert snmp.get_snmp_name("192.168.1.10") is None


def test_get_snmp_name_truncates_long_description(monkeypatch):
    long_descr = "A" * (SNMP_CONST.MAX_NAME_LENGTH + 20)
    reply = _snmp_reply(
        "192.168.1.10",
        [SNMPvarbind(oid=SNMP_CONST.SYS_DESCR, value=long_descr)],
    )
    monkeypatch.setattr(snmp, "sr1", lambda *a, **k: reply)

    assert snmp.get_snmp_name("192.168.1.10") == "A" * SNMP_CONST.MAX_NAME_LENGTH


def test_snmp_runs_after_llmnr_before_tls():
    sources = [source for source, _ in NAME_SOURCES]

    assert sources.index("SNMP") == sources.index("LLMNR") + 1
    assert sources.index("TLS certificate") == sources.index("SNMP") + 1


def test_clean_banner_strips_control_sequences():
    assert banner._clean_banner(b"\xff\xfb\x01SSH-2.0-OpenSSH_9.6\r\n") == (
        "SSH-2.0-OpenSSH_9.6"
    )
    assert banner._clean_banner(b"") is None


def _ntlm_challenge_blob(computer_name):
    encoded = computer_name.encode("utf-16-le")
    av_pairs = (
        BANNER.AV_NB_COMPUTER_NAME.to_bytes(2, "little")
        + len(encoded).to_bytes(2, "little")
        + encoded
        + b"\x00\x00\x00\x00"
    )
    header = (
        BANNER.NTLM_SIGNATURE
        + BANNER.NTLM_CHALLENGE.to_bytes(4, "little")
        + b"\x00" * 8
        + b"\x00" * 4
        + b"\x00" * 8
        + b"\x00" * 8
        + len(av_pairs).to_bytes(2, "little")
        + len(av_pairs).to_bytes(2, "little")
        + (48).to_bytes(4, "little")
    )
    return header + av_pairs


def test_parse_smb_name_extracts_computer_name():
    body = b"\xfeSMB" + b"\x00" * 60 + _ntlm_challenge_blob("OFFICE-PC")

    assert banner.parse_smb_name(body) == "OFFICE-PC"


def test_parse_smb_name_rejects_non_smb():
    assert banner.parse_smb_name(b"HTTP/1.1 200 OK") is None
    assert banner.parse_smb_name(b"") is None


def test_get_service_banner_uses_text_banner(monkeypatch):
    monkeypatch.setattr(
        banner,
        "_text_banner",
        lambda ip, port, timeout: "SSH-2.0-OpenSSH_9.6" if port == 22 else None,
    )
    monkeypatch.setattr(banner, "_smb_banner", lambda *a, **k: None)

    assert banner.get_service_banner("192.168.1.10") == "SSH-2.0-OpenSSH_9.6"


def test_get_service_banner_falls_back_to_smb(monkeypatch):
    monkeypatch.setattr(banner, "_text_banner", lambda *a, **k: None)
    monkeypatch.setattr(banner, "_smb_banner", lambda *a, **k: "OFFICE-PC")

    assert banner.get_service_banner("192.168.1.10") == "OFFICE-PC"


def test_get_service_banner_returns_none(monkeypatch):
    monkeypatch.setattr(banner, "_text_banner", lambda *a, **k: None)
    monkeypatch.setattr(banner, "_smb_banner", lambda *a, **k: None)

    assert banner.get_service_banner("192.168.1.10") is None


def test_service_banner_is_last_source():
    assert NAME_SOURCES[-1][0] == "service banner"
