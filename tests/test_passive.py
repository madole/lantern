from scapy.all import ARP, BOOTP, DHCP, DNS, DNSRR, IP, UDP, Raw

import network_lister.passive as passive
import network_lister.resolvers as resolvers


def _dhcp(ip, hostname):
    return (
        IP(src="192.168.1.1", dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(yiaddr=ip)
        / DHCP(options=[("hostname", hostname)])
    )


def _mdns(ip, *answers):
    return IP(src=ip) / UDP(sport=5353, dport=5353) / DNS(qr=1, an=list(answers))


def test_parse_arp():
    pkt = ARP(psrc="192.168.1.5", hwsrc="aa:bb:cc:dd:ee:ff")

    assert passive.parse_arp(pkt) == ("192.168.1.5", "aa:bb:cc:dd:ee:ff")


def test_parse_arp_ignores_probes():
    assert passive.parse_arp(ARP(psrc="0.0.0.0", hwsrc="00:00:00:00:00:00")) is None


def test_parse_dhcp_hostname():
    pkt = _dhcp("192.168.1.5", b"laptop")

    assert passive.parse_dhcp(pkt) == ("192.168.1.5", ["laptop"])


def test_parse_dhcp_without_hostname():
    pkt = IP() / UDP(sport=67, dport=68) / BOOTP(yiaddr="192.168.1.5") / DHCP()

    assert passive.parse_dhcp(pkt) is None


def test_parse_llmnr_response():
    pkt = (
        IP(src="192.168.1.9")
        / UDP(sport=5355, dport=5355)
        / DNS(qr=1, an=DNSRR(rrname="desktop", type="A", rdata="192.168.1.9"))
    )

    assert passive.parse_llmnr(pkt) == ("192.168.1.9", ["desktop"])


def test_parse_llmnr_ignores_queries():
    pkt = IP(src="192.168.1.9") / UDP(sport=5355, dport=5355) / DNS(qr=0, qd=[], an=[])

    assert passive.parse_llmnr(pkt) is None


def test_parse_mdns_prefers_instance_then_hostname():
    pkt = _mdns(
        "192.168.1.9",
        DNSRR(rrname="host.local", type="A", rdata="192.168.1.9"),
        DNSRR(
            rrname="_airplay._tcp.local",
            type="PTR",
            rdata="Living Room._airplay._tcp.local",
        ),
    )

    assert passive.parse_mdns(pkt) == ("192.168.1.9", ["Living Room", "host"])


def test_parse_mdns_ignores_other_dns_ports():
    pkt = (
        IP(src="192.168.1.9")
        / UDP(sport=5355, dport=5355)
        / DNS(qr=1, an=DNSRR(rrname="desktop", type="A", rdata="192.168.1.9"))
    )

    assert passive.parse_mdns(pkt) is None


def test_parse_ssdp_location():
    payload = (
        b"NOTIFY * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b"LOCATION: http://192.168.1.5:80/desc.xml\r\n\r\n"
    )
    pkt = IP(src="192.168.1.5") / UDP(sport=1900, dport=1900) / Raw(load=payload)

    assert passive.parse_ssdp(pkt) == ("192.168.1.5", "http://192.168.1.5:80/desc.xml")


def test_handle_harvests_dhcp_name():
    passive.reset_passive_cache()

    passive._handle(_dhcp("192.168.1.5", b"laptop"))

    assert passive.get_passive_name("192.168.1.5") == "laptop"


def test_handle_keeps_first_name():
    passive.reset_passive_cache()

    passive._handle(_dhcp("192.168.1.5", b"laptop"))
    passive._handle(_dhcp("192.168.1.5", b"other"))

    assert passive.get_passive_name("192.168.1.5") == "laptop"


def test_handle_harvests_macs():
    passive.reset_passive_cache()

    passive._handle(ARP(psrc="192.168.1.7", hwsrc="aa:bb:cc:dd:ee:01"))

    assert passive.get_passive_macs() == {"192.168.1.7": "aa:bb:cc:dd:ee:01"}


def test_get_passive_name_fetches_ssdp_once(monkeypatch):
    passive.reset_passive_cache()
    payload = b"NOTIFY * HTTP/1.1\r\nLOCATION: http://192.168.1.5/d.xml\r\n\r\n"
    passive._handle(IP(src="192.168.1.5") / UDP(sport=1900, dport=1900) / Raw(payload))

    calls = []
    monkeypatch.setattr(
        resolvers,
        "get_ssdp_description",
        lambda location: calls.append(location) or "Living Room TV",
    )

    assert passive.get_passive_name("192.168.1.5") == "Living Room TV"
    assert passive.get_passive_name("192.168.1.5") == "Living Room TV"
    assert calls == ["http://192.168.1.5/d.xml"]


def test_passive_scan_spins_until_finished(monkeypatch):
    passive.reset_passive_cache()
    events = []

    class FakeSpinner:
        def start(self):
            events.append("start")

        def stop(self):
            events.append("stop")

    class FakeSniffer:
        def start(self):
            events.append("sniff")

        def join(self):
            events.append("join")

    monkeypatch.setattr(passive, "yaspin", lambda **kwargs: FakeSpinner())
    monkeypatch.setattr(passive, "AsyncSniffer", lambda **kwargs: FakeSniffer())

    sniffer = passive.start_passive_scan(timeout=5)

    assert events == ["start", "sniff"]

    passive.finish_passive_scan(sniffer)

    assert events == ["start", "sniff", "join", "stop"]


def test_passive_scan_stops_spinner_without_sniffer():
    passive.reset_passive_cache()
    events = []

    class FakeSpinner:
        def start(self):
            events.append("start")

        def stop(self):
            events.append("stop")

    passive._spinner = FakeSpinner()
    passive._spinner.start()

    passive.finish_passive_scan(None)

    assert events == ["start", "stop"]


def test_passive_runs_first_in_name_chain():
    sources = [source for source, _ in resolvers.NAME_SOURCES]

    assert sources[0] == "passive"
    assert sources.index("passive") < sources.index("hostname")
