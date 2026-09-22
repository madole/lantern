import lantern.main as main


def test_scan_overlaps_broadcast_prefetch_with_passive_window(monkeypatch):
    events = []

    class FakeSniffer:
        pass

    def fake_srp(*_args, **_kwargs):
        events.append("arp")
        return [], []

    monkeypatch.setattr(
        main,
        "start_passive_scan",
        lambda: events.append("passive-start") or FakeSniffer(),
    )
    monkeypatch.setattr(
        main, "finish_passive_scan", lambda _sniffer: events.append("passive-finish")
    )
    monkeypatch.setattr(
        main,
        "start_prefetch_broadcast",
        lambda: events.append("prefetch-start") or object(),
    )
    monkeypatch.setattr(
        main,
        "finish_prefetch_broadcast",
        lambda _thread: events.append("prefetch-finish"),
    )
    monkeypatch.setattr(
        main, "resolve_passive_names", lambda: events.append("passive-names")
    )
    monkeypatch.setattr(main, "get_passive_macs", lambda: {})
    monkeypatch.setattr(main, "srp", fake_srp)

    main.scan_network("192.168.1.0/24")

    # The broadcast prefetch starts before the ARP probe and is only joined
    # after the passive listener has stopped, so its multicasts overlap the
    # listening window rather than following it.
    assert events == [
        "passive-start",
        "prefetch-start",
        "arp",
        "passive-finish",
        "prefetch-finish",
        "passive-names",
    ]
