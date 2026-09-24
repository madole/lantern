import threading
import time

import lantern.metadata as metadata
from lantern.constants import FALLBACK
from lantern.resolvers import name


def setup_function():
    metadata.reset_metadata()
    name.shutdown_name_state()


def teardown_function():
    name.shutdown_name_state()


def test_resolve_name_records_winning_source(monkeypatch):
    monkeypatch.setattr(name, "NAME_SOURCES", (("mDNS", lambda ip: "tv"),))

    assert name.resolve_name("192.168.1.10") == "tv"
    assert metadata.get_metadata("192.168.1.10")["name_source"] == "mDNS"


def test_resolve_name_records_responded_sources(monkeypatch):
    def high(ip):
        return "high"

    def low(ip):
        return "low"

    monkeypatch.setattr(name, "NAME_SOURCES", (("high", high), ("low", low)))

    assert name.resolve_name("192.168.1.10") == "high"

    facts = metadata.get_metadata("192.168.1.10")
    assert "high" in facts["responded"]
    assert facts["name_source"] == "high"


def test_resolve_name_records_nothing_when_all_fail(monkeypatch):
    monkeypatch.setattr(name, "NAME_SOURCES", (("none", lambda ip: None),))

    assert name.resolve_name("192.168.1.10") == FALLBACK.NAME
    assert "name_source" not in metadata.get_metadata("192.168.1.10")


def test_full_matrix_waits_for_lower_priority_sources(monkeypatch):
    monkeypatch.setattr(name.NAME, "FULL_MATRIX", True)

    def high(ip):
        return "high"

    def low(ip):
        time.sleep(0.05)
        return "low"

    monkeypatch.setattr(name, "NAME_SOURCES", (("high", high), ("low", low)))

    assert name.resolve_name("192.168.1.10") == "high"

    responded = metadata.get_metadata("192.168.1.10")["responded"]
    assert "high" in responded
    assert "low" in responded


def test_full_matrix_still_prefers_higher_priority(monkeypatch):
    monkeypatch.setattr(name.NAME, "FULL_MATRIX", True)

    def high(ip):
        time.sleep(0.05)
        return "high"

    monkeypatch.setattr(
        name, "NAME_SOURCES", (("high", high), ("low", lambda ip: "low"))
    )

    assert name.resolve_name("192.168.1.10") == "high"


def test_default_mode_exits_before_lower_priority_finishes(monkeypatch):
    monkeypatch.setattr(name.NAME, "FULL_MATRIX", False)
    release = threading.Event()

    def low(ip):
        release.wait(5)
        return "low"

    monkeypatch.setattr(
        name, "NAME_SOURCES", (("high", lambda ip: "high"), ("low", low))
    )

    started = time.monotonic()
    try:
        assert name.resolve_name("192.168.1.10") == "high"
        assert time.monotonic() - started < 1.0
    finally:
        release.set()
