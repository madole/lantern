import lantern.metadata as metadata
from lantern.main import _format_metadata


def setup_function():
    metadata.reset_metadata()


def test_record_and_get_roundtrip():
    metadata.record("192.168.1.5", metadata.MODEL, "UE55", source="SSDP")
    metadata.record("192.168.1.5", metadata.OS, "Tizen", source="SNMP")
    assert metadata.get_metadata("192.168.1.5") == {"model": "UE55", "os": "Tizen"}
    assert metadata.get_metadata("192.168.1.6") == {}


def test_first_value_for_a_key_wins():
    metadata.record("192.168.1.5", metadata.MODEL, "UE55", source="SSDP")
    metadata.record("192.168.1.5", metadata.MODEL, "Other", source="SNMP")
    assert metadata.get_metadata("192.168.1.5") == {"model": "UE55"}


def test_values_are_sanitized_and_blanks_dropped():
    metadata.record("192.168.1.5", metadata.MODEL, "  TV\x1b  ", source="SSDP")
    metadata.record("192.168.1.5", metadata.OS, "   ", source="SNMP")
    assert metadata.get_metadata("192.168.1.5") == {"model": "TV"}


def test_records_keep_source():
    metadata.record("192.168.1.5", metadata.MODEL, "UE55", source="SSDP")
    records = metadata.get_metadata_records("192.168.1.5")
    assert records["model"] == {"value": "UE55", "source": "SSDP"}


def test_reset_clears():
    metadata.record("192.168.1.5", metadata.MODEL, "UE55", source="SSDP")
    metadata.reset_metadata()
    assert metadata.get_metadata("192.168.1.5") == {}


def test_format_metadata_orders_keys():
    facts = {"os": "Linux", "model": "UE55", "device_type": "MediaRenderer"}
    assert _format_metadata(facts) == "device_type=MediaRenderer, model=UE55, os=Linux"
    assert _format_metadata({}) == ""


def test_format_metadata_truncates():
    rendered = _format_metadata({"model": "x" * 200})
    assert len(rendered) <= 80
    assert rendered.endswith("...")
