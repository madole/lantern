import pytest

import lantern.metadata as metadata
from lantern import scope
from lantern.resolvers import ssdp

RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"CACHE-CONTROL: max-age=1800\r\n"
    b"ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
    b"USN: uuid:abcd-1234::urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
    b"SERVER: Linux/5.4 UPnP/1.0\r\n"
    b"LOCATION: http://192.168.1.5:9197/dmr\r\n"
    b"\r\n"
)

DESCRIPTION = (
    b"<root><device>"
    b"<deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>"
    b"<UDN>uuid:abcd-1234</UDN>"
    b"<serialNumber>SN-99</serialNumber>"
    b"<modelName>UE55</modelName>"
    b"<manufacturer>Samsung</manufacturer>"
    b"<modelNumber>2020</modelNumber>"
    b"</device></root>"
)


@pytest.fixture(autouse=True)
def clean_scan():
    ssdp.reset_ssdp_cache()
    metadata.reset_metadata()
    yield
    ssdp.reset_ssdp_cache()
    metadata.reset_metadata()
    scope.clear_scan_network()


def test_parse_ssdp_headers_lowercases_and_maps():
    headers = ssdp.parse_ssdp_headers(RESPONSE)
    assert headers["st"] == "urn:schemas-upnp-org:device:MediaRenderer:1"
    assert (
        headers["usn"] == "uuid:abcd-1234::urn:schemas-upnp-org:device:MediaRenderer:1"
    )
    assert headers["server"] == "Linux/5.4 UPnP/1.0"
    assert headers["location"] == "http://192.168.1.5:9197/dmr"
    assert headers["cache-control"] == "max-age=1800"


def test_parse_ssdp_headers_tolerates_noise():
    assert ssdp.parse_ssdp_headers(b"HTTP/1.1 200 OK\r\n\r\n") == {}
    assert ssdp.parse_ssdp_headers(b"not headers\xff\x00") == {}


def test_parse_ssdp_location_still_returns_location():
    assert ssdp.parse_ssdp_location(RESPONSE) == "http://192.168.1.5:9197/dmr"
    assert ssdp.parse_ssdp_location(b"HTTP/1.1 200 OK\r\n\r\n") is None


def test_parse_ssdp_metadata_extracts_fields():
    assert ssdp.parse_ssdp_metadata(DESCRIPTION) == {
        "devicetype": "urn:schemas-upnp-org:device:MediaRenderer:1",
        "udn": "uuid:abcd-1234",
        "serialnumber": "SN-99",
        "modelname": "UE55",
        "manufacturer": "Samsung",
        "modelnumber": "2020",
    }


def test_parse_ssdp_metadata_rejects_malformed_xml():
    assert ssdp.parse_ssdp_metadata(b"not xml") == {}
    assert ssdp.parse_ssdp_metadata(b"<root><a></root>") == {}


def test_record_ssdp_description_metadata():
    location = "http://192.168.1.5:9197/dmr"
    ssdp._locations["192.168.1.5"] = location
    ssdp._description_metadata[location] = ssdp.parse_ssdp_metadata(DESCRIPTION)

    ssdp.record_ssdp_description_metadata()

    records = metadata.get_metadata_records("192.168.1.5")
    assert records["device_type"] == {"value": "MediaRenderer", "source": "SSDP"}
    assert records["uuid"] == {"value": "abcd-1234", "source": "SSDP"}
    assert records["serial"] == {"value": "SN-99", "source": "SSDP"}
    assert records["model"] == {"value": "UE55", "source": "SSDP"}
    assert records["manufacturer"] == {"value": "Samsung", "source": "SSDP"}
    assert records["model_number"] == {"value": "2020", "source": "SSDP"}


def test_record_ssdp_description_metadata_skips_out_of_scope():
    location = "http://10.9.9.9/dmr"
    ssdp._locations["10.9.9.9"] = location
    ssdp._description_metadata[location] = ssdp.parse_ssdp_metadata(DESCRIPTION)
    scope.set_scan_network("192.168.1.0/24")

    ssdp.record_ssdp_description_metadata()

    assert metadata.get_metadata("10.9.9.9") == {}


def test_record_response_headers():
    ssdp._record_response_metadata("192.168.1.5", ssdp.parse_ssdp_headers(RESPONSE))

    facts = metadata.get_metadata("192.168.1.5")
    assert facts["server"] == "Linux/5.4 UPnP/1.0"
    assert facts["device_type"] == "MediaRenderer"
    assert facts["uuid"] == "abcd-1234"


def test_record_response_headers_skips_out_of_scope():
    scope.set_scan_network("192.168.1.0/24")

    ssdp._record_response_metadata("10.9.9.9", ssdp.parse_ssdp_headers(RESPONSE))

    assert metadata.get_metadata("10.9.9.9") == {}


def test_reset_ssdp_cache_clears_description_metadata():
    ssdp._description_metadata["http://192.168.1.5/dmr"] = {"udn": "uuid:x"}

    ssdp.reset_ssdp_cache()

    assert ssdp._description_metadata == {}
