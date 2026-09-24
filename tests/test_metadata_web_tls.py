import pytest

from lantern.metadata import SERVER, get_metadata_records, reset_metadata
from lantern.resolvers import tls, web


class FakeResponse:
    def __init__(self, body, headers=None):
        self.body = body
        self.headers = headers or {}

    def read(self, amount=-1):
        return self.body

    def close(self):
        pass


@pytest.fixture(autouse=True)
def clean_metadata():
    reset_metadata()
    yield
    reset_metadata()


def test_web_title_records_server_header(monkeypatch):
    body = b"<html><head><title>Living Room TV</title></head></html>"
    response = FakeResponse(body, {"Server": "Boa/0.94.14rc1"})
    monkeypatch.setattr(web.urllib.request, "urlopen", lambda *a, **k: response)

    assert web.get_web_title("192.168.1.10") == "Living Room TV"
    records = get_metadata_records("192.168.1.10")
    assert records[SERVER] == {"value": "Boa/0.94.14rc1", "source": "web"}


def test_web_title_records_realm(monkeypatch):
    body = b"<html><head><title>Router Login</title></head></html>"
    response = FakeResponse(
        body,
        {"Server": "lighttpd/1.4", "WWW-Authenticate": 'Basic realm="Router UI"'},
    )
    monkeypatch.setattr(web.urllib.request, "urlopen", lambda *a, **k: response)

    assert web.get_web_title("192.168.1.10") == "Router Login"
    records = get_metadata_records("192.168.1.10")
    assert records["realm"] == {"value": "Router UI", "source": "web"}


def test_web_title_first_server_header_wins(monkeypatch):
    bodies = (
        (b"<html><head><title>404</title></head></html>", {"Server": "nginx/1.1"}),
        (b"<html><head><title>Setup</title></head></html>", {"Server": "Goahead/2.0"}),
    )
    responses = [FakeResponse(body, headers) for body, headers in bodies]

    def fake_urlopen(request, *a, **k):
        return responses.pop(0)

    monkeypatch.setattr(web.urllib.request, "urlopen", fake_urlopen)

    # The title chain still falls through the generic page to the next port...
    assert web.get_web_title("192.168.1.10") == "Setup"
    # ...but only the first Server header seen is kept (first value wins).
    assert get_metadata_records("192.168.1.10")[SERVER]["value"] == "nginx/1.1"


def test_web_title_without_headers_records_nothing(monkeypatch):
    body = b"<html><head><title>Living Room TV</title></head></html>"
    monkeypatch.setattr(
        web.urllib.request, "urlopen", lambda *a, **k: FakeResponse(body)
    )

    assert web.get_web_title("192.168.1.10") == "Living Room TV"
    assert get_metadata_records("192.168.1.10") == {}


def test_web_unnamed_server_records_appliance_hint(monkeypatch):
    body = b"<html><head><title>404 - Page not found</title></head></html>"
    monkeypatch.setattr(
        web.urllib.request, "urlopen", lambda *a, **k: FakeResponse(body)
    )

    assert web.get_web_title("192.168.1.10") is None
    records = get_metadata_records("192.168.1.10")
    assert records["appliance"] == {"value": "embedded http server", "source": "web"}


def test_web_server_header_suppresses_appliance_hint(monkeypatch):
    body = b"<html><head><title>404</title></head></html>"
    response = FakeResponse(body, {"Server": "nginx/1.24"})
    monkeypatch.setattr(web.urllib.request, "urlopen", lambda *a, **k: response)

    assert web.get_web_title("192.168.1.10") is None
    assert "appliance" not in get_metadata_records("192.168.1.10")


def test_web_title_suppresses_appliance_hint(monkeypatch):
    body = b"<html><head><title>Living Room TV</title></head></html>"
    monkeypatch.setattr(
        web.urllib.request, "urlopen", lambda *a, **k: FakeResponse(body)
    )

    assert web.get_web_title("192.168.1.10") == "Living Room TV"
    assert "appliance" not in get_metadata_records("192.168.1.10")


def test_tls_name_records_issuer_and_validity(monkeypatch):
    monkeypatch.setattr(
        tls,
        "_fetch_certificate",
        lambda *a, **k: {
            "subjectAltName": (("DNS", "kitchen-speaker"),),
            "issuer": (
                (("organizationName", "Acme Corp"),),
                (("commonName", "Acme Device CA"),),
            ),
            "notAfter": "Jun 1 12:00:00 2027 GMT",
            "notBefore": "Jun 1 12:00:00 2017 GMT",
        },
    )

    assert tls.get_tls_name("192.168.1.10") == "kitchen-speaker"
    records = get_metadata_records("192.168.1.10")
    assert records["tls_issuer"]["value"] == "Acme Device CA"
    assert records["tls_issuer"]["source"] == "TLS"
    assert records["tls_valid_to"]["value"] == "Jun 1 12:00:00 2027 GMT"
    assert records["tls_valid_from"]["value"] == "Jun 1 12:00:00 2017 GMT"


def test_tls_issuer_falls_back_to_organization(monkeypatch):
    monkeypatch.setattr(
        tls,
        "_fetch_certificate",
        lambda *a, **k: {
            "subject": ((("commonName", "nas"),),),
            "issuer": ((("organizationName", "Acme Corp"),),),
            "notAfter": "Jun 1 12:00:00 2027 GMT",
        },
    )

    assert tls.get_tls_name("192.168.1.10") == "nas"
    records = get_metadata_records("192.168.1.10")
    assert records["tls_issuer"]["value"] == "Acme Corp"


def test_tls_certificate_without_issuer_fields_records_nothing(monkeypatch):
    monkeypatch.setattr(
        tls,
        "_fetch_certificate",
        lambda *a, **k: {"subject": ((("commonName", "nas"),),)},
    )

    assert tls.get_tls_name("192.168.1.10") == "nas"
    # No issuer and no notAfter fields: nothing should be recorded.
    assert get_metadata_records("192.168.1.10") == {}


def test_tls_without_certificate_records_nothing(monkeypatch):
    monkeypatch.setattr(tls, "_fetch_certificate", lambda *a, **k: None)

    assert tls.get_tls_name("192.168.1.10") is None
    assert get_metadata_records("192.168.1.10") == {}
