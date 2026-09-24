import ipaddress
import socket
import ssl
import tempfile

from lantern.constants import TLS
from lantern.logger import logger
from lantern.metadata import record
from lantern.sanitize import sanitize_name

# Certificate fields recorded alongside the name: who signed it and when it
# expires. Keys are metadata keys (first value per key wins per scan).
_ORGANIZATION_NAME = "organizationName"
_NOT_AFTER = "notAfter"
_NOT_BEFORE = "notBefore"
_TLS_ISSUER_KEY = "tls_issuer"
_TLS_VALID_TO_KEY = "tls_valid_to"
_TLS_VALID_FROM_KEY = "tls_valid_from"
_TLS_SOURCE = "TLS"


def _issuer_value(certificate, field):
    """The named field from the certificate's issuer DN, or None."""
    try:
        for rdn in certificate.get("issuer", ()):
            for key, value in rdn:
                if key == field and value:
                    return value
    except Exception:
        pass
    return None


def _record_certificate_metadata(certificate, ip_address):
    """Remember the certificate's issuer and validity window, if decodable."""
    if not certificate:
        return

    issuer = _issuer_value(certificate, TLS.COMMON_NAME) or _issuer_value(
        certificate, _ORGANIZATION_NAME
    )
    record(ip_address, _TLS_ISSUER_KEY, issuer, _TLS_SOURCE)
    record(ip_address, _TLS_VALID_TO_KEY, certificate.get(_NOT_AFTER), _TLS_SOURCE)
    record(ip_address, _TLS_VALID_FROM_KEY, certificate.get(_NOT_BEFORE), _TLS_SOURCE)


def _decode_certificate(der_certificate):
    """Decode a DER certificate into the dict shape ssl.getpeercert returns."""
    if not der_certificate:
        return None

    pem = ssl.DER_cert_to_PEM_cert(der_certificate)
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem") as handle:
            handle.write(pem)
            handle.flush()
            # Stdlib has no public PEM/DER parser; this is the same decoder
            # ssl uses internally for a validated peer certificate.
            return ssl._ssl._test_decode_cert(handle.name)
    except Exception as error:
        logger.trace("Could not decode TLS certificate: {}", error)
        return None


def certificate_names(certificate):
    """Ordered name candidates from a decoded cert: DNS SANs, then the CN."""
    if not certificate:
        return []

    names = []
    for kind, value in certificate.get("subjectAltName", ()):
        if kind in TLS.SAN_KINDS and value:
            names.append(value)

    for rdn in certificate.get("subject", ()):
        for key, value in rdn:
            if key == TLS.COMMON_NAME and value:
                names.append(value)

    return names


def clean_cert_name(name, ip_address):
    """Reject certificate values that are not usable device names."""
    name = sanitize_name(name)
    if not name or name == ip_address or name.startswith("*"):
        return None

    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name

    return None


def _fetch_certificate(ip_address, port, timeout):
    """Open a TLS connection and return the peer's decoded certificate."""
    context = ssl.create_default_context()
    # Devices are addressed by IP and rarely carry an IP SAN, so hostname
    # verification is always off. Chain verification is off by default because
    # device certificates are usually self-signed; set LANTERN_TLS_VERIFY=1 to
    # require a trusted chain instead of reading whatever is presented.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED if TLS.VERIFY else ssl.CERT_NONE

    try:
        with socket.create_connection((ip_address, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip_address) as connection:
                der_certificate = connection.getpeercert(binary_form=True)
    except Exception as error:
        logger.trace("TLS handshake with {}:{} failed: {}", ip_address, port, error)
        return None

    return _decode_certificate(der_certificate)


def get_tls_name(ip_address, timeout=TLS.TIMEOUT):
    """Read a hostname from the CN/SAN of the device's TLS certificate."""
    logger.debug("Reading TLS certificate for IP: {}", ip_address)
    for port in TLS.PORTS:
        certificate = _fetch_certificate(ip_address, port, timeout)
        _record_certificate_metadata(certificate, ip_address)
        for name in certificate_names(certificate):
            cleaned = clean_cert_name(name, ip_address)
            if cleaned:
                logger.debug("TLS resolved {} as {!r}", ip_address, cleaned)
                return cleaned

    logger.debug("No TLS certificate name for {}", ip_address)
    return None
