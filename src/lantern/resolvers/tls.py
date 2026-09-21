import ipaddress
import socket
import ssl
import tempfile

from network_lister.constants import TLS
from network_lister.logger import logger


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
    if not name:
        return None

    name = name.strip()
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
    # Devices routinely present self-signed or mismatched certificates; we only
    # want the certificate contents, so skip chain and hostname verification.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

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
        for name in certificate_names(certificate):
            cleaned = clean_cert_name(name, ip_address)
            if cleaned:
                logger.debug("TLS resolved {} as {!r}", ip_address, cleaned)
                return cleaned

    logger.debug("No TLS certificate name for {}", ip_address)
    return None
