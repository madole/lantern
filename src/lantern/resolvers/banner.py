import concurrent.futures
import re
import socket

from scapy.layers.smb2 import (
    NBTSession,
    SMB2_Header,
    SMB2_Negotiate_Protocol_Request,
)

from lantern.constants import BANNER, ENCODING
from lantern.logger import logger

# Strip telnet control sequences and other non-printable noise from a banner.
_NON_PRINTABLE = re.compile(r"[^\x20-\x7e]+")


def _clean_banner(raw):
    """Turn raw banner bytes into a single trimmed, printable line."""
    if not raw:
        return None
    text = raw.decode(ENCODING, errors="ignore")
    text = _NON_PRINTABLE.sub(" ", text)
    text = " ".join(text.split())
    return text or None


def _read_line(sock, max_bytes):
    """Read from a socket until the first newline or a size bound."""
    data = b""
    while len(data) < max_bytes:
        chunk = sock.recv(min(256, max_bytes - len(data)))
        if not chunk:
            break
        data += chunk
        if b"\n" in data:
            break
    return data


def _text_banner(ip_address, port, timeout):
    """Read the greeting line of a text protocol (SSH, FTP, SMTP, ...)."""
    try:
        with socket.create_connection((ip_address, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            raw = _read_line(sock, BANNER.MAX_BYTES)
    except OSError as error:
        logger.trace("Banner read from {}:{} failed: {}", ip_address, port, error)
        return None
    return _clean_banner(raw)


def _recv_exact(sock, length):
    """Read exactly ``length`` bytes from a socket (best effort)."""
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _smb_request():
    """Build an SMB2 NEGOTIATE request framed with a NetBIOS session header."""
    negotiate = SMB2_Header(Command=0) / SMB2_Negotiate_Protocol_Request(
        Dialects=list(BANNER.SMB_DIALECTS)
    )
    payload = bytes(negotiate)
    return bytes(NBTSession(TYPE=0, LENGTH=len(payload)) / payload)


def _smb_negotiate(ip_address, port, timeout):
    """Send an SMB2 NEGOTIATE and return the response body, or None."""
    try:
        with socket.create_connection((ip_address, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(_smb_request())
            header = _recv_exact(sock, 4)
            if len(header) < 4 or header[0] != 0x00:
                return None
            length = int.from_bytes(header[1:4], "big")
            if length <= 0:
                return None
            return _recv_exact(sock, length)
    except OSError as error:
        logger.trace("SMB negotiate with {}:{} failed: {}", ip_address, port, error)
        return None


def _parse_av_pairs(data):
    """Parse NTLM target-info AV pairs into ``{id: value}``."""
    pairs = {}
    offset = 0
    while offset + 4 <= len(data):
        av_id = int.from_bytes(data[offset : offset + 2], "little")
        av_length = int.from_bytes(data[offset + 2 : offset + 4], "little")
        offset += 4
        if av_id == 0:
            break
        pairs.setdefault(av_id, data[offset : offset + av_length])
        offset += av_length
    return pairs


def _ntlm_computer_name(blob):
    """Extract the server computer name from an NTLMSSP Type 2 challenge."""
    start = blob.find(BANNER.NTLM_SIGNATURE)
    if start < 0:
        return None

    challenge = blob[start:]
    if len(challenge) < 48:
        return None
    if int.from_bytes(challenge[8:12], "little") != BANNER.NTLM_CHALLENGE:
        return None

    info_length = int.from_bytes(challenge[40:42], "little")
    info_offset = int.from_bytes(challenge[44:48], "little")
    pairs = _parse_av_pairs(challenge[info_offset : info_offset + info_length])

    for av_id in (BANNER.AV_NB_COMPUTER_NAME, BANNER.AV_DNS_COMPUTER_NAME):
        raw = pairs.get(av_id)
        if raw:
            name = raw.decode("utf-16-le", errors="ignore").strip().strip(".")
            if name:
                return name
    return None


def parse_smb_name(body):
    """Pull a computer name out of an SMB2 NEGOTIATE response."""
    if not body or body[:4] != b"\xfeSMB":
        return None
    return _ntlm_computer_name(body)


def _smb_banner(ip_address, port, timeout):
    name = parse_smb_name(_smb_negotiate(ip_address, port, timeout))
    if name:
        logger.debug("SMB resolved {} as {!r}", ip_address, name)
    return name


def get_service_banner(ip_address, timeout=BANNER.TIMEOUT):
    """Probe text services and SMB concurrently for a last-resort name.

    Ports are probed together so a single dead port cannot spend the whole
    budget; the first service that answers with something usable wins.
    """
    logger.debug("Reading service banners for IP: {}", ip_address)
    probes = [(port, _text_banner) for port in BANNER.TEXT_PORTS]
    probes.append((BANNER.SMB_PORT, _smb_banner))

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(probes), thread_name_prefix="banner"
    ) as executor:
        futures = {
            executor.submit(probe, ip_address, port, timeout): port
            for port, probe in probes
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                banner = future.result()
            except Exception as error:
                logger.trace("Banner probe for {} raised: {}", ip_address, error)
                continue
            if banner:
                logger.debug("Service banner resolved {} as {!r}", ip_address, banner)
                return banner

    logger.debug("No service banner for {}", ip_address)
    return None
