"""Sanitization for text learned from the wire.

Device names come from mDNS, SSDP, DHCP, LLMNR, TLS certificates, HTTP titles,
SNMP, and service banners, all of which an on-link attacker can control. Control
characters in those strings would otherwise reach the terminal (and the log) as
escape sequences, and zero-width or bidirectional characters could visually
spoof output. Every harvested name passes through :func:`sanitize_name` before
it is used or displayed.
"""

import re

from lantern.constants import ENCODING

# C0/C1 control characters (including ESC), plus zero-width and bidirectional
# formatting characters that can spoof how a name renders in a terminal.
_INVISIBLE = re.compile(
    "[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]+"
)


def sanitize_name(value):
    """Return ``value`` with control/invisible characters and padding removed.

    Bytes are decoded first and non-string values become ``None``. Runs of
    whitespace collapse to a single space, and an empty result is ``None`` so
    callers keep their existing "no name" handling.
    """
    if isinstance(value, bytes):
        value = value.decode(ENCODING, errors="ignore")
    if not isinstance(value, str):
        return None

    value = _INVISIBLE.sub(" ", value)
    value = " ".join(value.split())
    return value or None
