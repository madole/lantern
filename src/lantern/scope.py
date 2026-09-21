"""LAN-scope and read-only guardrails for device probes.

``lantern`` only ever probes addresses inside the subnet it was asked to scan,
and it only ever reads. This module is the single place both policies are
expressed:

- :func:`set_scan_network` registers the subnet for a scan; resolvers call
  :func:`is_in_scope` (or :func:`require_in_scope`) before sending. Outside a
  configured scan every address is treated as in scope, so direct library use
  keeps working while :func:`lantern.main.scan_network` stays confined to its
  own subnet.
- :func:`require_read_only` rejects any operation that is not a known read-only
  probe, so a future code path cannot quietly introduce an SNMP ``set``, a UPnP
  action, or a credential attempt.
"""

import ipaddress
import threading

# The whole tool is read-only. Keep this True; the tests assert it.
READ_ONLY = True

# The only kinds of probe allowed on the wire.
READ_ONLY_OPERATIONS = frozenset(
    {
        "snmp get",
        "ssdp search",
        "http get",
        "tls handshake",
        "service banner",
        "name query",
    }
)

_lock = threading.Lock()
_network = None


class OutOfScopeError(ValueError):
    """A probe targeted an address outside the subnet being scanned."""


class ReadOnlyViolation(RuntimeError):
    """A probe attempted an operation that is not read-only."""


def set_scan_network(network):
    """Register the subnet being scanned.

    Accepts an ``ipaddress`` network or anything :func:`ipaddress.ip_network`
    understands (e.g. ``"192.168.1.0/24"``).
    """
    global _network
    if not isinstance(network, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        network = ipaddress.ip_network(network, strict=False)
    with _lock:
        _network = network


def clear_scan_network():
    """Forget the registered subnet, re-allowing every address."""
    global _network
    with _lock:
        _network = None


def get_scan_network():
    """Return the registered subnet, or ``None`` when no scan is configured."""
    with _lock:
        return _network


def is_in_scope(ip_address):
    """Whether ``ip_address`` may be probed.

    With no subnet registered (direct resolver calls, unit tests) every address
    is in scope, so the guardrail only narrows behavior during a scan.
    """
    network = get_scan_network()
    if network is None:
        return True
    try:
        address = ipaddress.ip_address(ip_address)
    except ValueError:
        return False
    return address in network


def require_in_scope(ip_address):
    """Return ``ip_address`` when in scope, else raise :class:`OutOfScopeError`."""
    if not is_in_scope(ip_address):
        raise OutOfScopeError(f"{ip_address} is outside the scanned subnet")
    return ip_address


def require_read_only(operation):
    """Assert that ``operation`` is a known read-only probe.

    This is the read-only policy in executable form: anything that would mutate
    a device is rejected before it can reach the wire.
    """
    if not READ_ONLY or operation not in READ_ONLY_OPERATIONS:
        raise ReadOnlyViolation(f"refusing non-read-only operation: {operation!r}")
