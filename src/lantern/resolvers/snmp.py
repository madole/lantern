from scapy.all import IP, UDP, sr1
from scapy.layers.snmp import SNMP as SNMP_PACKET
from scapy.layers.snmp import SNMPget, SNMPvarbind

from lantern.constants import ENCODING, SNMP
from lantern.logger import logger


def _build_query(ip_address, oids):
    """Build an SNMP v2c GET for the given OIDs using the read-only community."""
    return (
        IP(dst=ip_address)
        / UDP(sport=SNMP.PORT, dport=SNMP.PORT)
        / SNMP_PACKET(
            community=SNMP.COMMUNITY,
            PDU=SNMPget(varbindlist=[SNMPvarbind(oid=oid) for oid in oids]),
        )
    )


def _varbind_text(varbind):
    """Decode a varbind's value to text, or None when it carries no string."""
    value = getattr(varbind, "value", None)
    raw = getattr(value, "val", None)
    if raw is None and isinstance(value, str):
        raw = value
    if isinstance(raw, bytes):
        text = raw.decode(ENCODING, errors="ignore").strip()
    elif isinstance(raw, str):
        text = raw.strip()
    else:
        return None
    return text or None


def _varbind_oid(varbind):
    oid = getattr(varbind.oid, "val", None)
    if oid:
        return oid
    return varbind.oid if isinstance(varbind.oid, str) else None


def _varbind_values(reply):
    """Map requested OID -> decoded value from a GET response."""
    values = {}
    for varbind in reply.PDU.varbindlist:
        oid = _varbind_oid(varbind)
        if oid:
            values[oid] = _varbind_text(varbind)
    return values


def get_snmp_name(ip_address, timeout=SNMP.TIMEOUT):
    """Read a device's sysName (falling back to sysDescr) over SNMP."""
    logger.debug("Querying SNMP sysName/sysDescr for IP: {}", ip_address)
    try:
        reply = sr1(
            _build_query(ip_address, SNMP.NAME_OIDS),
            timeout=timeout,
            verbose=False,
        )
    except Exception as error:
        logger.trace("SNMP query to {} failed: {}", ip_address, error)
        return None

    if reply is None or not reply.haslayer(SNMP_PACKET):
        logger.debug("No SNMP response from {}", ip_address)
        return None

    pdu = reply[SNMP_PACKET].PDU
    error = getattr(pdu.error, "val", pdu.error)
    try:
        error_code = int(error)
    except (TypeError, ValueError):
        error_code = 0
    if error_code != 0:
        logger.debug("SNMP error from {}: {}", ip_address, pdu.error)
        return None

    values = _varbind_values(reply[SNMP_PACKET])
    for oid in SNMP.NAME_OIDS:
        name = values.get(oid)
        if not name:
            continue
        if len(name) > SNMP.MAX_NAME_LENGTH:
            name = name[: SNMP.MAX_NAME_LENGTH].rstrip()
        logger.debug("SNMP resolved {} as {!r}", ip_address, name)
        return name

    logger.debug("No SNMP name for {}", ip_address)
    return None
