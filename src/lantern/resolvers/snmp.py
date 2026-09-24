from scapy.all import IP, UDP, sr1
from scapy.layers.snmp import SNMP as SNMP_PACKET
from scapy.layers.snmp import SNMPget, SNMPvarbind

from lantern.constants import SNMP
from lantern.logger import logger
from lantern.metadata import UPTIME, record
from lantern.sanitize import sanitize_name
from lantern.scope import require_read_only


def _build_query(ip_address, oids):
    """Build an SNMP v2c GET for the given OIDs using the read-only community."""
    require_read_only("snmp get")
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
    return sanitize_name(raw)


def _varbind_oid(varbind):
    oid = getattr(varbind.oid, "val", None)
    if oid:
        return oid
    return varbind.oid if isinstance(varbind.oid, str) else None


def _varbind_int(varbind):
    """Decode a varbind's value to an int, or None when it is not numeric."""
    value = getattr(varbind, "value", None)
    raw = getattr(value, "val", None)
    if raw is None and isinstance(value, int):
        raw = value
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _format_uptime(ticks):
    """Render TimeTicks (centiseconds) as a short string like '3d 4h 5m'."""
    total_seconds = ticks // 100
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _record_metadata(ip_address, packet):
    """Record metadata facts from the reply's varbinds; never raises.

    This is a side effect of the name GET: a weird or missing varbind simply
    records nothing. The values are not truncated here; MAX_NAME_LENGTH only
    bounds the displayed name.
    """
    try:
        varbinds = list(packet.PDU.varbindlist)
    except Exception as error:
        logger.trace("SNMP metadata unavailable for {}: {}", ip_address, error)
        return

    for varbind in varbinds:
        try:
            oid = _varbind_oid(varbind)
            if oid == SNMP.SYS_DESCR:
                record(ip_address, "sys_descr", _varbind_text(varbind), "SNMP")
            elif oid == SNMP.SYS_OBJECT_ID:
                record(ip_address, "sys_object_id", _varbind_text(varbind), "SNMP")
            elif oid == SNMP.SYS_UPTIME:
                ticks = _varbind_int(varbind)
                if ticks is not None and ticks >= 0:
                    record(ip_address, UPTIME, _format_uptime(ticks), "SNMP")
            elif oid == SNMP.SYS_CONTACT:
                record(ip_address, "contact", _varbind_text(varbind), "SNMP")
            elif oid == SNMP.SYS_LOCATION:
                record(ip_address, "location", _varbind_text(varbind), "SNMP")
        except Exception as error:
            logger.trace("SNMP metadata varbind skipped for {}: {}", ip_address, error)


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
    if not SNMP.ENABLED:
        logger.debug("SNMP disabled (no community configured); skipping {}", ip_address)
        return None

    logger.debug("Querying SNMP sysName/sysDescr for IP: {}", ip_address)
    try:
        reply = sr1(
            _build_query(ip_address, SNMP.NAME_OIDS + SNMP.METADATA_OIDS),
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
    _record_metadata(ip_address, reply[SNMP_PACKET])
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
