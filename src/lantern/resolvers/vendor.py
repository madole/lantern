from mac_vendor_lookup import MacLookup

from lantern.constants import FALLBACK
from lantern.logger import logger

mac_lookup = MacLookup()


def is_locally_administered(mac_address):
    """Randomized/private MACs carry no OUI, so vendor lookup cannot succeed."""
    try:
        first_octet = int(mac_address.replace(":", "").replace("-", "")[:2], 16)
    except (ValueError, IndexError):
        return False
    return bool(first_octet & 0b10)


def get_vendor(mac_address):
    """Look up the hardware maker from the MAC address's OUI prefix."""
    logger.debug("Looking up vendor for MAC address: {}", mac_address)
    if is_locally_administered(mac_address):
        logger.debug(
            "MAC {} is locally administered; no OUI vendor is available",
            mac_address,
        )
        return FALLBACK.VENDOR
    try:
        return mac_lookup.lookup(mac_address)
    except Exception as error:
        logger.debug("No vendor found for MAC {}: {}", mac_address, error)
        return FALLBACK.VENDOR
