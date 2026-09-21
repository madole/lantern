from mac_vendor_lookup import BaseMacLookup, MacLookup

from lantern.constants import FALLBACK, VENDOR
from lantern.logger import logger

mac_lookup = MacLookup()

_vendor_download = mac_lookup.async_lookup.update_vendors

_warned_missing_list = False


async def _guarded_download(*args, **kwargs):
    """Stop mac_vendor_lookup's implicit internet fetch unless opted in.

    ``MacLookup.lookup`` downloads the IEEE OUI list when no local copy exists.
    Wrapping the download lets lookups keep working off a provisioned file while
    never reaching the network on their own.
    """
    if not VENDOR.DOWNLOAD:
        raise RuntimeError(
            f"OUI vendor download disabled; set {VENDOR.DOWNLOAD_ENV} to allow it"
        )
    return await _vendor_download(*args, **kwargs)


mac_lookup.async_lookup.update_vendors = _guarded_download


def is_locally_administered(mac_address):
    """Randomized/private MACs carry no OUI, so vendor lookup cannot succeed."""
    try:
        first_octet = int(mac_address.replace(":", "").replace("-", "")[:2], 16)
    except (ValueError, IndexError):
        return False
    return bool(first_octet & 0b10)


def _warn_if_no_vendor_list():
    """Warn once when vendors will be unknown because no OUI list is available."""
    global _warned_missing_list
    if VENDOR.DOWNLOAD or _warned_missing_list:
        return
    if mac_lookup.async_lookup.find_vendors_list():
        return

    _warned_missing_list = True
    logger.warning(
        "No local OUI vendor list at {}; vendors stay '{}'. Place the IEEE OUI "
        "file there or set {} to download it.",
        BaseMacLookup.cache_path,
        FALLBACK.VENDOR,
        VENDOR.DOWNLOAD_ENV,
    )


def get_vendor(mac_address):
    """Look up the hardware maker from the MAC address's OUI prefix."""
    logger.debug("Looking up vendor for MAC address: {}", mac_address)
    if is_locally_administered(mac_address):
        logger.debug(
            "MAC {} is locally administered; no OUI vendor is available",
            mac_address,
        )
        return FALLBACK.VENDOR

    _warn_if_no_vendor_list()
    try:
        return mac_lookup.lookup(mac_address)
    except Exception as error:
        logger.debug("No vendor found for MAC {}: {}", mac_address, error)
        return FALLBACK.VENDOR
