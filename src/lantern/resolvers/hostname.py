import socket

from lantern.logger import logger
from lantern.sanitize import sanitize_name


def get_hostname(ip_address):
    """Ask the OS resolver what hostname an IP maps to (reverse DNS)."""
    logger.debug("Resolving hostname for IP: {}", ip_address)
    try:
        hostname = sanitize_name(socket.gethostbyaddr(ip_address)[0])
        logger.debug("Hostname for IP {}: {}", ip_address, hostname)
        return hostname
    except (socket.herror, socket.gaierror):
        logger.debug("No hostname found for IP {}", ip_address)
        return None
