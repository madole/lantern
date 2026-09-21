import socket

from network_lister.logger import logger


def get_hostname(ip_address):
    """Ask the OS resolver what hostname an IP maps to (reverse DNS)."""
    logger.debug("Resolving hostname for IP: {}", ip_address)
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        logger.debug("Hostname for IP {}: {}", ip_address, hostname)
        return hostname
    except (socket.herror, socket.gaierror):
        logger.debug("No hostname found for IP {}", ip_address)
        return None
