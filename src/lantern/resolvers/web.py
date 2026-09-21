import urllib.error
import urllib.request

from bs4 import BeautifulSoup

from lantern.constants import WEB
from lantern.logger import logger


def is_generic_title(title):
    """True when a page title is a boilerplate server/error page, not a device."""
    lowered = title.lower()
    return any(pattern in lowered for pattern in WEB.GENERIC_TITLE_PATTERNS)


def get_web_title(ip_address, timeout=WEB.TIMEOUT):
    """Load the device's built-in web page and use its <title> as a name."""
    logger.debug("Fetching web title for IP: {}", ip_address)
    for scheme, port in WEB.CANDIDATES:
        request = urllib.request.Request(
            f"{scheme}://{ip_address}:{port}",
            headers={WEB.USER_AGENT_HEADER: WEB.USER_AGENT},
        )
        try:
            response = urllib.request.urlopen(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            # Some devices return an error status but still serve a title.
            logger.trace("{} returned HTTP {} for {}", scheme, error.code, ip_address)
            response = error
        except Exception as error:
            logger.trace("{} request to {} failed: {}", scheme, ip_address, error)
            continue

        try:
            soup = BeautifulSoup(response.read(WEB.MAX_BYTES), WEB.HTML_PARSER)
            title_tag = soup.find(WEB.TITLE_TAG)
            title = title_tag.text.strip() if title_tag else ""
            # Ignore generic server/error pages ("404 - Page not found" and the
            # like) that say nothing about the device.
            if title and not is_generic_title(title):
                return title
            if title:
                logger.debug(
                    "Ignoring generic web title {!r} for {}", title, ip_address
                )
        except Exception as error:
            logger.trace(
                "Could not parse {} response from {}: {}", scheme, ip_address, error
            )
            continue
        finally:
            response.close()
    return None
