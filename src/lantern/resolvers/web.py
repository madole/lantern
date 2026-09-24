import ipaddress
import urllib.error
import urllib.parse
import urllib.request

from bs4 import BeautifulSoup

from lantern.constants import WEB
from lantern.logger import logger
from lantern.metadata import APPLIANCE, SERVER, record
from lantern.sanitize import sanitize_name
from lantern.scope import is_in_scope

# Response headers/keys kept beyond the title: the server software banner and,
# when the page requires auth, the realm it advertises.
_AUTHENTICATE_HEADER = "WWW-Authenticate"
_REALM_PREFIX = "realm="
_REALM_KEY = "realm"
_SOURCE = "web"


def is_generic_title(title):
    """True when a page title is a boilerplate server/error page, not a device."""
    lowered = title.lower()
    return any(pattern in lowered for pattern in WEB.GENERIC_TITLE_PATTERNS)


def _final_url_in_scope(response, ip_address):
    """False when a redirect sent the response to an out-of-scope host.

    ``urlopen`` follows redirects, so an on-subnet device could otherwise bounce
    the title fetch to loopback or the cloud metadata service. Test doubles
    without ``geturl`` are treated as in scope.
    """
    final_url = getattr(response, "geturl", lambda: None)()
    if not isinstance(final_url, str):
        return True

    host = urllib.parse.urlparse(final_url).hostname
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return host == ip_address or is_in_scope(host)


def _realm_from_authenticate(value):
    """The realm named in a ``WWW-Authenticate`` header value, or None."""
    if not value:
        return None
    index = value.lower().find(_REALM_PREFIX)
    if index < 0:
        return None
    realm = value[index + len(_REALM_PREFIX) :].strip().strip('"').strip()
    return realm or None


def _record_response_metadata(response, ip_address):
    """Remember what the response headers say about the device.

    Best effort: test doubles (and odd responses) may carry no headers at all.
    ``record`` sanitizes and keeps only the first value per key, so a later
    candidate port never overwrites an earlier answer. Returns whether a
    ``Server`` header was present, which the caller uses to spot a bare
    embedded stack.
    """
    headers = getattr(response, "headers", None)
    if not headers:
        return False
    saw_server = False
    try:
        server = headers.get(WEB.SERVER_HEADER)
        record(ip_address, SERVER, server, _SOURCE)
        saw_server = bool(server)
        record(
            ip_address,
            _REALM_KEY,
            _realm_from_authenticate(headers.get(_AUTHENTICATE_HEADER)),
            _SOURCE,
        )
    except Exception as error:
        logger.trace("Could not read web headers from {}: {}", ip_address, error)
    return saw_server


def get_web_title(ip_address, timeout=WEB.TIMEOUT):
    """Load the device's built-in web page and use its <title> as a name."""
    logger.debug("Fetching web title for IP: {}", ip_address)
    saw_response = False
    saw_server = False
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
            if not _final_url_in_scope(response, ip_address):
                logger.debug(
                    "Ignoring off-subnet redirect while fetching {} for {}",
                    scheme,
                    ip_address,
                )
                continue
            saw_response = True
            if _record_response_metadata(response, ip_address):
                saw_server = True
            soup = BeautifulSoup(response.read(WEB.MAX_BYTES), WEB.HTML_PARSER)
            title_tag = soup.find(WEB.TITLE_TAG)
            title = sanitize_name(title_tag.text) if title_tag else None
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

    # A web server that answered but never named itself (no Server header, no
    # usable title) is the signature of a bare embedded stack. Record the hint
    # so the summary can flag an otherwise-anonymous appliance.
    if saw_response and not saw_server:
        record(ip_address, APPLIANCE, "embedded http server", _SOURCE)
    return None
