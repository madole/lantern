import concurrent.futures
import threading
import time

from lantern.constants import FALLBACK, NAME
from lantern.logger import logger
from lantern.metadata import NAME_SOURCE, RESPONDED, record
from lantern.passive import get_passive_name, resolve_passive_names
from lantern.resolvers.banner import get_service_banner
from lantern.resolvers.hostname import get_hostname
from lantern.resolvers.llmnr import get_llmnr_name
from lantern.resolvers.mdns import (
    browse_mdns_services,
    get_mdns_name,
    get_mdns_service_name,
)
from lantern.resolvers.netbios import get_net_bios_name
from lantern.resolvers.router_dns import get_router_dns_name
from lantern.resolvers.snmp import get_snmp_name
from lantern.resolvers.ssdp import (
    discover_ssdp,
    get_ssdp_name,
    resolve_ssdp_names,
)
from lantern.resolvers.tls import get_tls_name
from lantern.resolvers.web import get_web_title
from lantern.scope import is_in_scope

# Ordered by priority: the first non-empty result wins, regardless of which
# lookup finishes first. Kept as (label, resolver) pairs so tests and callers
# can reason about the chain.
NAME_SOURCES = (
    ("passive", get_passive_name),
    ("hostname", get_hostname),
    ("router DNS", get_router_dns_name),
    ("mDNS", get_mdns_name),
    ("SSDP", get_ssdp_name),
    ("mDNS services", get_mdns_service_name),
    ("NetBIOS", get_net_bios_name),
    ("LLMNR", get_llmnr_name),
    ("SNMP", get_snmp_name),
    ("TLS certificate", get_tls_name),
    ("web title", get_web_title),
    ("service banner", get_service_banner),
)

# Sources whose answers are learned by broadcast/multicast: a single pass
# fills caches that the per-device sources then read from.
SCAN_SOURCES = ("passive", "SSDP", "mDNS services")

_executor = None
_executor_lock = threading.Lock()


def _get_executor():
    global _executor
    with _executor_lock:
        if _executor is None:
            _executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=NAME.MAX_WORKERS,
                thread_name_prefix="name",
            )
        return _executor


def reset_name_state():
    """Recreate the lookup pool so a new scan starts with fresh workers."""
    global _executor
    with _executor_lock:
        if _executor is not None:
            _executor.shutdown(wait=False, cancel_futures=True)
        _executor = None


def shutdown_name_state():
    """Wait for in-flight lookups to drain so none run past the scan.

    Early exit cancels queued lookups but cannot stop the ones already in a
    worker; letting those finish here keeps them from leaking past the report.
    """
    global _executor
    with _executor_lock:
        executor, _executor = _executor, None
    if executor is not None:
        executor.shutdown(wait=True, cancel_futures=True)


def prefetch_broadcast_names():
    """Run the scan-wide broadcast lookups, overlapping the two multicasts.

    mDNS browsing and SSDP discovery answer for every host at once, so doing
    them per device would repeat the same network round-trips N times. They use
    different multicast groups and sockets, so they run concurrently. Neither
    depends on the ARP results or the passive listener, which lets the caller
    start this before the ARP scan and join it after the passive listener.
    """
    logger.debug("Prefetching scan-scoped broadcast name sources")
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=NAME.PREFETCH_WORKERS, thread_name_prefix="prefetch"
    ) as pool:
        futures = (
            pool.submit(browse_mdns_services),
            pool.submit(_discover_and_resolve_ssdp),
        )
        for future in futures:
            future.result()


def _discover_and_resolve_ssdp():
    """Discover SSDP responders, then fetch every description once."""
    discover_ssdp()
    resolve_ssdp_names()


def _prefetch_broadcast_worker():
    """Best-effort wrapper so a prefetch failure can never abort the scan."""
    try:
        prefetch_broadcast_names()
    except Exception as error:
        logger.opt(exception=error).warning("Scan-wide name prefetch failed: {}", error)


def start_prefetch_broadcast():
    """Start the scan-wide broadcast lookups in the background.

    Returns the worker thread so the caller can join it with
    :func:`finish_prefetch_broadcast` once the passive listener has stopped.
    """
    thread = threading.Thread(
        target=_prefetch_broadcast_worker,
        name="prefetch-broadcast",
        daemon=True,
    )
    thread.start()
    return thread


def finish_prefetch_broadcast(thread=None):
    """Wait for the scan-wide broadcast lookups started above to finish."""
    if thread is not None:
        thread.join()


def prefetch_scan_names():
    """Run every scan-scoped source once, synchronously.

    Convenience for callers that are not overlapping the prefetch with the
    passive window; ``scan_network`` uses the split broadcast/passive steps
    instead so the multicasts can run while the listener is still going.
    """
    prefetch_broadcast_names()
    resolve_passive_names()


def _run_source(source, resolver, ip_address, device):
    """Call a resolver, tagging any logs it emits with its device context."""
    if not is_in_scope(ip_address):
        logger.debug("Skipping {} for out-of-scope {}", source, ip_address)
        return None
    with logger.contextualize(device=device or "-"):
        return resolver(ip_address)


def _highest_priority_success(successes, futures, pending):
    """The best completed name, if no running source could still outrank it."""
    if not successes:
        return None

    best_priority = min(successes)
    pending_priorities = [futures[future][0] for future in pending]
    if pending_priorities and min(pending_priorities) < best_priority:
        return None

    return successes[best_priority]


def _record_responded(ip_address, successes):
    """Remember which name sources answered for a device.

    Best-effort: the chain exits as soon as the highest-priority running source
    is decided, so this is the set that completed before that point, not every
    source on the network. The winning source is recorded separately.
    """
    if not successes:
        return
    try:
        sources = [successes[priority][0] for priority in sorted(successes)]
        record(ip_address, RESPONDED, "; ".join(sources), "name")
    except Exception as error:
        logger.trace("Could not record responded sources for {}: {}", ip_address, error)


def _run_sources(executor, ip_address, device, sources, deadline):
    """Run one tier of sources concurrently until one wins or time runs out.

    Returns the winning ``(source, name)`` pair, the best available success at
    the deadline, or None when nothing matched. Queued stragglers are cancelled
    once a winner is confirmed; ones already running are left to drain.
    """
    if not sources or deadline - time.monotonic() <= 0:
        return None

    futures = {
        executor.submit(_run_source, source, resolver, ip_address, device): (
            priority,
            source,
        )
        for priority, source, resolver in sources
    }
    pending = set(futures)
    successes = {}

    while pending:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            logger.debug("Name lookups for {} hit the deadline", ip_address)
            break

        done, pending = concurrent.futures.wait(
            pending,
            timeout=remaining,
            return_when=concurrent.futures.FIRST_COMPLETED,
        )
        if not done:
            break

        for future in done:
            priority, source = futures[future]
            try:
                name = future.result()
            except Exception as error:
                logger.opt(exception=error).debug(
                    "{} lookup raised for {}: {}", source, ip_address, error
                )
                continue

            if name:
                successes[priority] = (source, name)
                logger.debug("{} resolved {} as {!r}", source, ip_address, name)
            else:
                logger.debug("{} found no name for {}", source, ip_address)

        winner = _highest_priority_success(successes, futures, pending)
        # Early exit is the default: once no still-running source can outrank
        # the best result, stop. FULL_MATRIX keeps waiting so every source that
        # answers is recorded, trading scan time for a complete protocol matrix.
        if not NAME.FULL_MATRIX and winner is not None:
            for future in pending:
                future.cancel()
            _record_responded(ip_address, successes)
            return winner

    _record_responded(ip_address, successes)
    return successes[min(successes)] if successes else None


def resolve_name(ip_address, device=None):
    """Resolve an IP concurrently, returning the highest-priority name.

    Fast sources run together; the slow, low-yield sources (TLS and web) are
    only tried when those all come up empty, so a device named quickly never
    spends time on them. A total deadline caps how long one device can stall
    the scan.
    """
    if not is_in_scope(ip_address):
        logger.warning("Refusing to probe out-of-scope address {}", ip_address)
        return FALLBACK.NAME

    executor = _get_executor()
    deadline = time.monotonic() + NAME.DEADLINE

    tiers = (
        [
            (priority, source, resolver)
            for priority, (source, resolver) in enumerate(NAME_SOURCES)
            if source not in NAME.DEFERRED_SOURCES
        ],
        [
            (priority, source, resolver)
            for priority, (source, resolver) in enumerate(NAME_SOURCES)
            if source in NAME.DEFERRED_SOURCES
        ],
    )

    for sources in tiers:
        winner = _run_sources(executor, ip_address, device, sources, deadline)
        if winner is not None:
            source, name = winner
            record(ip_address, NAME_SOURCE, source, "name")
            logger.debug("Using {} result for {}", source, ip_address)
            return name

    logger.debug("No name source matched {}; using {}", ip_address, FALLBACK.NAME)
    return FALLBACK.NAME
