# Intent: richer device identification

## Goal

Too many devices on the LAN are reported as `Unknown`. The current scan only
collects an IP, MAC, and vendor, then makes a single attempt at each name source
in order. We want to raise the share of devices with a human-meaningful name and
add useful metadata (model, services, OS hints) when a name is unavailable.

## Current behavior

For every host found via ARP, `scan_network` resolves a name through this chain
and takes the first non-empty result:

1. `get_hostname` - reverse DNS (PTR)
2. `get_mdns_name` - reverse mDNS PTR (`<ip>.in-addr.arpa`)
3. `get_net_bios_name` - NetBIOS name query (UDP/137)
4. `get_web_title` - HTTP/HTTPS `<title>`
5. fallback: `Unknown`

Vendor is looked up from the MAC OUI.

### Recently fixed

- `get_mdns_name` sent a unicast query with `sr1` to a multicast address, so
  replies were never matched. It now sends a proper link-layer mDNS query
  (multicast MAC, TTL 255) and sniffs for multicast answers.
- `get_web_title` only accepted HTTP 200, ignored redirects/error pages, and
  returned the truthy `"N/A"` which blocked the fallback to `Unknown`. It now
  reads the body regardless of status (including `HTTPError` responses), sends a
  browser-like `User-Agent`, and returns `None` when no title is found.
- `get_hostname` only caught `socket.herror`; `socket.gaierror` could crash the
  whole scan. Both are handled now.
- `get_web_title` treated generic server/error pages ("404 - Page not found",
  "Apache2 Ubuntu Default Page", directory listings, ...) as device names. Those
  titles are now rejected so the chain can fall through to another source or
  `Unknown`.

## Planned additions

Ordered roughly by expected payoff versus effort.

### 1. SSDP / UPnP discovery — DONE

- Send an `M-SEARCH` to `239.255.255.250:1900` and collect `LOCATION` responses.
- Fetch the device description XML for `friendlyName`, `manufacturer`, and
  `modelName`.
- High yield for TVs, speakers, printers, consoles, and IoT gear that never
  answer DNS or NetBIOS.
- Names learned this way should feed the same result chain (after DNS/mDNS).

### 2. mDNS service browsing — DONE

- In addition to reverse PTR, browse `_services._dns-sd._udp.local` and common
  service types (`_http._tcp`, `_airplay._tcp`, `_raop._tcp`, `_googlecast._tcp`,
  `_printer._tcp`, ...).
- Map service instance names back to IPs. Many devices answer a browse even when
  they ignore a reverse lookup.
- Reuse the new send/sniff mDNS helper; consider caching results per scan pass.

### 3. Passive listening — DONE

- Sniff the LAN and harvest self-announced data from ARP, mDNS, SSDP, DHCP, and
  LLMNR traffic. Runs once in parallel with the active scan.
- The window is adaptive: it closes once the wire has been quiet for
  `PASSIVE.QUIET_PERIOD` (after a `PASSIVE.MIN_WINDOW` floor) or at the
  `PASSIVE.TIMEOUT` ceiling, so a quiet LAN finishes in seconds while a busy one
  keeps listening.
- Catches devices that ignore active probes and reveals names before/without
  querying.
- Requires no extra privileges beyond what ARP scanning already needs.

### 4. LLMNR — DONE

- Query UDP/5355 for Windows hosts that do not answer NetBIOS.
- Same shape as the existing NetBIOS query.

### 5. Router DNS as a second resolver — DONE

- Query the default gateway directly as a DNS server; routers usually hold the
  DHCP client-name list even when a device will not answer reverse DNS.
- Cheap to add, complements the system resolver.

### 6. TLS certificate and HTTP metadata — DONE

- On HTTPS, read the certificate CN/SAN for a hostname even when the page title
  is missing or auth-gated. Self-signed certificates are read without chain
  verification by default; `LANTERN_TLS_VERIFY=1` requires a trusted chain.
- Collect the `Server` response header and try the title on common alternate
  ports (8080, 8443, 8000, ...), not just 80/443.

### 7. SNMP — DONE

- Attempt `sysName` / `sysDescr` with the community from
  `LANTERN_SNMP_COMMUNITY` (default `public`).
- Excellent detail (model, firmware, OS) for managed switches, printers, and
  NAS boxes; silent when SNMP is disabled (empty community).

### 8. Service banners — DONE

- Grab banners for SSH, SMB, and similar ports to infer vendor/model/OS when no
  name source succeeds.
- Slower and noisier; treat as a last resort and keep timeouts tight.

## Future considerations

Follow-ups beyond the name-source work; A, C, D, and I are done, B/E/F are
partly shipped, and G-H remain.

### A. Concurrency and a per-device time budget — DONE

`scan_network` used to resolve devices one at a time and `resolve_name` walked
`NAME_SOURCES` sequentially, each with its own timeout. Worst case was the sum:

| source | worst case |
| --- | --- |
| passive (`get_passive_name`) | ~1s (SSDP description fetch) |
| `get_hostname` | OS resolver default (seconds) |
| router DNS / mDNS reverse / SSDP / NetBIOS / LLMNR | 2 + 2 + 3 + 2 + 2s |
| mDNS services | 3s, once per scan |
| TLS | 1s x 2 ports |
| web title | 1s x 7 candidates |

So ~20-25s per device, multiplied by device count, on top of the passive
window. On a busy /24 this dominated total runtime.

What shipped:

1. **Scan-scoped prefetch.** `prefetch_scan_names` (`name.py`) runs the
   broadcast/multicast sources once per scan: `browse_mdns_services` (already
   cached) and `discover_ssdp` + `resolve_ssdp_names`, which send one M-SEARCH
   and collect every responder's `LOCATION` into an `IP -> name` cache. The
   passive listener's SSDP descriptions are fetched once via
   `resolve_passive_names`. `get_ssdp_name` reads the cache and only falls back
   to a targeted per-host search when no scan-wide discovery ran. The prefetch
   is split so the broadcast half (`prefetch_broadcast_names`) starts *before*
   the ARP scan and overlaps the passive window, while `resolve_passive_names`
   runs once the listener is joined; each half fans its independent work out
   over a small pool.
2. **Concurrent device sources with a deadline, in tiers.** `resolve_name` runs
   all fast `NAME_SOURCES` together in a shared `ThreadPoolExecutor`, returning
   the highest-priority success as soon as no still-running source outranks it
   and cancelling the rest. Only when every fast source comes up empty does it
   run the deferred tier (`NAME.DEFERRED_SOURCES`: TLS certificate and web
   title), so a device named quickly never spends time on the slow sources.
   `NAME.DEADLINE` caps the total wait across both tiers.
3. **No global probe tunnel.** An earlier attempt serialized every scapy-based
   source through a `PROBE_LIMIT` semaphore, but workers blocked on one token
   starved the lookups (devices hit the deadline and fell through to `Unknown`)
   and built a backlog that could not be cancelled, leaking past the report.
   Sources now run independently; each sniffer/`sr1` uses its own socket and
   filters replies by source IP, so they do not need to be serialized.
4. **Bounded device parallelism.** `scan_network` resolves devices through a
   `ThreadPoolExecutor(NAME.MAX_DEVICE_WORKERS)` pool, then `shutdown_name_state`
   waits for in-flight lookups so nothing continues after the table is printed.
5. `NAME.*` constants live in `constants.py` and the per-scan state is reset via
   `reset_name_state` / `reset_ssdp_cache`. Device context is passed into pooled
   lookups so their logs keep the `IP (MAC)` label.

Remaining: concurrent multicast sniffers on UDP/5353 and UDP/1900 can
theoretically cross-talk, though every resolver filters by responder IP and the
scan-scoped maps remove most of the need. The adaptive passive window trades
coverage for latency: stopping after a quiet period can miss a device that
would have announced only after several seconds of silence. Early exit still
leaves already-running fast-tier lookups to finish (the drain absorbs them), but
the slow TLS/web tier is never started for a device that the fast tier already
named.

### B. Source and confidence reporting — PARTLY DONE (source, no confidence)

What shipped: `resolve_name` records the winning label as `name_source` and the
set of sources that answered before the early exit as `responded`, both through
`metadata.record`, so they appear in the `Details` column and feed the summary.
The name chain itself is unchanged — no confidence weighting yet.

Still open:

- Apply a per-source confidence table (e.g. passive self-announcement and router
  DNS high; reverse DNS/mDNS medium; SSDP `friendlyName` medium; TLS CN and web
  `<title>` low), and distinguish an OUI hit from a locally administered/unknown
  MAC (`is_locally_administered`) as its own confidence signal.
- Never let a low-confidence source override a higher-confidence one, even if it
  resolves first. (Today priority order alone decides.)
- Optionally surface a dedicated `Source`/`Confidence` column; `name_source` in
  the details column already exposes the winner.

### C. Metadata capture — DONE (name-source confidence, B, still open)

Shipped as a per-scan, lock-guarded fact store in `metadata.py`:

- `record(ip, key, value, source)` stores one fact per key (first value wins)
  and sanitizes at the boundary; `get_metadata(ip)` reads them back. The store
  is reset per scan and touched only through this module.
- `main.py` reads it *after* `shutdown_name_state` (the drain) and renders a
  `Details` column, so a fact a slow source records still reaches the table.
- Canonical keys (`model`, `os`, `version`, `serial`, `device_type`, ...) let
  two protocols fill one column instead of inventing parallel ones.
- Every fact keeps its `source` for auditing; the per-source *confidence*
  treatment of B is not implemented yet.

The SSDP parser still collapses its name fields to one string, but now also
exposes the full set (see E).

### D. Read-only and LAN-scoped guardrails — DONE

What shipped:

1. **A single scope module.** `scope.py` owns two policies. It holds the
   scanned subnet (registered once per scan) and answers `is_in_scope` /
   `require_in_scope`; and it holds the read-only policy via `READ_ONLY` plus
   `require_read_only`, which rejects any operation that is not a known
   read-only probe.
2. **Scope registration in `scan_network`.** `main.py` parses the range and
   calls `set_scan_network` before any probe, clearing it in a `finally`. The
   passive-MAC membership filter (`main.py`) now reuses `is_in_scope` instead of
   a local `ipaddress` check.
3. **Out-of-subnet probes are skipped, not sent.** `resolve_name` and
   `_run_source` refuse off-subnet addresses, so no name source is dispatched
   for them. SSDP discovery and the passive SSDP description fetch also filter
   responders by scope before fetching a description.
4. **Read-only is executable.** SNMP builds only an `SNMPget` and SSDP sends
   only an `M-SEARCH`; both call `require_read_only`. No `set`, action, or
   credential path exists.
5. **Regression tests.** `tests/test_guardrails.py` covers membership parsing,
   in/out-of-subnet dispatch, SSDP/passive filtering, and asserts the wire
   formats are read-only (`SNMPget`, `M-SEARCH`) and that a mutating operation
   is rejected.
6. **No unsolicited internet egress.** The OUI vendor list is only downloaded
   when `LANTERN_OUI_DOWNLOAD=1`; otherwise `mac_vendor_lookup`'s implicit fetch
   is blocked and only a locally provisioned list is used. SNMP probing can be
   turned off by clearing its community.

Concurrency was already bounded (`NAME.MAX_DEVICE_WORKERS`, `NAME.MAX_WORKERS`)
and there are no retry loops, so probes cannot flood the segment. The explicit
`8.8.8.8` use remains local-IP detection only and sends no packet.

### E. Fields already on the wire, currently discarded — PARTLY DONE

Every name source fetches a payload that carries more than the one value the
chain keeps. Surfacing the rest needs no additional network traffic — only
extraction work in code that is already receiving the bytes. Ordered roughly by
payoff; the first three overlap C.

What shipped (all via `metadata.record`, no new probes, no new round-trips):

- **DHCP** (`passive.py`): options 60 (vendor class), 55 (parameter-request
  fingerprint), 81 (client FQDN), and 61 (client id). The hostname return value
  is unchanged; metadata is recorded even when option 12 is absent.
- **SSDP** (`resolvers/ssdp.py`): response `SERVER`/`ST`/`USN` headers
  (`server`, `device_type`, `uuid`) recorded for in-scope responders, plus the
  description's `deviceType`/`UDN`/`serialNumber`/`modelName`/`manufacturer`/
  `modelNumber`. `_ssdp_search` and `get_ssdp_description` keep their existing
  contracts so the monkeypatched tests still hold.
- **SNMP** (`resolvers/snmp.py`): the one read-only GET now also asks for
  `sysDescr`, `sysObjectID`, `sysUpTime`, `sysContact`, and `sysLocation`, and
  records `sys_descr`/`sys_object_id`/`contact`/`location`/`uptime`
  (`sysDescr` is kept even when `sysName` supplies the name).
- **mDNS** (`resolvers/mdns.py`): TXT `model`/`os`/`version`/`deviceid` and the
  set of SRV service types (`services`) from the one browse pass.
- **HTTP/TLS** (`resolvers/{web,tls}.py`): the `Server` header (and an auth
  realm when present), and the certificate issuer/validity window. This also
  resolves the drift noted below — item 6 claimed the `Server` header was
  collected; it now is.
- **MAC randomization** (`main.py`): a locally administered MAC records
  `randomized_mac`.
- **Open-service inventory** (`resolvers/ports.py`, called once per device from
  `main.py`): a bounded, read-only TCP connect probe of `PORTS.CANDIDATES`
  records `open_ports`, independent of the name chain. This is the one item here
  that adds a probe rather than reusing one; it is LAN-scoped and
  concurrency-bounded, and it also feeds the summary (F).

Everything in this section is now shipped; the only field deliberately left
uncaptured is the redirect `Location` header.

- **SSDP response headers.** `parse_ssdp_location` (`resolvers/ssdp.py`) and the
  passive `parse_ssdp` (`passive.py`) read only `LOCATION` out of the M-SEARCH
  response. The same datagram carries `SERVER:` (the OS/UPnP stack, e.g.
  `Linux/3.14 UPnP/1.0 ...`), `ST:` (`urn:...:device:MediaRenderer:1`, a device
  class), and `USN:` (stable identity). Capture them as device-class and
  platform hints, and use `USN` as a cross-scan identity anchor (see G).
- **UPnP description internals.** `parse_ssdp_description` (`ssdp.py`) already
  iterates every element but keeps only `friendlyName`/`modelName`/
  `manufacturer`. `deviceType`, `UDN`, `serialNumber`, `modelNumber`, and the
  `serviceList` are in the same document; capture them to fill model/serial
  columns and a stable UUID.
- **SNMP `sysDescr` as metadata.** `SNMP.NAME_OIDS` already fetches both
  `sysName` and `sysDescr` in one GET, but `get_snmp_name` (`snmp.py`) only
  consults `sysDescr` when `sysName` is empty, discarding the model/OS/firmware
  text whenever a name was found. Keep `sysDescr` as metadata regardless, and
  extend the same query with `sysObjectID` (vendor device type), `sysUpTime`
  (recent reboot?), and `sysContact`/`sysLocation`.
- **DHCP options beyond the hostname.** `parse_dhcp` (`passive.py`) keeps only
  option 12 (hostname). The packets it already sniffs also carry option 60
  (vendor class: `MSFT 5.0`, `android-dhcp-13`, `dhcpcd-...`), option 55
  (parameter request list, a classic OS fingerprint), option 81 (client FQDN,
  usually the real machine name and domain), and option 61 (client id). This is
  one of the highest-yield, zero-cost fingerprints available.
- **mDNS SRV/TXT records.** `browse_mdns_services` (`mdns.py`) keeps only PTR
  answers. The same DNS-SD response bundles SRV (host + port, i.e. which service
  runs where) and TXT (`model=`, `os=`, `ver=`, feature flags). AirPlay, Cast,
  and printers hand over model and OS version in TXT for free.
- **HTTP and TLS response metadata.** `get_web_title` (`web.py`) now records
  the `Server` header and a `WWW-Authenticate` realm from the response it
  already reads (a redirect `Location` is still not captured). This also fixes
  the drift in item 6, which claimed the `Server` header was collected when it
  was not. `certificate_names` (`tls.py`) still keeps only DNS SANs and the CN,
  but the issuer and validity window are now recorded as metadata (signed vs.
  self-signed, firmware age, vendor).
- **Open-service inventory.** Implemented as a dedicated probe
  (`resolvers/ports.py`) rather than reusing the banner/web ports, so it runs
  for every device even when the name chain never reaches those sources.
  `open_ports` yields a per-device exposed-port map; an open telnet (23) or SMB
  (445) is a security signal, not just a name candidate.
- **MAC randomization.** `is_locally_administered` (`vendor.py`) is already
  computed but collapsed to `"Unknown Vendor"`. A locally administered MAC
  signals a privacy-randomized endpoint (phone/laptop) or a VM and is useful on
  its own.

### F. Aggregate and cross-device insights — PARTLY DONE

What shipped in `summary.py` (pure, no I/O; `main.py` logs the lines after the
table):

- **IP↔MAC cardinality.** `main.py` now keeps every `(ip, mac, source)`
  observation from the ARP scan and the passive listener, and `summarize`
  reports an IP seen with multiple MACs and a MAC seen on multiple IPs.
- **Fleet composition and device class.** `classify` infers one label per device
  (virtual machine, printer, windows host, unix host, apple/consumer,
  media/iot, iot, unknown) from open ports, `name_source`, `services`, and
  vendor; `summarize` tallies vendors and classes.
- **Security posture.** Risky open ports (`PORTS.RISKY`) and a device that
  answered SNMP under the default `public` community are reported per device.
- **Randomized-MAC count** and named/unknown counts.

Still open: the complete protocol-response matrix is now an opt-in rather than
the default. `LANTERN_FULL_MATRIX=1` disables the early exit so every source in
a tier runs to completion and `responded` records the full set; it is off by
default and still bounded by `NAME.DEADLINE`. The deferred tier still only runs
when the fast tier finds no name, so the matrix covers the tier that ran.

Original notes:

- **IP↔MAC cardinality.** The passive and merged caches are first-write-wins
  (`passive.py`, `main.py`), so two MACs on one IP (address conflict or roaming)
  and one MAC on several IPs (multi-homed/aliased) are silently discarded. Flag
  both as network-health findings.
- **Protocol-response matrix as a signature.** *Which* sources answered is
  itself a fingerprint: NetBIOS + LLMNR + SMB implies Windows; mDNS/AirPlay/Cast
  implies Apple or consumer gear; SNMP implies managed equipment; router DNS
  only implies a headless DHCP client; a web title only implies an appliance.
  This is B's source data reused for device-class inference, not just confidence.
- **Fleet composition.** A vendor histogram, VM/container detection from the OUI
  (VMware/QEMU/VirtualBox), and a randomized-MAC count characterize the network
  as a whole.
- **Security posture.** The same data flags an SNMP agent answering the default
  `public` community, an open telnet port, an unauthenticated web admin page, or
  a self-signed certificate.

### G. Persistence across scans

Nothing is stored between scans today — `scan_network` returns a transient list.
Persisting the (MAC, UDN, name, vendor, metadata) records would unlock the
highest-value insight of all: new, vanished, and moved devices, i.e. rogue-
device detection and IP-churn tracking anchored on a stable identifier.

### H. Coverage gap: IPv6

The passive parsers and multicast resolvers require `haslayer(IP)` (`passive.py`,
`mdns.py`), so IPv6-only devices and NDP/DHCPv6 traffic are invisible. Worth
scoping separately if the LAN carries IPv6.

### I. MCP server — DONE

`mcp_server.py` exposes the scan to AI hosts over MCP stdio, so a model can run
a scan and add its own insight to the results. `main.py` was split into a
presentation-free core (`run_scan`, returning devices, observations and the
`summary` as one JSON-serializable dict) and the existing CLI wrapper, so the
CLI and the server share one scan implementation. Two tools: `network_info`
(local IP/subnet) and `scan(ip_range?)` (the JSON result). The CLI also gained
`--json` and `--range`. The server must run as root, since the scan needs raw
sockets.

### J. Service-type discovery, appliance hint, and class inference — DONE

A live scan of a real LAN surfaced four gaps, all closed without new probes:

- **Dynamic mDNS service-type discovery.** `browse_mdns_services` already sent
  the `_services._dns-sd._udp.local` meta-query but discarded its answers. The
  meta-query reply enumerates every service type the LAN advertises, so those
  answers now drive a second browse pass for any type not in the static list
  (capped by `MDNS.MAX_DISCOVERED_TYPES`). This is how MAC-derived names such as
  Google Nearby's `_FC9F5ED42C8A._tcp` are found at all, and it removes the need
  to hardcode every stack.
- **New static types.** `_miio._udp` (Xiaomi/Yeelight), `_hap._tcp` (HomeKit),
  and `_dkapi._tcp` (Daikin) join the list, and `_udp` services are now covered.
- **Service-aware classification.** `summary.classify` no longer treats any
  `services` value as `apple/consumer`; it maps known types to a family
  (HomeKit/Xiaomi/Daikin → `iot`, Cast/Spotify → `media/iot`,
  AirPlay/Companion-Link → `apple/consumer`) and checks them before the coarser
  name-source fallbacks.
- **Embedded-appliance fingerprint.** A web server that answers but presents no
  `Server` header and no usable title is recorded as `appliance` (metadata) and
  classified as `appliance`, so a bare embedded stack is no longer `unknown`.


