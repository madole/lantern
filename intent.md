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

- Sniff the LAN for a bounded window (30-60s) and harvest self-announced data
  from ARP, mDNS, SSDP, DHCP, and LLMNR traffic.
- Catches devices that ignore active probes and reveals names before/without
  querying. Best run once in parallel with the active scan.
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
  is missing or auth-gated. Handle self-signed certs explicitly.
- Collect the `Server` response header and try the title on common alternate
  ports (8080, 8443, 8000, ...), not just 80/443.

### 7. SNMP

- Attempt `sysName` / `sysDescr` with community `public`.
- Excellent detail (model, firmware, OS) for managed switches, printers, and
  NAS boxes; silent when SNMP is disabled.

### 8. Service banners

- Grab banners for SSH, SMB, and similar ports to infer vendor/model/OS when no
  name source succeeds.
- Slower and noisier; treat as a last resort and keep timeouts tight.

## Future considerations

Three follow-ups that the current implementation makes increasingly urgent.

### A. Concurrency and a per-device time budget

Today `scan_network` resolves devices one at a time (`main.py:52`) and
`resolve_name` walks `NAME_SOURCES` sequentially (`name.py:27`), each with its
own timeout. Worst case per device is roughly the sum:

| source | worst case |
| --- | --- |
| passive (`get_passive_name`) | ~1s (SSDP description fetch) |
| `get_hostname` | OS resolver default (seconds) |
| router DNS / mDNS reverse / SSDP / NetBIOS / LLMNR | 2 + 2 + 3 + 2 + 2s |
| mDNS services | 3s, once per scan |
| TLS | 1s x 2 ports |
| web title | 1s x 7 candidates |

So ~20-25s per device, multiplied by device count, on top of the 30s passive
window. On a busy /24 this dominates total runtime.

Plan:

1. **Split scan-scoped from device-scoped sources.** Multicast/broadcast
   lookups should run once for the whole scan and build an `IP -> name` map
   before the device loop: mDNS service browse (already cached), SSDP discovery
   (one M-SEARCH, collect every `LOCATION`), the passive harvest, and gateway
   resolution. Device-scoped sources stay per-IP: reverse DNS, router-DNS PTR,
   mDNS reverse, NetBIOS, LLMNR, TLS, web.
2. **Run device-scoped sources concurrently per device** behind a
   `ThreadPoolExecutor` and an overall per-device deadline
   (new `NAME.DEADLINE` constant). Submit in `NAME_SOURCES` priority order,
   collect results as they complete, return the highest-priority success, and
   cancel the rest. Keep the existing order as the tie-breaker so behaviour is
   unchanged when multiple sources answer.
3. **Bound the sniffer fan-out.** `AsyncSniffer` is thread-based and each
   instance opens its own BPF handle; concurrent mDNS/SSDP/NetBIOS/LLMNR
   sniffers can cross-talk on shared ports. Gate the sniffer-based resolvers
   with a semaphore (or serialize them) while letting the socket-based ones
   (reverse DNS, router DNS, TLS, web) run freely.
4. **Process devices with bounded parallelism** (e.g. 4-8 workers) so wall time
   is ~`DEADLINE * ceil(N / workers)` plus the passive window.
5. Move all timeouts/deadline into `constants.py` and allow env overrides.

Risk: simultaneous multicast sniffers on UDP/5353 and UDP/1900 can mis-attribute
answers. The scan-scoped maps in step 1 remove most of that need.

### B. Source and confidence reporting

- Return a structured result from `resolve_name` (`name`, `source`) instead of a
  bare string, and update `main.py` and tests accordingly.
- Add a per-source confidence table in `constants.py` (e.g. passive
  self-announcement and router DNS high; reverse DNS/mDNS medium; SSDP
  `friendlyName` medium; TLS CN and web `<title>` low). Vendor confidence should
  distinguish an OUI hit from a locally administered/unknown MAC
  (`is_locally_administered`).
- Surface it: add `Source` and `Confidence` to `TABLE.HEADERS`, and log the
  winning source alongside the name. Keep the full per-source attempt log at
  debug level for auditing rather than bloating the table.
- Never let a low-confidence source override a higher-confidence one, even if it
  resolves first.

### C. Metadata capture

The SSDP parser already reads `friendlyName`, `modelName`, and `manufacturer`
but collapses them to one string (`ssdp.py:34`). Return a record so `model` and
`manufacturer` can fill optional columns even when the name came from another
source, and carry the same source/confidence treatment from B. Feeds the goal's
"model, services, OS hints" without forcing a name.

### D. Read-only and LAN-scoped guardrails

- Assert every probed IP belongs to the scanned subnet before sending; extend
  the membership filter already used for passive MACs (`main.py:47`).
- Stay read-only: no SNMP `set`, no UPnP actions, no credential attempts.
- Device naming must never leave the LAN; the explicit `8.8.8.8` use is only for
  local-IP detection and should stay that way.
- Cap concurrency and retries so probes cannot accidentally flood the segment,
  and add a regression test that a resolver is skipped for out-of-subnet IPs.
