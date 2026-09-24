# lantern

Identify and name every device on your local network.

`lantern` ARP-scans your LAN while passively listening for self-announcements,
then works through a dozen name sources to turn anonymous IP/MAC pairs into
human-readable names. Vendor is resolved from the MAC OUI.

## What it does

- **Discovers** hosts with an ARP scan and a parallel passive listener
  (ARP, DHCP, mDNS, SSDP, LLMNR) whose listening window closes early once the
  wire goes quiet.
- **Identifies** each host via a priority-ordered chain of name sources,
  falling back to `Unknown` only when every source comes up empty. The mDNS
  browse first asks the meta-query which service types the LAN advertises, then
  browses any it did not already know, so unusual stacks (Xiaomi/Yeelight,
  HomeKit, Daikin, Google Nearby) are found without a hardcoded list.
- **Reports** a `grid` table of `IP | MAC | Name | Vendor | Details` on stdout,
  with verbose progress on stderr. `Details` carries any extra metadata a probe
  learned (model, OS hint, server, exposed services) without affecting the name.
- **Inspects** each in-scope host with a bounded, read-only TCP port probe, then
  logs a scan summary: device classes, vendor mix, IP/MAC anomalies, and
  security signals (risky open ports, default-community SNMP). A web server that
  answers but never names itself is recorded as an `appliance` hint, so a bare
  embedded stack is classified as `appliance` rather than `unknown`.

## How it identifies devices

Sources run concurrently and the highest-priority non-empty name wins. The
slow, low-yield probes are *deferred* and only start when every fast source
has failed, so a device named quickly never pays for them. Set
`LANTERN_FULL_MATRIX=1` to disable the early exit and run every source in a tier
to completion, recording the full set of protocols that answered
(`responded`).

| # | Source | Notes |
| --- | --- | --- |
| 0 | passive | Self-announced names heard on the wire |
| 1 | hostname | Reverse DNS (PTR) |
| 2 | router DNS | Default gateway as a second resolver |
| 3 | mDNS | Reverse PTR |
| 4 | SSDP / UPnP | `friendlyName` / `modelName` |
| 5 | mDNS services | AirPlay, Chromecast, printers, ... |
| 6 | NetBIOS | UDP/137 |
| 7 | LLMNR | UDP/5355 |
| 8 | SNMP | `sysName` / `sysDescr` |
| 9 | TLS certificate | CN/SAN — *deferred* |
| 10 | web title | HTTP(S) `<title>` — *deferred* |
| 11 | service banner | SSH, SMB, ... — *deferred* |

A per-device deadline caps total lookup time. Broadcast and multicast sources
are resolved once per scan, not once per host. See
[docs/concurrency.md](docs/concurrency.md) for the full design.

## Requirements

- Linux or macOS (raw sockets via [scapy](https://scapy.net/))
- Python 3.12+
- `root` / `sudo` for ARP and multicast
- A multicast-capable LAN

## Install

```sh
uv sync
```

## Usage

```sh
just scan
```

or directly:

```sh
sudo uv run python -m lantern.main
```

`just scan` runs the same scan but opts into the one-time OUI vendor-list
download (see [Configuration](#configuration)) and waits 10s (instead of the
default 3s) for the wire to go quiet before closing the passive window. The
direct command leaves both at their defaults; override the window with
`LANTERN_PASSIVE_QUIET_PERIOD`.

`lantern` auto-detects your local address and scans the `/24` around it. The
results table is written to stdout; logs go to stderr. Pass `--range` to scan a
different subnet, or `--json` to print the full structured result instead of the
table.

```text
+-------------+-------------------+------------------+------------------+-----------------------------+
| IP          | MAC               | Name             | Vendor           | Details                     |
+=============+===================+==================+==================+=============================+
| 192.168.1.1 | aa:bb:cc:dd:ee:01 | router.lan       | Netgear, Inc     | server=nginx/1.24.0         |
| 192.168.1.4 | aa:bb:cc:dd:ee:04 | Living Room TV   | Samsung Electro  | model=UE55, os=Tizen        |
| 192.168.1.9 | aa:bb:cc:dd:ee:09 | Office Printer   | HP Inc.          | server=HP HTTP Server       |
| 192.168.1.7 | aa:bb:cc:dd:ee:07 | Unknown          | Espressif Inc.   | vendor_class=ESP32          |
+-------------+-------------------+------------------+------------------+-----------------------------+
```

## MCP server

`lantern` ships an [MCP](https://modelcontextprotocol.io) server so an AI host
can run a scan and get the results as JSON to reason over. It speaks MCP over
**stdio** and exposes two tools:

- `network_info` — this machine's local IP and the subnet lantern would scan.
- `scan(ip_range?)` — run a read-only, LAN-scoped scan and return JSON. Defaults
  to the /24 around the local IP. A scan can take 10–40 seconds while it listens
  for self-announcements.

The result is a JSON object with the per-device records and the scan summary:

```json
{
  "range": "192.168.1.0/24",
  "elapsed_seconds": 12.4,
  "device_count": 4,
  "devices": [
    {
      "ip": "192.168.1.1",
      "mac": "aa:bb:cc:dd:ee:01",
      "name": "router.lan",
      "vendor": "Netgear, Inc",
      "details": "server=nginx/1.24.0",
      "metadata": {"server": "nginx/1.24.0", "open_ports": "80,443"}
    }
  ],
  "summary": {
    "total": 4,
    "named": 3,
    "unknown": 1,
    "randomized": 0,
    "vendors": [["Netgear, Inc", 1]],
    "device_classes": [["unix host", 1]],
    "anomalies": [],
    "security": ["192.168.1.1 exposes rdp(3389)"],
    "lines": ["Scan summary: 4 device(s), 3 named, 1 unknown, 0 randomized MAC(s)"]
  }
}
```

### Running it

The scan needs root for raw sockets, so the server must run as root. Start it
once, in a terminal where you can answer the `sudo` prompt, and leave it
running:

```sh
just mcp
# or
sudo env LANTERN_MCP_TRANSPORT=http uv run python -m lantern.mcp_server
```

It serves streamable HTTP on `http://127.0.0.1:8765/mcp`; override the bind with
`LANTERN_MCP_HOST` / `LANTERN_MCP_PORT`. Because the server outlives the host,
the host never launches a root process itself — it just connects to the URL.
(Set `LANTERN_MCP_TRANSPORT` to anything other than `http` to speak stdio
instead, e.g. `just mcp-stdio` when the host launches the server itself.)

### Host configuration

The repo ships [`.opencode/opencode.json`](.opencode/opencode.json), which
registers the already-running server as a remote endpoint and raises the
per-request timeout to 180s, since a scan is much slower than the 5s default:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "lantern": {
      "type": "remote",
      "url": "http://127.0.0.1:8765/mcp",
      "enabled": true,
      "timeout": 180000
    }
  }
}
```

Start the server with `just mcp` before launching the host; the host itself
needs no privileges.

Alternatively, let the host launch the server over stdio (no separate process),
which requires the launch command to run as root without a password prompt — run
the host as root, grant passwordless `sudo`, or on Linux give the interpreter
raw-socket capability
(`sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(which python)")"`).
For that, register a local server instead:

```json
{
  "mcp": {
    "lantern": {
      "type": "local",
      "command": ["sudo", "-E", "uv", "--directory", "/path/to/lantern", "run", "python", "-m", "lantern.mcp_server"],
      "enabled": true,
      "timeout": 180000,
      "environment": { "LANTERN_OUI_DOWNLOAD": "1" }
    }
  }
}
```

Example `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "lantern": {
      "type": "remote",
      "url": "http://127.0.0.1:8765/mcp"
    }
  }
}
```

Set `LANTERN_OUI_DOWNLOAD=1` (and `LANTERN_SNMP_COMMUNITY` / `LANTERN_TLS_VERIFY`)
in the server's environment to match the `just scan` defaults.

## Configuration

- `LOG_LEVEL` — sets log verbosity (default `DEBUG`).
- `LANTERN_SNMP_COMMUNITY` — read-only SNMP community string (default
  `public`). Set it empty to skip SNMP probing entirely.
- `LANTERN_TLS_VERIFY` — set to `1` to require a trusted TLS chain when reading
  certificate names. Off by default because device certificates are usually
  self-signed.
- `LANTERN_OUI_DOWNLOAD` — set to `1` to allow fetching the IEEE OUI vendor
  list. Off by default: only a pre-provisioned list at `~/.cache/mac-vendors.txt`
  is used, so a scan makes no unsolicited internet requests. The `just scan`
  recipe sets this for you; `LANTERN_SNMP_COMMUNITY` and `LANTERN_TLS_VERIFY`
  pass through it as well.
- All timeouts, ports, and concurrency limits live in
  [`src/lantern/constants.py`](src/lantern/constants.py). The timing and
  concurrency knobs are environment-overridable; a malformed or too-small value
  falls back to the built-in default.
  - `LANTERN_NAME_DEADLINE` — seconds per device across both tiers.
  - `LANTERN_FULL_MATRIX` — set to `1` to disable the name chain's early exit:
    every source in a tier runs to completion so the details column records the
    full set of protocols that answered (`responded`). Slower, still bounded by
    `LANTERN_NAME_DEADLINE`. Off by default; the deferred tier (TLS/web/banner)
    still only runs when the fast tier finds no name.
  - `LANTERN_NAME_MAX_DEVICE_WORKERS`, `LANTERN_NAME_MAX_WORKERS` — device and
    resolver pool sizes.
  - `LANTERN_NAME_PREFETCH_WORKERS` — threads for the scan-wide broadcast
    prefetch (mDNS vs SSDP).
  - `LANTERN_PASSIVE_TIMEOUT` — ceiling on the passive listening window.
  - `LANTERN_PASSIVE_QUIET_PERIOD`, `LANTERN_PASSIVE_MIN_WINDOW` — how long the
    listener waits for silence, and the floor before it may stop early.
  - `LANTERN_PASSIVE_POLL_INTERVAL` — how often it checks for silence.
  - `LANTERN_PASSIVE_MAX_FETCH_WORKERS`, `LANTERN_SSDP_MAX_FETCH_WORKERS` —
    concurrent SSDP description fetches.
- There are no CLI arguments yet; the scan range is derived from the local IP.

## Development

```sh
just check   # ruff lint + format-check + pytest
just test    # pytest only
just lint    # ruff check
just format  # ruff format
```

Layout: `src/lantern/` (package, `resolvers/` per protocol), `tests/`,
`docs/concurrency.md`, `intent.md`.

## Safety & limitations

- **Read-only**: SNMP `GET`, SSDP `M-SEARCH`, TCP connect port probes, and
  HTTP/TLS reads — no SNMP `set`, no UPnP actions, no credential attempts. Each
  probe passes through `scope.require_read_only` and the wire format is asserted
  in the tests.
- **LAN-scoped**: every active probe is checked against the scanned subnet
  (`scope.is_in_scope`); an out-of-subnet address is skipped rather than sent.
- **No unsolicited egress**: the tool does not reach the internet on its own.
  The OUI vendor list is only downloaded when `LANTERN_OUI_DOWNLOAD=1`, and SNMP
  can be disabled by clearing `LANTERN_SNMP_COMMUNITY`.
- **Untrusted names**: any value learned from a device is stripped of control
  and zero-width characters before it is logged or printed.
- Requires `root`; some devices never answer any probe and stay `Unknown`.
- Concurrent multicast sniffers can theoretically cross-talk, though every
  resolver filters replies by responder IP.
