# lantern

Identify and name every device on your local network.

`lantern` ARP-scans your LAN while passively listening for self-announcements,
then works through a dozen name sources to turn anonymous IP/MAC pairs into
human-readable names. Vendor is resolved from the MAC OUI.

## What it does

- **Discovers** hosts with an ARP scan and a parallel passive listener
  (ARP, DHCP, mDNS, SSDP, LLMNR).
- **Identifies** each host via a priority-ordered chain of name sources,
  falling back to `Unknown` only when every source comes up empty.
- **Reports** a `grid` table of `IP | MAC | Name | Vendor` on stdout, with
  verbose progress on stderr.

## How it identifies devices

Sources run concurrently and the highest-priority non-empty name wins. The
slow, low-yield probes are *deferred* and only start when every fast source
has failed, so a device named quickly never pays for them.

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
download (see [Configuration](#configuration)); the direct command leaves it off.

`lantern` auto-detects your local address and scans the `/24` around it. The
results table is written to stdout; logs go to stderr.

```text
+-------------+-------------------+------------------+------------------+
| IP          | MAC               | Name             | Vendor           |
+=============+===================+==================+==================+
| 192.168.1.1 | aa:bb:cc:dd:ee:01 | router.lan       | Netgear, Inc     |
| 192.168.1.4 | aa:bb:cc:dd:ee:04 | Living Room TV   | Samsung Electro  |
| 192.168.1.9 | aa:bb:cc:dd:ee:09 | Office Printer   | HP Inc.          |
| 192.168.1.7 | aa:bb:cc:dd:ee:07 | Unknown          | Espressif Inc.   |
+-------------+-------------------+------------------+------------------+
```

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
  [`src/lantern/constants.py`](src/lantern/constants.py).
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

- **Read-only**: only SNMP `GET`, SSDP `M-SEARCH`, and HTTP/TLS reads — no
  SNMP `set`, no UPnP actions, no credential attempts. Each probe passes through
  `scope.require_read_only` and the wire format is asserted in the tests.
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
