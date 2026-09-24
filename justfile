set shell := ["bash", "-uc"]

default:
    @just --list

# Run the linter
lint:
    uv run ruff check .

# Apply formatting
format:
    uv run ruff format .

# Check formatting without writing
format-check:
    uv run ruff format --check .

# Run the test suite
test *args:
    uv run pytest {{ args }}

# Run lint and tests
check: lint format-check test

# Run a scan with the OUI list enabled and a longer passive quiet window
scan:
    sudo env LANTERN_OUI_DOWNLOAD=1 LANTERN_SNMP_COMMUNITY="${LANTERN_SNMP_COMMUNITY:-public}" LANTERN_TLS_VERIFY="${LANTERN_TLS_VERIFY:-}" LANTERN_PASSIVE_QUIET_PERIOD="${LANTERN_PASSIVE_QUIET_PERIOD:-10}" uv run python -m lantern.main

# Run a scan and print the full result as JSON
scan-json:
    sudo env LANTERN_OUI_DOWNLOAD=1 LANTERN_SNMP_COMMUNITY="${LANTERN_SNMP_COMMUNITY:-public}" LANTERN_TLS_VERIFY="${LANTERN_TLS_VERIFY:-}" LANTERN_PASSIVE_QUIET_PERIOD="${LANTERN_PASSIVE_QUIET_PERIOD:-10}" uv run python -m lantern.main --json

# Run the MCP server over streamable HTTP (needs root for the ARP scan).
# Serves http://127.0.0.1:8765/mcp, matching the remote server registered in
# .opencode/opencode.json. Leave it running so the MCP host can attach to it.
mcp:
    sudo env LANTERN_MCP_TRANSPORT=http LANTERN_MCP_HOST="${LANTERN_MCP_HOST:-127.0.0.1}" LANTERN_MCP_PORT="${LANTERN_MCP_PORT:-8765}" LANTERN_OUI_DOWNLOAD=1 LANTERN_SNMP_COMMUNITY="${LANTERN_SNMP_COMMUNITY:-public}" LANTERN_TLS_VERIFY="${LANTERN_TLS_VERIFY:-}" LANTERN_PASSIVE_QUIET_PERIOD="${LANTERN_PASSIVE_QUIET_PERIOD:-10}" uv run python -m lantern.mcp_server

# Run the MCP server over stdio (needs root for the ARP scan).
# Use this only when the host launches the server itself; the registered
# .opencode/opencode.json uses the HTTP recipe above.
mcp-stdio:
    sudo env LANTERN_OUI_DOWNLOAD=1 LANTERN_SNMP_COMMUNITY="${LANTERN_SNMP_COMMUNITY:-public}" LANTERN_TLS_VERIFY="${LANTERN_TLS_VERIFY:-}" LANTERN_PASSIVE_QUIET_PERIOD="${LANTERN_PASSIVE_QUIET_PERIOD:-10}" uv run python -m lantern.mcp_server