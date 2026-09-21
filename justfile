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

# Run a scan with the OUI vendor-list download enabled; SNMP/TLS knobs pass through
scan:
    sudo env LANTERN_OUI_DOWNLOAD=1 LANTERN_SNMP_COMMUNITY="${LANTERN_SNMP_COMMUNITY:-public}" LANTERN_TLS_VERIFY="${LANTERN_TLS_VERIFY:-}" uv run python -m lantern.main