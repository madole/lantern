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

scan:
    sudo uv run python -m lantern.main