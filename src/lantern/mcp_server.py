"""MCP server exposing lantern's scan over stdio.

An MCP host launches this server as a subprocess and calls its tools. The scan
needs raw sockets, so run the server as root::

    sudo uv run python -m lantern.mcp_server

Tools return JSON so a host's model can reason about the results and add its
own insight. The MCP protocol runs on stdout, so nothing on the scan path may
print there; ``run_scan`` does no printing and all logging already goes to
stderr.
"""

from mcp.server import MCPServer

from lantern.constants import NETWORK
from lantern.main import default_scan_range, get_local_ip, run_scan

mcp = MCPServer(
    "lantern",
    instructions=(
        "Identify and name every device on the local network. Call network_info "
        "to learn which subnet to scan, then scan to run a read-only LAN scan "
        "and get per-device records and a summary as JSON."
    ),
)


@mcp.tool()
def network_info() -> dict:
    """Return this machine's local IP and the subnet lantern would scan."""
    local_ip = get_local_ip()
    return {
        "local_ip": local_ip,
        "prefix_length": NETWORK.DEFAULT_PREFIX_LENGTH,
        "default_range": default_scan_range(),
    }


@mcp.tool()
def scan(ip_range: str | None = None) -> dict:
    """Run a read-only scan of the LAN and return the results as JSON.

    Scans every host on ``ip_range`` (a CIDR such as ``192.168.1.0/24``), or the
    /24 around this machine's local IP when omitted. The result holds per-device
    records (``ip``, ``mac``, ``name``, ``vendor``, ``details``, ``metadata``)
    and a ``summary`` (counts, vendors, device classes, anomalies, security
    findings). The scan is read-only and confined to the subnet, and can take
    10-40 seconds while it listens for self-announcements. Requires root.
    """
    return run_scan(ip_range or default_scan_range())


def main() -> None:
    """Run the MCP server.

    Speaks stdio by default. Set ``LANTERN_MCP_TRANSPORT=http`` to serve
    streamable HTTP instead, so a host can attach to an already-running (root)
    server rather than spawning its own. Host and port come from
    ``LANTERN_MCP_HOST`` / ``LANTERN_MCP_PORT``.
    """
    import os

    if os.environ.get("LANTERN_MCP_TRANSPORT") == "http":
        mcp.run(
            transport="streamable-http",
            host=os.environ.get("LANTERN_MCP_HOST", "127.0.0.1"),
            port=int(os.environ.get("LANTERN_MCP_PORT", "8765")),
        )
    else:
        mcp.run()


if __name__ == "__main__":
    main()
