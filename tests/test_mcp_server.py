import asyncio
import json

from mcp import Client

import lantern.mcp_server as mcp_server


def _call(tool, arguments):
    """Call one MCP tool in-memory and return its result."""

    async def run():
        async with Client(mcp_server.mcp) as client:
            return await client.call_tool(tool, arguments)

    return asyncio.run(run())


def _payload(result):
    """Decode a tool result's JSON text content into a dict."""
    return json.loads(result.content[0].text)


def test_network_info_reports_local_subnet(monkeypatch):
    monkeypatch.setattr(mcp_server, "get_local_ip", lambda: "192.168.1.50")
    monkeypatch.setattr(mcp_server, "default_scan_range", lambda: "192.168.1.50/24")

    payload = _payload(_call("network_info", {}))

    assert payload == {
        "local_ip": "192.168.1.50",
        "prefix_length": 24,
        "default_range": "192.168.1.50/24",
    }


def test_scan_defaults_to_local_range(monkeypatch):
    seen = []

    def fake_run_scan(ip_range):
        seen.append(ip_range)
        return {"range": ip_range, "device_count": 0, "devices": [], "summary": {}}

    monkeypatch.setattr(mcp_server, "run_scan", fake_run_scan)
    monkeypatch.setattr(mcp_server, "default_scan_range", lambda: "192.168.1.50/24")

    payload = _payload(_call("scan", {}))

    assert seen == ["192.168.1.50/24"]
    assert payload["range"] == "192.168.1.50/24"


def test_scan_forwards_explicit_range(monkeypatch):
    seen = []

    def fake_run_scan(ip_range):
        seen.append(ip_range)
        return {"range": ip_range}

    monkeypatch.setattr(mcp_server, "run_scan", fake_run_scan)
    monkeypatch.setattr(mcp_server, "default_scan_range", lambda: "unused")

    _call("scan", {"ip_range": "10.0.0.0/24"})

    assert seen == ["10.0.0.0/24"]


def test_server_exposes_expected_tools():
    async def run():
        async with Client(mcp_server.mcp) as client:
            return await client.list_tools()

    tools = asyncio.run(run())
    assert {tool.name for tool in tools.tools} == {"network_info", "scan"}
