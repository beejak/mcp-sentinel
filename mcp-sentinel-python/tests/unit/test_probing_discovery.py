"""MCP config discovery for dynamic probes."""

from __future__ import annotations

import json
from pathlib import Path

from mcp_sentinel.probing.discovery import discover_probe_targets


def test_discovers_stdio_from_mcp_servers(tmp_path: Path):
    (tmp_path / "mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "demo": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-foo"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    t = discover_probe_targets(tmp_path)
    assert len(t) == 1
    assert t[0].transport == "stdio"
    assert t[0].command == "npx"
    assert t[0].args[0] == "-y"


def test_prefers_http_when_url_set(tmp_path: Path):
    (tmp_path / "mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "remote": {
                        "url": "https://127.0.0.1:8080/mcp",
                        "command": "ignored",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    t = discover_probe_targets(tmp_path)
    assert len(t) == 1
    assert t[0].transport == "http"
    assert "8080" in t[0].url
