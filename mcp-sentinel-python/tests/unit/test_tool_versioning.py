"""Tests for MCP tool definition versioning metadata."""

from pathlib import Path

import pytest

from mcp_sentinel.core.scanner import Scanner
from mcp_sentinel.core.tool_versioning import (
    DEFAULT_TOOL_BASELINE_FILENAME,
    build_tool_definition_change_findings,
    build_tool_definition_metadata,
    diff_tool_definition_metadata,
)


def test_tool_definition_fingerprint_stable_for_reordered_servers(tmp_path: Path):
    config_a = tmp_path / "mcp.json"
    config_a.write_text(
        """
{
  "mcpServers": {
    "beta": {"command": "node", "args": ["b.js"]},
    "alpha": {"command": "node", "args": ["a.js"]}
  }
}
""".strip(),
        encoding="utf-8",
    )

    first = build_tool_definition_metadata(tmp_path)

    config_a.write_text(
        """
{
  "mcpServers": {
    "alpha": {"command": "node", "args": ["a.js"]},
    "beta": {"command": "node", "args": ["b.js"]}
  }
}
""".strip(),
        encoding="utf-8",
    )
    second = build_tool_definition_metadata(tmp_path)

    assert first["tool_definition_fingerprint"] == second["tool_definition_fingerprint"]
    assert first["tool_definition_server_count"] == 2


def test_tool_definition_fingerprint_changes_on_server_mutation(tmp_path: Path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        """
{
  "mcpServers": {
    "alpha": {"command": "node", "args": ["server.js"]}
  }
}
""".strip(),
        encoding="utf-8",
    )
    baseline = build_tool_definition_metadata(tmp_path)

    cfg.write_text(
        """
{
  "mcpServers": {
    "alpha": {"command": "uvx", "args": ["server.js"]}
  }
}
""".strip(),
        encoding="utf-8",
    )
    changed = build_tool_definition_metadata(tmp_path)

    assert baseline["tool_definition_fingerprint"] != changed["tool_definition_fingerprint"]
    assert changed["tool_definition_fingerprints"][0]["command"] == "uvx"


@pytest.mark.asyncio
async def test_scanner_emits_tool_definition_metadata(temp_dir: Path):
    (temp_dir / "safe.py").write_text("print('ok')\n", encoding="utf-8")
    (temp_dir / "mcp.json").write_text(
        """
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
""".strip(),
        encoding="utf-8",
    )

    scanner = Scanner()
    result = await scanner.scan_directory(temp_dir)

    assert "tool_definition_fingerprint" in result.config
    assert result.config["tool_definition_server_count"] == 1
    assert result.config["tool_definition_fingerprints"][0]["server_name"] == "filesystem"


def test_diff_detects_added_removed_and_changed_servers():
    before = {
        "tool_definition_fingerprints": [
            {
                "source_file": "mcp.json",
                "server_name": "alpha",
                "server_fingerprint": "aaa",
            },
            {
                "source_file": "mcp.json",
                "server_name": "beta",
                "server_fingerprint": "bbb",
            },
        ]
    }
    after = {
        "tool_definition_fingerprints": [
            {
                "source_file": "mcp.json",
                "server_name": "beta",
                "server_fingerprint": "changed-b",
            },
            {
                "source_file": "mcp.json",
                "server_name": "gamma",
                "server_fingerprint": "ggg",
            },
        ]
    }
    diff = diff_tool_definition_metadata(before, after)

    assert diff["has_changes"] is True
    assert len(diff["added"]) == 1
    assert len(diff["removed"]) == 1
    assert len(diff["changed"]) == 1

    findings = build_tool_definition_change_findings(diff, engine_name="static")
    titles = [f.title for f in findings]
    assert any("removed" in t for t in titles)
    assert any("changed" in t for t in titles)
    assert any("added" in t for t in titles)


@pytest.mark.asyncio
async def test_scanner_baseline_update_and_change_alerts(temp_dir: Path):
    (temp_dir / "safe.py").write_text("print('ok')\n", encoding="utf-8")
    cfg = temp_dir / "mcp.json"
    cfg.write_text(
        """
{
  "mcpServers": {
    "filesystem": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "/tmp"]}
  }
}
""".strip(),
        encoding="utf-8",
    )
    scanner = Scanner()
    baseline = temp_dir / DEFAULT_TOOL_BASELINE_FILENAME

    first = await scanner.scan_directory(temp_dir, update_tool_baseline=True)
    assert baseline.exists()
    assert first.config.get("tool_definition_baseline_updated") is True

    cfg.write_text(
        """
{
  "mcpServers": {
    "filesystem": {"command": "uvx", "args": ["@modelcontextprotocol/server-filesystem", "/tmp"]}
  }
}
""".strip(),
        encoding="utf-8",
    )
    second = await scanner.scan_directory(temp_dir)
    versioning_vulns = [v for v in second.vulnerabilities if v.detector == "ToolDefinitionVersioning"]

    assert second.config["tool_definition_baseline_exists"] is True
    assert second.config["tool_definition_changes"]["changed"] == 1
    assert len(versioning_vulns) >= 1
