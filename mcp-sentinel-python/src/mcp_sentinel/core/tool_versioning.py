"""
Tool definition versioning helpers for MCP config files.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

_IGNORE_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
}


def _canonical_sha256(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _is_candidate_json_file(path: Path) -> bool:
    if path.suffix.lower() != ".json":
        return False
    name = path.name.lower()
    return (
        "mcp" in name
        or name in {"claude_desktop_config.json", "cursor_settings.json", "settings.json"}
    )


def _extract_mcp_servers(path: Path, data: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(data, dict):
        return {}

    if isinstance(data.get("mcpServers"), dict):
        return {
            str(k): v for k, v in data["mcpServers"].items() if isinstance(v, dict)  # type: ignore[index]
        }

    if isinstance(data.get("mcp_servers"), dict):
        return {
            str(k): v for k, v in data["mcp_servers"].items() if isinstance(v, dict)  # type: ignore[index]
        }

    # Some clients use top-level "servers" in dedicated MCP config files.
    if path.name.lower() in {"mcp.json", "claude_desktop_config.json"} and isinstance(
        data.get("servers"), dict
    ):
        return {
            str(k): v for k, v in data["servers"].items() if isinstance(v, dict)  # type: ignore[index]
        }

    return {}


def _build_server_record(source_file: Path, server_name: str, server: dict[str, Any]) -> dict[str, Any]:
    env = server.get("env")
    env_keys = sorted(str(k) for k in env.keys()) if isinstance(env, dict) else []

    tools = server.get("tools")
    tool_names: list[str] = []
    if isinstance(tools, list):
        tool_names = sorted(str(x) for x in tools if isinstance(x, str))
    elif isinstance(tools, dict):
        tool_names = sorted(str(k) for k in tools.keys())

    core = {
        "source_file": str(source_file),
        "server_name": server_name,
        "command": server.get("command"),
        "args": list(server.get("args", [])) if isinstance(server.get("args"), list) else [],
        "transport": server.get("transport"),
        "type": server.get("type"),
        "url": server.get("url"),
        "env_keys": env_keys,
        "tool_names": tool_names,
    }
    return {
        **core,
        "server_fingerprint": _canonical_sha256(core),
    }


def build_tool_definition_metadata(target_path: str | Path) -> dict[str, Any]:
    """
    Build deterministic metadata for MCP tool/server definitions in JSON config files.
    """
    root = Path(target_path)
    records: list[dict[str, Any]] = []
    scanned_candidates = 0

    for path in root.rglob("*.json"):
        if any(ignore in path.parts for ignore in _IGNORE_DIRS):
            continue
        if not _is_candidate_json_file(path):
            continue

        scanned_candidates += 1
        try:
            raw = path.read_text(encoding="utf-8", errors="ignore")
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError, ValueError):
            continue

        servers = _extract_mcp_servers(path, data)
        for server_name, server_config in sorted(servers.items()):
            records.append(_build_server_record(path.relative_to(root), server_name, server_config))

    records.sort(key=lambda r: (r["source_file"], r["server_name"]))
    return {
        "tool_definition_files_scanned": scanned_candidates,
        "tool_definition_server_count": len(records),
        "tool_definition_fingerprints": records,
        "tool_definition_fingerprint": _canonical_sha256(records),
    }
