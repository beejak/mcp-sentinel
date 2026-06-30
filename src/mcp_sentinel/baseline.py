"""
MCP Tool Definition Baseline — fingerprint tool schemas for rug-pull detection.

Extracts tool definitions from MCP server files, hashes each tool's
name + description + inputSchema, and persists a baseline. Subsequent runs
compare the current definitions against the baseline to detect ADDED, REMOVED,
and MODIFIED tools — the primary indicator of a rug pull attack.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_BASELINE_VERSION = "1"

# Matches JSON "tools" arrays (MCP server configs / schema files)
_JSON_TOOL_NAME = re.compile(r'"name"\s*:\s*"([^"]+)"')
_JSON_TOOL_DESC = re.compile(r'"description"\s*:\s*"([^"]*)"')

# Python @tool / @mcp.tool decorated functions with docstrings
_PY_DECORATED = re.compile(
    r"@(?:mcp\.)?tool\s*(?:\([^)]*\))?\s*\n\s*(?:async\s+)?def\s+(\w+)\s*\([^)]*\)\s*:\s*\n"
    r'\s*"""(.*?)"""',
    re.DOTALL,
)


def _fingerprint(name: str, description: str, schema: dict | None = None) -> str:
    """Return SHA-256 of the canonical JSON representation of a tool definition."""
    canonical = json.dumps(
        {"name": name, "description": description.strip(), "inputSchema": schema or {}},
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------


def _tools_from_json_data(data: Any, file_path: str) -> list[dict[str, Any]]:
    tools = []
    tool_list: list | None = None

    if isinstance(data, list):
        tool_list = data
    elif isinstance(data, dict):
        tool_list = data.get("tools") or data.get("Tools")

    if not tool_list:
        return tools

    for item in tool_list:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or item.get("Name")
        if not name:
            continue
        description = item.get("description") or item.get("Description") or ""
        schema = item.get("inputSchema") or item.get("input_schema") or {}
        tools.append(
            {
                "name": name,
                "description": description,
                "inputSchema": schema,
                "source_file": file_path,
                "fingerprint": _fingerprint(name, description, schema),
            }
        )
    return tools


def extract_tools_from_json(content: str, file_path: str) -> list[dict[str, Any]]:
    """Extract tool definitions from a JSON (or JSON-like) MCP config file."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return []
    return _tools_from_json_data(data, file_path)


def extract_tools_from_python(content: str, file_path: str) -> list[dict[str, Any]]:
    """Extract @tool-decorated functions from Python MCP server source files."""
    tools = []
    for match in _PY_DECORATED.finditer(content):
        name = match.group(1)
        description = match.group(2).strip()
        tools.append(
            {
                "name": name,
                "description": description,
                "inputSchema": {},
                "source_file": file_path,
                "fingerprint": _fingerprint(name, description, None),
            }
        )
    return tools


def extract_tools(target: Path) -> list[dict[str, Any]]:
    """Walk *target* and return all detected MCP tool definitions."""
    all_tools: list[dict[str, Any]] = []

    if target.is_file():
        files = [target]
    else:
        files = [
            p
            for p in target.rglob("*")
            if p.is_file() and p.suffix.lower() in {".json", ".py", ".yaml", ".yml"}
        ]

    for file_path in files:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        suffix = file_path.suffix.lower()
        if suffix == ".py":
            all_tools.extend(extract_tools_from_python(content, str(file_path)))
        elif suffix in (".json", ".yaml", ".yml"):
            all_tools.extend(extract_tools_from_json(content, str(file_path)))

    # Deduplicate by (name, source_file) keeping first occurrence
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []
    for t in all_tools:
        key = (t["name"], t["source_file"])
        if key not in seen:
            seen.add(key)
            unique.append(t)

    return unique


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def load_baseline(baseline_file: Path) -> dict[str, Any] | None:
    """Load an existing baseline; return None if absent or unreadable."""
    if not baseline_file.exists():
        return None
    try:
        return json.loads(baseline_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def save_baseline(
    tools: list[dict[str, Any]], target: str, baseline_file: Path
) -> None:
    """Persist a tool definition baseline to *baseline_file*."""
    payload: dict[str, Any] = {
        "version": _BASELINE_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "tools": tools,
    }
    baseline_file.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Diffing
# ---------------------------------------------------------------------------


def diff_baseline(
    current: list[dict[str, Any]],
    baseline: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """
    Compare *current* tool definitions against *baseline*.

    Returns a dict with keys:
        "added"    — tools present now but not in the baseline
        "removed"  — tools in the baseline but no longer present
        "modified" — tools present in both but with a different fingerprint
                     (each entry is {"current": ..., "baseline": ...})
    """
    current_map = {(t["name"], t["source_file"]): t for t in current}
    baseline_map = {(t["name"], t["source_file"]): t for t in baseline}

    added = [current_map[k] for k in current_map if k not in baseline_map]
    removed = [baseline_map[k] for k in baseline_map if k not in current_map]
    modified = [
        {"current": current_map[k], "baseline": baseline_map[k]}
        for k in current_map
        if k in baseline_map
        and current_map[k]["fingerprint"] != baseline_map[k]["fingerprint"]
    ]

    return {"added": added, "removed": removed, "modified": modified}
