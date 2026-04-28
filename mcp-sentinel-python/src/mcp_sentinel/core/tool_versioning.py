"""
Tool definition versioning helpers for MCP config files.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from mcp_sentinel.models.vulnerability import (
    Confidence,
    Severity,
    Vulnerability,
    VulnerabilityType,
)

DEFAULT_TOOL_BASELINE_FILENAME = ".mcp-sentinel-tool-baseline.json"

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
    if name == DEFAULT_TOOL_BASELINE_FILENAME:
        return False
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


def resolve_tool_baseline_path(
    target_path: str | Path, baseline_path: str | Path | None
) -> Path:
    """Resolve the baseline file path from optional override."""
    if baseline_path:
        return Path(baseline_path)
    return Path(target_path) / DEFAULT_TOOL_BASELINE_FILENAME


def load_tool_definition_baseline(baseline_path: str | Path) -> dict[str, Any] | None:
    """Load a previously saved tool-definition baseline metadata blob."""
    path = Path(baseline_path)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    if isinstance(data, dict) and isinstance(data.get("tool_definition_fingerprint"), str):
        return data
    if isinstance(data, dict) and isinstance(data.get("metadata"), dict):
        nested = data["metadata"]
        if isinstance(nested.get("tool_definition_fingerprint"), str):
            return nested
    return None


def save_tool_definition_baseline(
    baseline_path: str | Path, metadata: dict[str, Any]
) -> None:
    """Persist tool-definition metadata to a baseline file."""
    path = Path(baseline_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "metadata": metadata,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def diff_tool_definition_metadata(
    baseline: dict[str, Any], current: dict[str, Any]
) -> dict[str, Any]:
    """Compute added/removed/changed MCP server definitions between two metadata snapshots."""
    base_records = baseline.get("tool_definition_fingerprints") or []
    cur_records = current.get("tool_definition_fingerprints") or []
    if not isinstance(base_records, list) or not isinstance(cur_records, list):
        return {"added": [], "removed": [], "changed": [], "has_changes": False}

    def key_of(record: dict[str, Any]) -> str:
        return f"{record.get('source_file')}::{record.get('server_name')}"

    base_map = {key_of(r): r for r in base_records if isinstance(r, dict)}
    cur_map = {key_of(r): r for r in cur_records if isinstance(r, dict)}

    added = [cur_map[k] for k in sorted(cur_map.keys() - base_map.keys())]
    removed = [base_map[k] for k in sorted(base_map.keys() - cur_map.keys())]
    changed = []
    for key in sorted(base_map.keys() & cur_map.keys()):
        before = base_map[key]
        after = cur_map[key]
        if before.get("server_fingerprint") != after.get("server_fingerprint"):
            changed.append({"before": before, "after": after})

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "has_changes": bool(added or removed or changed),
    }


def build_tool_definition_change_findings(
    diff: dict[str, Any], *, engine_name: str
) -> list[Vulnerability]:
    """Convert tool-definition diff records into vulnerability findings."""
    findings: list[Vulnerability] = []

    for record in diff.get("removed", []):
        if not isinstance(record, dict):
            continue
        server_name = str(record.get("server_name", "unknown"))
        file_path = str(record.get("source_file", "unknown"))
        findings.append(
            Vulnerability(
                type=VulnerabilityType.CONFIG_SECURITY,
                title=f"MCP tool definition removed: {server_name}",
                description=(
                    "A previously baselined MCP server/tool definition is missing. "
                    "Review whether this was expected or a silent configuration mutation."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                file_path=file_path,
                line_number=1,
                cwe_id="CWE-353",
                remediation=(
                    "Verify the config change in code review; re-baseline only after "
                    "confirming the removal is intentional."
                ),
                metadata={
                    "change_type": "removed",
                    "server_name": server_name,
                    "baseline_record": record,
                },
                detector="ToolDefinitionVersioning",
                engine=engine_name,
            )
        )

    for pair in diff.get("changed", []):
        if not isinstance(pair, dict):
            continue
        before = pair.get("before") if isinstance(pair.get("before"), dict) else {}
        after = pair.get("after") if isinstance(pair.get("after"), dict) else {}
        server_name = str(after.get("server_name") or before.get("server_name") or "unknown")
        file_path = str(after.get("source_file") or before.get("source_file") or "unknown")
        findings.append(
            Vulnerability(
                type=VulnerabilityType.CONFIG_SECURITY,
                title=f"MCP tool definition changed: {server_name}",
                description=(
                    "The MCP server/tool definition differs from baseline "
                    "(command/args/url/env/tools). Review for silent redefinition risk."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                file_path=file_path,
                line_number=1,
                cwe_id="CWE-353",
                remediation=(
                    "Inspect config diffs and approvals; re-baseline only after "
                    "verifying change intent and trust."
                ),
                metadata={
                    "change_type": "changed",
                    "server_name": server_name,
                    "before": before,
                    "after": after,
                },
                detector="ToolDefinitionVersioning",
                engine=engine_name,
            )
        )

    for record in diff.get("added", []):
        if not isinstance(record, dict):
            continue
        server_name = str(record.get("server_name", "unknown"))
        file_path = str(record.get("source_file", "unknown"))
        findings.append(
            Vulnerability(
                type=VulnerabilityType.CONFIG_SECURITY,
                title=f"New MCP tool definition added: {server_name}",
                description=(
                    "A new MCP server/tool definition appeared since baseline. "
                    "Confirm ownership, permissions, and trust before rollout."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                file_path=file_path,
                line_number=1,
                cwe_id="CWE-829",
                remediation=(
                    "Review the new server source and permissions, then update baseline "
                    "if approved."
                ),
                metadata={
                    "change_type": "added",
                    "server_name": server_name,
                    "current_record": record,
                },
                detector="ToolDefinitionVersioning",
                engine=engine_name,
            )
        )

    return findings
