"""Discover MCP server entries from repo JSON configs for runtime probing."""

from __future__ import annotations

import json
from pathlib import Path

from mcp_sentinel.core.tool_versioning import (
    _IGNORE_DIRS,
    _extract_mcp_servers,
    _is_candidate_json_file,
)
from mcp_sentinel.probing.models import ProbeTarget


def discover_probe_targets(root: str | Path) -> list[ProbeTarget]:
    """
    Walk ``root`` for MCP client JSON files and extract probe-capable server entries.

    Prefer HTTP when ``url`` is set; otherwise stdio when ``command`` is set.
    """
    root_path = Path(root).resolve()
    out: list[ProbeTarget] = []

    for path in root_path.rglob("*.json"):
        if any(ignore in path.parts for ignore in _IGNORE_DIRS):
            continue
        if not _is_candidate_json_file(path):
            continue
        try:
            raw = path.read_text(encoding="utf-8", errors="ignore")
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError, ValueError):
            continue

        servers = _extract_mcp_servers(path, data)
        rel = str(path.relative_to(root_path))
        for server_name, server in sorted(servers.items()):
            if not isinstance(server, dict):
                continue
            url = server.get("url")
            if isinstance(url, str) and url.strip():
                out.append(
                    ProbeTarget(
                        server_name=server_name,
                        source_file=rel,
                        transport="http",
                        url=url.strip(),
                        headers=_headers_from_server(server),
                    )
                )
                continue
            cmd = server.get("command")
            if isinstance(cmd, str) and cmd.strip():
                args = server.get("args", [])
                arg_list = [str(a) for a in args] if isinstance(args, list) else []
                env: dict[str, str] | None = None
                if isinstance(server.get("env"), dict):
                    env = {str(k): str(v) for k, v in server["env"].items()}
                out.append(
                    ProbeTarget(
                        server_name=server_name,
                        source_file=rel,
                        transport="stdio",
                        command=cmd.strip(),
                        args=arg_list,
                        env=env,
                    )
                )
    return out


def _headers_from_server(server: dict) -> dict[str, str]:
    h = server.get("headers")
    if not isinstance(h, dict):
        return {}
    return {str(k): str(v) for k, v in h.items() if isinstance(v, str)}
