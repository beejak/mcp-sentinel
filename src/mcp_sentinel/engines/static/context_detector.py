"""
MCP server context detector.

Inspects the target directory for MCP configuration files and infers
context signals (filesystem access, network access, STDIO transport)
that can be used to calibrate vulnerability severity.

Supported config locations (in priority order):
  mcp.json
  .mcp/config.json
  package.json  (looks for "mcp" key or "@modelcontextprotocol/sdk" dep)
  pyproject.toml (looks for "mcp" in dependencies)
  Any *.json with "mcpServers" or "transport" keys
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Tool name/description keywords that imply filesystem access
_FS_KEYWORDS = frozenset(
    [
        "file",
        "filesystem",
        "read_file",
        "write_file",
        "readfile",
        "writefile",
        "ls",
        "glob",
        "directory",
        "folder",
        "path",
        "disk",
    ]
)

# Tool name/description keywords that imply network access
_NET_KEYWORDS = frozenset(
    [
        "fetch",
        "http",
        "https",
        "request",
        "curl",
        "browse",
        "web",
        "url",
        "download",
        "upload",
        "webhook",
        "api",
    ]
)

# Keywords in tool descriptions that indicate high-privilege / destructive ops
_SENSITIVE_OP_KEYWORDS = frozenset(
    [
        "rm",
        "delete",
        "execute",
        "shell",
        "sudo",
        "chmod",
        "chown",
        "format",
        "wipe",
        "drop",
        "truncate",
    ]
)


@dataclass
class MCPContext:
    """
    Signals inferred from MCP server configuration files.

    All fields default to False / empty so the calibrator degrades gracefully
    when no config files are found.
    """

    has_filesystem_access: bool = False
    has_network_access: bool = False
    is_stdio_transport: bool = False
    sensitive_tool_names: list[str] = field(default_factory=list)
    config_files_found: list[str] = field(default_factory=list)


def detect_mcp_context(target_path: Path) -> MCPContext:
    """
    Walk *target_path* looking for MCP configuration files and return an
    :class:`MCPContext` populated with whatever signals can be extracted.

    The function never raises — any parsing error is logged and skipped.
    """
    ctx = MCPContext()

    candidates = _find_candidate_files(target_path)

    for cfg_file in candidates:
        try:
            _parse_file(cfg_file, ctx)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Context detection: could not parse %s: %s", cfg_file, exc)

    return ctx


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _find_candidate_files(root: Path) -> list[Path]:
    """Return config files to inspect, ordered by priority."""
    priority: list[Path] = []
    fallback: list[Path] = []

    for name in ("mcp.json", "mcp_config.json"):
        p = root / name
        if p.is_file():
            priority.append(p)

    mcp_dir = root / ".mcp" / "config.json"
    if mcp_dir.is_file():
        priority.append(mcp_dir)

    for name in ("package.json", "pyproject.toml"):
        p = root / name
        if p.is_file():
            priority.append(p)

    # Scan up to 20 additional JSON files in the root (not recursive)
    for p in sorted(root.glob("*.json")):
        if p not in priority:
            fallback.append(p)

    return priority + fallback[:20]


def _parse_file(path: Path, ctx: MCPContext) -> None:
    """Extract context signals from a single config file."""
    suffix = path.suffix.lower()

    if suffix == ".json":
        _parse_json(path, ctx)
    elif suffix == ".toml":
        _parse_toml(path, ctx)


def _parse_json(path: Path, ctx: MCPContext) -> None:
    """Parse a JSON config file for MCP context signals."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return

    if not isinstance(data, dict):
        return

    # Only process files that look MCP-related
    if not _looks_like_mcp_config(data):
        return

    ctx.config_files_found.append(str(path))

    _extract_transport(data, ctx)
    _extract_tools(data, ctx)

    # package.json: check dependencies for @modelcontextprotocol/sdk
    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    if any("modelcontextprotocol" in k.lower() for k in deps):
        ctx.config_files_found.append(str(path))  # confirm MCP project

    # Recurse into "mcpServers" map values
    mcp_servers = data.get("mcpServers", {})
    if isinstance(mcp_servers, dict):
        for server_cfg in mcp_servers.values():
            if isinstance(server_cfg, dict):
                _extract_transport(server_cfg, ctx)


def _parse_toml(path: Path, ctx: MCPContext) -> None:
    """Parse pyproject.toml for MCP dependency signals."""
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return

    # Lightweight check — no need for a full TOML parser here
    if "mcp" not in content.lower():
        return

    ctx.config_files_found.append(str(path))

    # If the server uses STDIO transport it's very common to declare it here
    if "stdio" in content.lower():
        ctx.is_stdio_transport = True


def _looks_like_mcp_config(data: dict) -> bool:
    """Return True if the JSON object contains MCP-related keys."""
    mcp_keys = {"mcpServers", "mcp", "transport", "tools", "resources", "prompts"}
    return bool(mcp_keys.intersection(data.keys()))


def _extract_transport(data: dict, ctx: MCPContext) -> None:
    """Check 'transport' key for stdio/sse signals."""
    transport = data.get("transport", "")
    if isinstance(transport, str) and "stdio" in transport.lower():
        ctx.is_stdio_transport = True
    if isinstance(transport, dict):
        t_type = transport.get("type", "")
        if isinstance(t_type, str) and "stdio" in t_type.lower():
            ctx.is_stdio_transport = True


def _extract_tools(data: dict, ctx: MCPContext) -> None:
    """Scan tool names and descriptions for capability signals."""
    tools = data.get("tools", [])
    if isinstance(tools, dict):
        tools = list(tools.values())

    if not isinstance(tools, list):
        return

    for tool in tools:
        if not isinstance(tool, dict):
            continue

        name = str(tool.get("name", "")).lower()
        description = str(tool.get("description", "")).lower()
        combined = f"{name} {description}"

        if any(kw in combined for kw in _FS_KEYWORDS):
            ctx.has_filesystem_access = True

        if any(kw in combined for kw in _NET_KEYWORDS):
            ctx.has_network_access = True

        if any(kw in combined for kw in _SENSITIVE_OP_KEYWORDS):
            original_name = str(tool.get("name", ""))
            if original_name not in ctx.sensitive_tool_names:
                ctx.sensitive_tool_names.append(original_name)
