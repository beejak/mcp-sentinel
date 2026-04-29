"""
Heuristic analysis of live MCP capability listings (tools, resources, prompts).

No LLM: pattern-based. Produces ``Vulnerability`` rows with engine ``dynamic``.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any

from mcp_sentinel.models.vulnerability import (
    Confidence,
    Severity,
    Vulnerability,
    VulnerabilityType,
)

# Suspicious when advertised on the wire (execution, network exfil, shells).
_CODE_EXEC_PATTERNS = re.compile(
    r"(?i)(eval|exec|execfile|subprocess|child_process|spawn|shell_exec|os\.system|"
    r"Process\.Start|child_process\.exec|bash|/bin/sh|cmd\.exe|powershell|"
    r"__import__|compile\()"
)
_NET_FETCH_PATTERNS = re.compile(
    r"(?i)(\burllib\b|\brequests\.|\bhttpx\.|\bfetch\(|XMLHttpRequest|curl\s|wget\s|"
    r"http://|https://|axios\.|node-fetch)"
)
_PATH_TRAVERSAL = re.compile(r"(?i)(\.\./|%2e%2e|%252e|\\\\\.\.)")
_SECRET_HINT = re.compile(
    r"(?i)(api[_-]?key|secret|password|token|bearer|authorization|BEGIN RSA PRIVATE)"
)


def _dyn_location(transport: str, server_name: str, suffix: str = "") -> str:
    base = f"dynamic://{transport}/{server_name}"
    return f"{base}{suffix}"


def analyze_live_surface(
    *,
    transport: str,
    server_name: str,
    tools: list[Any],
    resources: list[Any],
    prompts: list[Any],
) -> list[Vulnerability]:
    """Turn MCP SDK model instances into vulnerability findings."""
    findings: list[Vulnerability] = []

    findings.extend(_analyze_tools(transport, server_name, tools))
    findings.extend(_analyze_resources(transport, server_name, resources))
    findings.extend(_analyze_prompts(transport, server_name, prompts))

    if len(tools) > 80:
        findings.append(
            _v(
                VulnerabilityType.CONFIG_SECURITY,
                Severity.MEDIUM,
                "Large advertised tool surface",
                f"The server exposes {len(tools)} tools — broad surfaces increase prompt injection "
                "and abuse risk; review whether all tools are required.",
                transport,
                server_name,
                "Reduce exposed tools; gate risky tools behind auth.",
            )
        )

    return findings


def _analyze_tools(transport: str, server_name: str, tools: list[Any]) -> list[Vulnerability]:
    out: list[Vulnerability] = []
    for tool in tools:
        name = getattr(tool, "name", "") or ""
        desc = getattr(tool, "description", None) or ""
        schema = getattr(tool, "inputSchema", None)
        blob = f"{name}\n{desc}\n{_schema_blob(schema)}"

        if _CODE_EXEC_PATTERNS.search(blob):
            out.append(
                _v(
                    VulnerabilityType.CODE_INJECTION,
                    Severity.HIGH,
                    f"Dynamic probe: code/exec surface in tool “{name}”",
                    "Tool name/description/schema suggests arbitrary execution or script invocation.",
                    transport,
                    server_name,
                    "Validate sinks; restrict tool inputs; avoid passing user text to exec.",
                    title_suffix=name[:48],
                )
            )
        if _NET_FETCH_PATTERNS.search(blob):
            out.append(
                _v(
                    VulnerabilityType.CONFIG_SECURITY,
                    Severity.MEDIUM,
                    f"Dynamic probe: network or HTTP capability in tool “{name}”",
                    "Advertised ability to perform HTTP or network operations can enable SSRF or exfiltration.",
                    transport,
                    server_name,
                    "Use outbound allowlists; block file/URL schemes; log destinations.",
                    title_suffix=name[:48],
                )
            )
        if _PATH_TRAVERSAL.search(blob):
            out.append(
                _v(
                    VulnerabilityType.PATH_TRAVERSAL,
                    Severity.HIGH,
                    f"Dynamic probe: path traversal indicators in tool “{name}”",
                    "Tool metadata suggests filesystem traversal or unsafe path composition.",
                    transport,
                    server_name,
                    "Canonicalize paths; jail to an explicit root; reject .. segments.",
                    title_suffix=name[:48],
                )
            )
        if _SECRET_HINT.search(blob):
            out.append(
                _v(
                    VulnerabilityType.SECRET_EXPOSURE,
                    Severity.MEDIUM,
                    f"Dynamic probe: secret/credential hints in tool “{name}”",
                    "Tool text references secrets or credential patterns — verify no live values.",
                    transport,
                    server_name,
                    "Remove secrets from descriptions; load from a vault at runtime.",
                    title_suffix=name[:48],
                )
            )
        if name and any(ord(c) > 127 for c in name):
            out.append(
                _v(
                    VulnerabilityType.TOOL_POISONING,
                    Severity.MEDIUM,
                    f"Dynamic probe: non-ASCII characters in tool name “{name}”",
                    "Unicode in tool names can confuse users or tools comparing identifiers.",
                    transport,
                    server_name,
                    "Use ASCII tool names or document normalization policy.",
                    title_suffix=name[:48],
                )
            )
    return out


def _analyze_resources(transport: str, server_name: str, resources: list[Any]) -> list[Vulnerability]:
    out: list[Vulnerability] = []
    for res in resources:
        uri = getattr(res, "uri", "") or ""
        name = getattr(res, "name", "") or ""
        blob = f"{uri}\n{name}"
        if uri.startswith("file://") or "/.." in uri or ".." in uri:
            out.append(
                _v(
                    VulnerabilityType.PATH_TRAVERSAL,
                    Severity.MEDIUM,
                    f"Dynamic probe: sensitive resource URI “{uri[:80]}”",
                    "Resource template suggests filesystem exposure via MCP resources.",
                    transport,
                    server_name,
                    "Restrict resource roots; avoid exposing arbitrary file URIs.",
                )
            )
        if _NET_FETCH_PATTERNS.search(blob):
            out.append(
                _v(
                    VulnerabilityType.CONFIG_SECURITY,
                    Severity.LOW,
                    f"Dynamic probe: network-like resource “{name or uri[:48]}”",
                    "Resource metadata references HTTP/network semantics.",
                    transport,
                    server_name,
                    "Validate resource handlers do not become SSRF surrogates.",
                )
            )
    return out


def _analyze_prompts(transport: str, server_name: str, prompts: list[Any]) -> list[Vulnerability]:
    out: list[Vulnerability] = []
    for pr in prompts:
        name = getattr(pr, "name", "") or ""
        desc = getattr(pr, "description", "") or ""
        blob = f"{name}\n{desc}"
        if _CODE_EXEC_PATTERNS.search(blob) or _NET_FETCH_PATTERNS.search(blob):
            out.append(
                _v(
                    VulnerabilityType.PROMPT_INJECTION,
                    Severity.MEDIUM,
                    f"Dynamic probe: high-risk prompt template “{name}”",
                    "Prompt metadata suggests injection-prone or dangerous instructions.",
                    transport,
                    server_name,
                    "Harden prompt boundaries; avoid embedding executable or URL directives.",
                )
            )
    return out


def _schema_blob(schema: Any) -> str:
    if schema is None:
        return ""
    try:
        if hasattr(schema, "model_dump"):
            return json.dumps(schema.model_dump(), default=str)[:8000]
        if isinstance(schema, dict):
            return json.dumps(schema)[:8000]
    except (TypeError, ValueError):
        pass
    return str(schema)[:4000]


def _v(
    vtype: VulnerabilityType,
    severity: Severity,
    title: str,
    description: str,
    transport: str,
    server_name: str,
    remediation: str,
    *,
    title_suffix: str = "",
) -> Vulnerability:
    t = title if not title_suffix else f"{title} ({title_suffix})"
    return Vulnerability(
        id=f"dyn-{uuid.uuid4().hex[:12]}",
        type=vtype,
        title=t,
        description=description,
        severity=severity,
        confidence=Confidence.MEDIUM,
        file_path=_dyn_location(transport, server_name),
        line_number=0,
        remediation=remediation,
        detector="DynamicProbe",
        engine="dynamic",
        metadata={"transport": transport, "server_name": server_name},
    )


def probe_failure_vulnerability(
    transport: str,
    server_name: str,
    err: str,
) -> Vulnerability:
    """Handshake or list_* failure — critical for CI visibility."""
    return Vulnerability(
        id=f"dyn-{uuid.uuid4().hex[:12]}",
        type=VulnerabilityType.CONFIG_SECURITY,
        title=f"Dynamic probe failed for server “{server_name}”",
        description=f"Could not complete MCP initialize/list on {transport} transport: {err}",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path=_dyn_location(transport, server_name),
        line_number=0,
        remediation="Fix server startup, transport URL, or auth headers; verify locally with an MCP client.",
        detector="DynamicProbe",
        engine="dynamic",
        metadata={"transport": transport, "server_name": server_name, "error": err[:2000]},
    )
