"""
MCP-Specific Severity Calibrator.

Performs a post-scan pass over all findings and elevates severity based on
server-level context signals detected from configuration files:

  - Filesystem or network access declared → elevate CODE_INJECTION,
    PATH_TRAVERSAL, SSRF, MCP_SAMPLING by one severity step.
  - STDIO transport detected → add a context note to all findings
    explaining that the server runs with full user privilege.
  - Sensitive tool operations (rm, delete, shell, sudo …) → elevate
    PATH_TRAVERSAL and CODE_INJECTION findings by one step.

The calibrator is called by :class:`StaticAnalysisEngine` after all
detectors have run, so detectors themselves remain context-agnostic.
"""

import logging
from typing import TYPE_CHECKING

from mcp_sentinel.models.vulnerability import Severity, VulnerabilityType

if TYPE_CHECKING:
    from mcp_sentinel.engines.static.context_detector import MCPContext
    from mcp_sentinel.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

# Severity elevation map: one step up
_ELEVATION_MAP: dict[Severity, Severity] = {
    Severity.INFO: Severity.LOW,
    Severity.LOW: Severity.MEDIUM,
    Severity.MEDIUM: Severity.HIGH,
    Severity.HIGH: Severity.CRITICAL,
    Severity.CRITICAL: Severity.CRITICAL,  # already at max
}

# Vulnerability types elevated when server has filesystem / network access
_ELEVATE_FOR_FS_NET: frozenset[VulnerabilityType] = frozenset(
    [
        VulnerabilityType.CODE_INJECTION,
        VulnerabilityType.PATH_TRAVERSAL,
        VulnerabilityType.SSRF,
        VulnerabilityType.MCP_SAMPLING,
    ]
)

# Vulnerability types further elevated when sensitive tool ops are present
_ELEVATE_FOR_SENSITIVE_TOOLS: frozenset[VulnerabilityType] = frozenset(
    [
        VulnerabilityType.PATH_TRAVERSAL,
        VulnerabilityType.CODE_INJECTION,
    ]
)

_STDIO_NOTE = (
    "Server uses STDIO transport and inherits the full privilege level of the "
    "host user process. Any code execution or path traversal vulnerability "
    "has direct system-level impact."
)


class SeverityCalibrator:
    """
    Apply MCP server context to refine finding severity.

    Usage::

        context = detect_mcp_context(target_path)
        calibrator = SeverityCalibrator()
        calibrated = calibrator.calibrate(vulnerabilities, context)
    """

    def calibrate(
        self,
        vulnerabilities: "list[Vulnerability]",
        context: "MCPContext",
    ) -> "list[Vulnerability]":
        """
        Return a new list of (possibly modified) :class:`Vulnerability` objects.

        The original list is never mutated.
        """
        if not vulnerabilities:
            return vulnerabilities

        has_context = (
            context.has_filesystem_access
            or context.has_network_access
            or context.is_stdio_transport
            or bool(context.sensitive_tool_names)
        )
        if not has_context:
            logger.debug("SeverityCalibrator: no context signals — no changes made")
            return vulnerabilities

        result: list[Vulnerability] = []
        elevated_count = 0

        for vuln in vulnerabilities:
            updates: dict = {}
            new_meta = dict(vuln.metadata)

            # FS / network access elevation
            if (
                context.has_filesystem_access or context.has_network_access
            ) and vuln.type in _ELEVATE_FOR_FS_NET:
                new_sev = _ELEVATION_MAP[vuln.severity]
                if new_sev != vuln.severity:
                    updates["severity"] = new_sev
                    elevated_count += 1
                    reasons = []
                    if context.has_filesystem_access:
                        reasons.append("declared filesystem access")
                    if context.has_network_access:
                        reasons.append("declared network access")
                    new_meta["severity_elevated"] = True
                    new_meta["elevation_reason"] = (
                        f"Severity elevated because server has {' and '.join(reasons)}."
                    )

            # Sensitive tool operations: additional elevation
            if (
                context.sensitive_tool_names
                and vuln.type in _ELEVATE_FOR_SENSITIVE_TOOLS
            ):
                current_sev = updates.get("severity", vuln.severity)
                new_sev = _ELEVATION_MAP[current_sev]
                if new_sev != current_sev:
                    updates["severity"] = new_sev
                    elevated_count += 1
                    tools_str = ", ".join(context.sensitive_tool_names[:5])
                    new_meta["severity_elevated"] = True
                    new_meta["elevation_reason"] = new_meta.get(
                        "elevation_reason", ""
                    ) + (
                        f" Server exposes sensitive tool operations: {tools_str}."
                    )

            # STDIO transport: add context note to all findings
            if context.is_stdio_transport:
                new_meta["context_note"] = _STDIO_NOTE

            if updates or new_meta != vuln.metadata:
                updates["metadata"] = new_meta
                result.append(vuln.model_copy(update={**updates, "id": vuln.id}))
            else:
                result.append(vuln)

        if elevated_count:
            logger.info(
                "SeverityCalibrator: elevated %d finding(s) based on MCP context "
                "(fs_access=%s, net_access=%s, stdio=%s, sensitive_tools=%d)",
                elevated_count,
                context.has_filesystem_access,
                context.has_network_access,
                context.is_stdio_transport,
                len(context.sensitive_tool_names),
            )

        return result
