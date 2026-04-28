"""Incident/exploitability summary generator for high-risk findings."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mcp_sentinel.models.scan_result import ScanResult
from mcp_sentinel.models.vulnerability import Vulnerability, VulnerabilityType


@dataclass(slots=True)
class IncidentCandidate:
    """A vulnerability with an explanation for exploitability triage."""

    vuln: Vulnerability
    reasons: list[str]


class IncidentSummaryGenerator:
    """Generate markdown summaries for exploit-available and critical findings."""

    _EXPLOIT_KEYWORDS = (
        "remote code execution",
        "rce",
        "command injection",
        "arbitrary command",
        "eval(",
        "exec(",
        "deserialization",
        "shell",
    )

    def classify(self, result: ScanResult) -> list[IncidentCandidate]:
        """Return vulnerabilities that should be highlighted as incident candidates."""
        candidates: list[IncidentCandidate] = []
        for vuln in result.vulnerabilities:
            reasons = self._reasons(vuln)
            if reasons:
                candidates.append(IncidentCandidate(vuln=vuln, reasons=reasons))
        return candidates

    def has_candidates(self, result: ScanResult) -> bool:
        """Check if scan contains critical/RCE/exploit-available findings."""
        return bool(self.classify(result))

    def generate(self, result: ScanResult) -> str:
        """Build markdown incident summary."""
        candidates = self.classify(result)
        lines: list[str] = [
            "# MCP Sentinel Incident Summary",
            "",
            f"- **Target:** `{result.target}`",
            f"- **Total findings:** {result.statistics.total_vulnerabilities}",
            f"- **Exploitability candidates:** {len(candidates)}",
            "",
        ]
        if not candidates:
            lines.extend(
                [
                    "No findings matched default incident criteria "
                    "(critical severity, code injection type, or exploit-style indicators).",
                    "",
                ]
            )
            return "\n".join(lines)

        lines.extend(
            [
                "## High-priority triage list",
                "",
                "| Severity | Type | Title | Location | Why flagged |",
                "|---|---|---|---|---|",
            ]
        )
        for item in candidates:
            vuln = item.vuln
            location = f"{vuln.file_path}:{vuln.line_number}"
            lines.append(
                "| "
                + " | ".join(
                    [
                        self._md(vuln.severity.value),
                        self._md(vuln.type.value),
                        self._md(vuln.title),
                        self._md(location),
                        self._md(", ".join(item.reasons)),
                    ]
                )
                + " |"
            )

        lines.extend(
            [
                "",
                "## Suggested workflow",
                "",
                "1. Confirm exploitability in isolated runtime.",
                "2. Capture proof (inputs, observed output, and blast radius).",
                "3. Prioritize remediation for critical and code execution classes.",
                "4. Track fixes and rerun scanner to verify closure.",
                "",
            ]
        )
        return "\n".join(lines)

    def save_to_file(self, result: ScanResult, output_path: Path) -> bool:
        """Write incident summary. Returns True when candidates were found."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.generate(result), encoding="utf-8")
        return self.has_candidates(result)

    def _reasons(self, vuln: Vulnerability) -> list[str]:
        reasons: list[str] = []
        if vuln.severity.value == "critical":
            reasons.append("critical severity")
        if vuln.type == VulnerabilityType.CODE_INJECTION:
            reasons.append("code injection class")
        haystack = " ".join(
            [
                vuln.title or "",
                vuln.description or "",
                vuln.code_snippet or "",
            ]
        ).lower()
        if any(k in haystack for k in self._EXPLOIT_KEYWORDS):
            reasons.append("exploit-style indicator")
        meta = vuln.metadata or {}
        if meta.get("exploit_available") or meta.get("exploit_preview"):
            reasons.append("explicit exploit evidence")
        return reasons

    def _md(self, value: str) -> str:
        return value.replace("|", "\\|").replace("\n", " ").strip()
