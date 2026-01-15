"""
SARIF (Static Analysis Results Interchange Format) report generator.

Generates SARIF 2.1.0 format reports compatible with:
- GitHub Code Scanning
- Azure DevOps
- GitLab Security Dashboard
- VS Code SARIF Viewer
"""

import json
from pathlib import Path
from typing import Any

from mcp_sentinel import __version__
from mcp_sentinel.models.scan_result import ScanResult
from mcp_sentinel.models.vulnerability import Severity, Vulnerability


class SARIFGenerator:
    """
    Generate SARIF 2.1.0 format reports.

    SARIF (Static Analysis Results Interchange Format) is an industry-standard
    format for static analysis tool output.
    """

    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    def _make_relative_path(self, file_path: str, base_path: str) -> str:
        """
        Convert absolute path to relative path for GitHub Code Scanning compatibility.

        Args:
            file_path: Absolute file path
            base_path: Base directory (scan target)

        Returns:
            Relative path from base_path
        """
        try:
            file_p = Path(file_path)
            base_p = Path(base_path)

            # Try to make it relative
            rel_path = file_p.relative_to(base_p)
            # Use forward slashes for cross-platform compatibility
            return str(rel_path).replace("\\", "/")
        except (ValueError, TypeError):
            # If can't make relative, just use the filename
            return Path(file_path).name

    def generate(self, result: ScanResult) -> dict[str, Any]:
        """
        Generate SARIF report from scan result.

        Args:
            result: ScanResult from scanner

        Returns:
            SARIF document as dictionary
        """
        return {
            "$schema": self.SCHEMA_URI,
            "version": self.SARIF_VERSION,
            "runs": [self._create_run(result)],
        }

    def generate_json(self, result: ScanResult, indent: int = 2) -> str:
        """
        Generate SARIF report as JSON string.

        Args:
            result: ScanResult from scanner
            indent: JSON indentation (default: 2)

        Returns:
            SARIF JSON string
        """
        sarif_doc = self.generate(result)
        return json.dumps(sarif_doc, indent=indent)

    def save_to_file(self, result: ScanResult, output_path: Path) -> None:
        """
        Save SARIF report to file.

        Args:
            result: ScanResult from scanner
            output_path: Path to output file
        """
        sarif_json = self.generate_json(result)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(sarif_json, encoding="utf-8")

    def _create_run(self, result: ScanResult) -> dict[str, Any]:
        """Create SARIF run object."""
        return {
            "tool": self._create_tool(),
            "invocations": [self._create_invocation(result)],
            "results": [
                self._create_result(vuln, result.target) for vuln in result.vulnerabilities
            ],
            "columnKind": "utf16CodeUnits",
            "properties": {
                "scanStatistics": {
                    "totalFiles": result.statistics.total_files,
                    "scannedFiles": result.statistics.scanned_files,
                    "totalVulnerabilities": result.statistics.total_vulnerabilities,
                    "criticalCount": result.statistics.critical_count,
                    "highCount": result.statistics.high_count,
                    "mediumCount": result.statistics.medium_count,
                    "lowCount": result.statistics.low_count,
                    "infoCount": result.statistics.info_count,
                    "scanDuration": result.statistics.scan_duration_seconds,
                    "riskScore": result.risk_score(),
                },
            },
        }

    def _create_tool(self) -> dict[str, Any]:
        """Create SARIF tool object."""
        return {
            "driver": {
                "name": "MCP Sentinel",
                "version": __version__,
                "informationUri": "https://github.com/beejak/mcp-sentinel",
                "semanticVersion": __version__,
                "organization": "MCP Sentinel Contributors",
                "shortDescription": {"text": "Enterprise Security Scanner for MCP Servers"},
                "fullDescription": {
                    "text": (
                        "MCP Sentinel is a comprehensive security scanner that detects "
                        "vulnerabilities including hardcoded secrets, code injection, "
                        "prompt injection, XSS, path traversal, and more."
                    )
                },
                "rules": self._create_rules(),
            }
        }

    def _create_rules(self) -> list[dict[str, Any]]:
        """Create SARIF rules for all detectors."""
        # Define rules for each vulnerability type
        # In production, this should be dynamically generated from detectors
        rules = [
            {
                "id": "SECRET_EXPOSURE",
                "name": "HardcodedSecrets",
                "shortDescription": {"text": "Hardcoded Secrets Detected"},
                "fullDescription": {
                    "text": "Hardcoded credentials, API keys, or other secrets detected in source code."
                },
                "helpUri": "https://cwe.mitre.org/data/definitions/798.html",
                "defaultConfiguration": {"level": "error"},
            },
            {
                "id": "CODE_INJECTION",
                "name": "CodeInjection",
                "shortDescription": {"text": "Code Injection Vulnerability"},
                "fullDescription": {
                    "text": "Command injection or code execution vulnerability detected."
                },
                "helpUri": "https://cwe.mitre.org/data/definitions/78.html",
                "defaultConfiguration": {"level": "error"},
            },
            {
                "id": "PROMPT_INJECTION",
                "name": "PromptInjection",
                "shortDescription": {"text": "Prompt Injection Vulnerability"},
                "fullDescription": {
                    "text": "AI prompt injection vulnerability that could lead to unintended behavior."
                },
                "helpUri": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                "defaultConfiguration": {"level": "warning"},
            },
            {
                "id": "XSS",
                "name": "CrossSiteScripting",
                "shortDescription": {"text": "Cross-Site Scripting (XSS)"},
                "fullDescription": {
                    "text": "Cross-site scripting vulnerability that could allow arbitrary JavaScript execution."
                },
                "helpUri": "https://cwe.mitre.org/data/definitions/79.html",
                "defaultConfiguration": {"level": "error"},
            },
            {
                "id": "PATH_TRAVERSAL",
                "name": "PathTraversal",
                "shortDescription": {"text": "Path Traversal Vulnerability"},
                "fullDescription": {
                    "text": "Path traversal vulnerability that could allow access to unauthorized files."
                },
                "helpUri": "https://cwe.mitre.org/data/definitions/22.html",
                "defaultConfiguration": {"level": "error"},
            },
        ]
        return rules

    def _create_invocation(self, result: ScanResult) -> dict[str, Any]:
        """Create SARIF invocation object."""
        invocation = {
            "executionSuccessful": result.status == "completed",
            "workingDirectory": {"uri": f"file:///{result.target}"},
        }

        if result.completed_at:
            invocation["endTimeUtc"] = result.completed_at.isoformat() + "Z"

        if result.error:
            invocation["toolExecutionNotifications"] = [
                {
                    "level": "error",
                    "message": {"text": result.error},
                }
            ]

        return invocation

    def _create_result(self, vuln: Vulnerability, base_path: str = "") -> dict[str, Any]:
        """Create SARIF result object from vulnerability."""
        # Convert absolute path to relative for GitHub Code Scanning compatibility
        relative_path = (
            self._make_relative_path(vuln.file_path, base_path) if base_path else vuln.file_path
        )

        return {
            "ruleId": vuln.type.value.upper(),
            "level": self._severity_to_sarif_level(vuln.severity),
            "message": {
                "text": vuln.description,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": relative_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": vuln.line_number,
                            "snippet": {
                                "text": vuln.code_snippet if vuln.code_snippet else "",
                            },
                        },
                    }
                }
            ],
            "properties": {
                "vulnerability_id": vuln.id,
                "title": vuln.title,
                "confidence": (
                    vuln.confidence.value
                    if hasattr(vuln.confidence, "value")
                    else str(vuln.confidence)
                ),
                "cwe_id": vuln.cwe_id,
                "cvss_score": vuln.cvss_score,
                "detector": vuln.detector,
                "engine": vuln.engine,
                "mitre_attack_ids": vuln.mitre_attack_ids,
            },
            "fixes": (
                [
                    {
                        "description": {
                            "text": (
                                vuln.remediation if vuln.remediation else "No remediation provided"
                            )
                        }
                    }
                ]
                if vuln.remediation
                else []
            ),
        }

    def _severity_to_sarif_level(self, severity: Severity) -> str:
        """Convert MCP Sentinel severity to SARIF level."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
        }
        return mapping.get(severity, "warning")
