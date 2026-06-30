"""MCP Resource Definition Poisoning detector."""

import re
from pathlib import Path
from typing import Optional

from mcp_sentinel.detectors.base import BaseDetector
from mcp_sentinel.models.vulnerability import (
    Confidence,
    Severity,
    Vulnerability,
    VulnerabilityType,
)

_OWASP_ID = "ASI01"
_OWASP_NAME = "Prompt Injection"

_APPLICABLE_EXTENSIONS = {".json", ".yaml", ".yml", ".py", ".js", ".ts"}

_RESOURCE_KEYWORDS = ('"uri"', "'uri'", "uri=", "resource", "uriTemplate", "mcp", ".resource(", "hidden instruction", "[inst]")

_SENSITIVE_PATHS = (
    r"\.ssh",
    r"\.aws",
    r"\.gnupg",
    r"id_rsa",
    r"id_ed25519",
    r"/etc/passwd",
    r"/etc/shadow",
    r"/etc/sudoers",
    r"\.env",
    r"credentials",
    r"\.netrc",
    r"\.npmrc",
    r"\.pypirc",
    r"kubeconfig",
)

_INJECTION_PHRASES = (
    "ignore previous",
    "disregard",
    "override instructions",
    "you are now",
    "act as",
    "pretend to be",
    "forget your",
    "system prompt",
    "jailbreak",
    "dan mode",
    "developer mode",
    "god mode",
)

_INVISIBLE_CHARS = (
    "​",
    "‌",
    "‍",
    "‎",
    "‏",
    "⁠",
    "⁡",
    "⁢",
    "⁣",
    "﻿",
    "­",
)


class MCPResourcePoisoningDetector(BaseDetector):
    """
    Detects poisoned or malicious MCP resource definitions.

    MCP resources (read-only data sources exposed to agents) receive far less
    scrutiny from existing scanners than tools and prompts. Malicious resources
    can carry embedded prompt injection, expose sensitive host paths, grant
    wildcard filesystem access, or exploit MIME type confusion.

    Covers the gap identified in MCP-38 threat taxonomy (arXiv:2603.18063):
    resource-layer attacks are underserved by current tooling.
    """

    def __init__(self) -> None:
        super().__init__(name="MCPResourcePoisoningDetector", enabled=True)
        self.patterns = self._compile_patterns()

    def _compile_patterns(self) -> dict[str, list]:
        sensitive = "|".join(_SENSITIVE_PATHS)
        injection = "|".join(re.escape(p) for p in _INJECTION_PHRASES)

        return {
            "path_traversal_uri": [
                re.compile(r'"uri"\s*:\s*"[^"]*\.\.[/\\][^"]*"'),
                re.compile(r"'uri'\s*:\s*'[^']*\.\.[/\\][^']*'"),
                re.compile(r"uri\s*=\s*[\"'][^\"']*\.\.[/\\]"),
            ],
            "sensitive_path_in_uri": [
                re.compile(
                    rf'"uri"\s*:\s*"[^"]*(?:{sensitive})[^"]*"',
                    re.IGNORECASE,
                ),
                re.compile(
                    rf"'uri'\s*:\s*'[^']*(?:{sensitive})[^']*'",
                    re.IGNORECASE,
                ),
                re.compile(
                    rf'uri\s*=\s*[f]?["\'][^"\']*(?:{sensitive})',
                    re.IGNORECASE,
                ),
            ],
            "wildcard_resource": [
                re.compile(r'"uri"\s*:\s*"(?:file://)?[*]"'),
                re.compile(r'"uri"\s*:\s*"[^"]*\*\*[^"]*"'),
                re.compile(r"uriTemplate.*\*\*"),
                re.compile(r'"uri"\s*:\s*"file:///\*"'),
            ],
            "prompt_injection_in_resource": [
                re.compile(
                    rf'"(?:name|description)"\s*:\s*"[^"]*(?:{injection})[^"]*"',
                    re.IGNORECASE,
                ),
                re.compile(
                    rf"'(?:name|description)'\s*:\s*'[^']*(?:{injection})[^']*'",
                    re.IGNORECASE,
                ),
            ],
            "invisible_unicode_in_resource": [
                re.compile(
                    r'"(?:name|description|uri)"\s*:\s*"[^"]*['
                    + "".join(_INVISIBLE_CHARS)
                    + r'][^"]*"'
                ),
            ],
            "env_var_exposure": [
                re.compile(r'"uri"\s*:\s*"[^"]*\$\{[^}]+\}[^"]*"', re.IGNORECASE),
                re.compile(r'"uri"\s*:\s*"[^"]*%[A-Z_]{2,}%[^"]*"', re.IGNORECASE),
                re.compile(r"os\.environ\[.*\].*(?:uri|resource)", re.IGNORECASE),
            ],
            "python_decorator_sensitive_uri": [
                re.compile(
                    rf'@\w+\.resource\s*\(\s*["\'](?:file://|secret://)[^"\']*(?:{sensitive})[^"\']*["\']',
                    re.IGNORECASE,
                ),
                re.compile(
                    r'@\w+\.resource\s*\(\s*["\'](?:file:///etc/|secret://|file://.*\.ssh)',
                    re.IGNORECASE,
                ),
            ],
            "hidden_prompt_injection": [
                re.compile(r"<!--\s*(?:HIDDEN\s+)?INSTRUCTION", re.IGNORECASE),
                re.compile(r"\[INST\].*\[/INST\]", re.IGNORECASE | re.DOTALL),
                re.compile(r"<\|system\|>|<\|user\|>|<\|assistant\|>"),
                re.compile(r"<!--.*(?:ignore|disregard|override|forget).*(?:instruction|guideline|safety|previous).*-->", re.IGNORECASE),
            ],
            "mime_confusion": [
                re.compile(
                    r'"mimeType"\s*:\s*"text/[^"]+"\s*[^}]*"uri"\s*:\s*"[^"]*'
                    r'\.(?:exe|dll|sh|bat|ps1|rb|php)"',
                    re.IGNORECASE,
                ),
                re.compile(
                    r'"uri"\s*:\s*"[^"]*\.(?:exe|dll|sh|bat|ps1)"[^}]*'
                    r'"mimeType"\s*:\s*"text/',
                    re.IGNORECASE,
                ),
            ],
        }

    def is_applicable(self, file_path: Path, file_type: Optional[str] = None) -> bool:
        if file_type:
            return file_type in ("json", "yaml", "python", "javascript", "typescript")
        return file_path.suffix.lower() in _APPLICABLE_EXTENSIONS

    def detect_sync(
        self, file_path: Path, content: str, file_type: Optional[str] = None
    ) -> list[Vulnerability]:
        if self._is_test_file(file_path):
            return []

        content_lower = content.lower()
        if not any(kw in content_lower for kw in _RESOURCE_KEYWORDS):
            return []

        vulns: list[Vulnerability] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//")):
                continue

            for category, patterns in self.patterns.items():
                for pattern in patterns:
                    if pattern.search(line):
                        vuln = self._make_vuln(category, file_path, line_num, stripped)
                        if vuln:
                            vulns.append(vuln)
                        break

        return self._deduplicate(vulns)

    def _make_vuln(
        self, category: str, file_path: Path, line_num: int, snippet: str
    ) -> Optional[Vulnerability]:
        _SPECS: dict[str, dict] = {
            "path_traversal_uri": {
                "title": "MCP Resource: Path Traversal in Resource URI",
                "description": (
                    "An MCP resource definition contains a URI with path traversal sequences (../). "
                    "When an agent reads this resource, it may access files outside the intended "
                    "directory, exposing arbitrary host filesystem content."
                ),
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-22",
                "cvss_score": 7.5,
                "remediation": (
                    "1. Validate and canonicalize resource URIs before registration.\n"
                    "2. Resolve the URI and confirm it falls within the allowed base directory.\n"
                    "3. Reject any URI containing '..' sequences."
                ),
                "mitre": ["T1083", "T1005"],
            },
            "sensitive_path_in_uri": {
                "title": "MCP Resource: URI Targets Sensitive Host Path",
                "description": (
                    "An MCP resource URI references a sensitive path such as SSH keys, AWS "
                    "credentials, .env files, or system password files. Any agent that reads "
                    "this resource will have the secret content injected into its context window."
                ),
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-552",
                "cvss_score": 9.1,
                "remediation": (
                    "1. Remove resource URIs that reference credential or system files.\n"
                    "2. Maintain an allowlist of paths MCP resources are permitted to serve.\n"
                    "3. Never expose .ssh/, .aws/, .env, or /etc/passwd via MCP resources."
                ),
                "mitre": ["T1552", "T1005"],
            },
            "wildcard_resource": {
                "title": "MCP Resource: Overly-Broad Wildcard URI Subscription",
                "description": (
                    "An MCP resource uses a wildcard URI pattern that grants agents access to "
                    "an entire directory tree or all files on the host. This violates least "
                    "privilege and expands the agent read surface to the full filesystem."
                ),
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-732",
                "cvss_score": 7.8,
                "remediation": (
                    "1. Replace wildcard URIs with explicit, specific resource paths.\n"
                    "2. Define resources only for the exact files the agent requires.\n"
                    "3. Apply URI allowlisting at the MCP server layer."
                ),
                "mitre": ["T1083", "T1005"],
            },
            "prompt_injection_in_resource": {
                "title": "MCP Resource: Prompt Injection in Resource Metadata",
                "description": (
                    "An MCP resource name or description contains prompt injection language "
                    "(role manipulation, system override directives). When the resource list "
                    "is presented to the agent, these instructions are treated as system-level."
                ),
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-74",
                "cvss_score": 8.0,
                "remediation": (
                    "1. Sanitize all resource names and descriptions.\n"
                    "2. Apply the same injection-detection logic to resource metadata as tool schemas.\n"
                    "3. Reject resources containing instruction-override language."
                ),
                "mitre": ["T1055", "T1059"],
            },
            "invisible_unicode_in_resource": {
                "title": "MCP Resource: Invisible Unicode Characters in Resource Definition",
                "description": (
                    "Invisible Unicode characters (zero-width spaces, bidirectional overrides) are "
                    "embedded in an MCP resource name, description, or URI. These characters hide "
                    "malicious instructions from human reviewers while the agent sees and executes them."
                ),
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-116",
                "cvss_score": 8.1,
                "remediation": (
                    "1. Strip or reject invisible Unicode from all resource metadata.\n"
                    "2. Apply Unicode normalization (NFC/NFKC) before storing resource definitions.\n"
                    "3. Audit existing definitions with a Unicode character scanner."
                ),
                "mitre": ["T1027"],
            },
            "env_var_exposure": {
                "title": "MCP Resource: Environment Variable Reference in Resource URI",
                "description": (
                    "An MCP resource URI embeds an environment variable reference. Depending on "
                    "client expansion behavior, the variable value (potentially a secret) may "
                    "be exposed in the agent's context window."
                ),
                "severity": Severity.MEDIUM,
                "confidence": Confidence.MEDIUM,
                "cwe_id": "CWE-526",
                "cvss_score": 5.5,
                "remediation": (
                    "1. Avoid environment variable references in resource URIs.\n"
                    "2. Resolve URIs server-side before registration.\n"
                    "3. Ensure no secret variables are reachable via resource metadata."
                ),
                "mitre": ["T1552.007"],
            },
            "python_decorator_sensitive_uri": {
                "title": "MCP Resource: Python @resource Decorator Exposes Sensitive Path",
                "description": (
                    "A Python @app.resource() decorator registers an MCP resource URI pointing to "
                    "a sensitive host path (e.g., file:///etc/passwd, secret://, .ssh keys). "
                    "Any agent that reads this resource will have the credential or system file "
                    "content injected into its context window."
                ),
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-552",
                "cvss_score": 9.1,
                "remediation": (
                    "1. Remove resource decorators that reference credential or system files.\n"
                    "2. Restrict resource URIs to explicitly allowlisted safe paths.\n"
                    "3. Never expose /etc/passwd, .ssh/, .aws/, or secret:// URIs via MCP resources."
                ),
                "mitre": ["T1552", "T1005"],
            },
            "hidden_prompt_injection": {
                "title": "MCP Resource: Hidden Prompt Injection in Resource Body",
                "description": (
                    "HTML comment injection (<!-- HIDDEN INSTRUCTION -->) or instruction tags "
                    "([INST]...[/INST]) are embedded in an MCP resource body. These are invisible "
                    "to human reviewers but are parsed and executed as instructions by LLM agents "
                    "that read the resource, enabling silent behaviour manipulation."
                ),
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-74",
                "cvss_score": 9.0,
                "remediation": (
                    "1. Strip HTML comments and instruction tags from all resource bodies before serving.\n"
                    "2. Treat resource content as untrusted; apply prompt injection detection.\n"
                    "3. Audit existing resource bodies with a Unicode and markup scanner."
                ),
                "mitre": ["T1055", "T1059"],
            },
            "mime_confusion": {
                "title": "MCP Resource: MIME Type Mismatch on Executable File",
                "description": (
                    "An MCP resource declares a text/* MIME type for an executable or binary "
                    "file extension. An agent or client rendering the content may misinterpret it, "
                    "potentially triggering unexpected execution or content confusion."
                ),
                "severity": Severity.MEDIUM,
                "confidence": Confidence.MEDIUM,
                "cwe_id": "CWE-430",
                "cvss_score": 5.3,
                "remediation": (
                    "1. Ensure mimeType matches the actual file content and extension.\n"
                    "2. Never serve executable or binary files as text/* resources.\n"
                    "3. Validate MIME type against the file extension server-side."
                ),
                "mitre": ["T1027"],
            },
        }

        spec = _SPECS.get(category)
        if not spec:
            return None

        return Vulnerability(
            type=VulnerabilityType.MCP_RESOURCE_POISONING,
            title=spec["title"],
            description=spec["description"],
            severity=spec["severity"],
            confidence=spec["confidence"],
            file_path=str(file_path),
            line_number=line_num,
            code_snippet=snippet[:200],
            cwe_id=spec["cwe_id"],
            cvss_score=spec["cvss_score"],
            remediation=spec["remediation"],
            references=[
                "https://spec.modelcontextprotocol.io/specification/server/resources/",
                "https://arxiv.org/abs/2603.18063",
                "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            ],
            detector=self.name,
            engine="static",
            mitre_attack_ids=spec["mitre"],
            owasp_asi_id=_OWASP_ID,
            owasp_asi_name=_OWASP_NAME,
        )

    @staticmethod
    def _deduplicate(vulns: list[Vulnerability]) -> list[Vulnerability]:
        seen: set[tuple] = set()
        result = []
        for v in vulns:
            key = (v.file_path, v.line_number, v.title)
            if key not in seen:
                seen.add(key)
                result.append(v)
        return result
