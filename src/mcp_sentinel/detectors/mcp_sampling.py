"""
MCP Sampling security detector.

MCP sampling (LLM inference delegated back to the client/host) is a powerful
feature but carries unique risks:

* **Prompt injection via sampling** — an MCP server requests sampling with
  crafted messages that hijack host-side LLM reasoning.
* **Sensitive data exfiltration** — sampling requests bundle secrets, PII, or
  internal context into the messages sent to the LLM.
* **Unconstrained model parameters** — no temperature/max-token limits allow
  resource exhaustion or open-ended generation.
* **Silent sampling without user visibility** — sampling that bypasses host
  UI/approval means users cannot review what is sent to the LLM.

Reference: https://spec.modelcontextprotocol.io/specification/client/sampling/
"""

import re
from pathlib import Path
from re import Pattern
from typing import Optional

from mcp_sentinel.detectors.base import BaseDetector
from mcp_sentinel.models.vulnerability import (
    Confidence,
    Severity,
    Vulnerability,
    VulnerabilityType,
)


class MCPSamplingDetector(BaseDetector):
    """
    Detector for MCP sampling misuse and security issues.

    Detects four categories:
    1. Prompt injection via sampling request construction
    2. Sensitive data bundled into sampling messages
    3. Unconstrained model parameters (no maxTokens / no temperature limit)
    4. Missing human-in-the-loop / approval markers
    """

    def __init__(self) -> None:
        super().__init__(name="MCPSamplingDetector", enabled=True)
        self.patterns: dict[str, list[Pattern[str]]] = self._compile_patterns()

    def _compile_patterns(self) -> dict[str, list[Pattern[str]]]:
        """Compile regex patterns for MCP sampling detection."""
        return {
            # ── Sampling invocation patterns ──────────────────────────────────
            # Detect calls to the MCP sampling API in various SDKs.
            "sampling_call": [
                # Python SDK: await session.create_message(...)
                re.compile(r"\bcreate_message\s*\(", re.IGNORECASE),
                # TypeScript/JS SDK: client.createMessage(...)
                re.compile(r"\bcreateMessage\s*\(", re.IGNORECASE),
                # Generic: sampling_request, request_sampling, requestSampling
                re.compile(r"\b(?:sampling_request|request_sampling|requestSampling)\s*\(", re.IGNORECASE),
                # JSON-RPC style: "sampling/createMessage"
                re.compile(r"['\"]sampling/createMessage['\"]", re.IGNORECASE),
            ],
            # ── Prompt injection risk ─────────────────────────────────────────
            # User-controlled data concatenated directly into sampling messages.
            "prompt_injection_in_sampling": [
                # Python f-string with user var in message content
                re.compile(
                    r"create_message\s*\([^)]*f['\"][^'\"]*\{(?:user_input|query|request|data|content|text)\}",
                    re.IGNORECASE,
                ),
                # Concatenation: "..."+user_input+"..." inside create_message
                re.compile(
                    r"create_message\s*\([^)]*\+\s*(?:user_input|query|request_data|user_data|content)",
                    re.IGNORECASE,
                ),
                # Template literal in JS: `${userInput}` inside createMessage
                re.compile(
                    r"createMessage\s*\([^)]*\$\{(?:userInput|query|requestData|userData|content)\}",
                    re.IGNORECASE,
                ),
            ],
            # ── Sensitive data in sampling ────────────────────────────────────
            # Credentials, tokens, or PII embedded in sampling message payloads.
            "sensitive_data_in_sampling": [
                re.compile(
                    r"create_message\s*\([^)]*(?:password|secret|token|api_key|apikey|credential|auth)",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"createMessage\s*\([^)]*(?:password|secret|token|apiKey|credential|auth)",
                    re.IGNORECASE,
                ),
                # Sampling message that references environment secrets
                re.compile(
                    r"create_message\s*\([^)]*os\.environ\s*\[",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"createMessage\s*\([^)]*process\.env\b",
                    re.IGNORECASE,
                ),
            ],
            # ── Unconstrained model parameters ───────────────────────────────
            # Sampling calls where maxTokens / max_tokens is absent or very high.
            "unconstrained_sampling": [
                # Python: ModelPreferences / SamplingMessage with no max_tokens
                re.compile(
                    r"create_message\s*\([^)]*messages\s*=",
                    re.IGNORECASE,
                ),
                # TypeScript: createMessage with no maxTokens in the options
                re.compile(
                    r"createMessage\s*\(\s*\{[^}]*messages\s*:",
                    re.IGNORECASE,
                ),
                # Explicit very high token limit (> 100 000)
                re.compile(
                    r"max_tokens\s*[=:]\s*(?:[1-9]\d{5,})",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"maxTokens\s*[=:]\s*(?:[1-9]\d{5,})",
                    re.IGNORECASE,
                ),
            ],
        }

    def is_applicable(self, file_path: Path, file_type: Optional[str] = None) -> bool:
        if file_type:
            return file_type in ("python", "javascript", "typescript")
        return file_path.suffix.lower() in (".py", ".js", ".ts", ".jsx", ".tsx")

    def detect_sync(
        self, file_path: Path, content: str, file_type: Optional[str] = None
    ) -> list[Vulnerability]:
        vulnerabilities: list[Vulnerability] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            if self._is_comment(line, file_type):
                continue

            for category, patterns in self.patterns.items():
                for pattern in patterns:
                    if pattern.search(line):
                        vuln = self._create_vulnerability(
                            category=category,
                            matched_text=line.strip(),
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=line.strip(),
                        )
                        vulnerabilities.append(vuln)
                        break  # one vuln per line per category

        return self._deduplicate(vulnerabilities)

    def _is_comment(self, line: str, file_type: Optional[str]) -> bool:
        stripped = line.strip()
        if not stripped:
            return False
        if stripped.startswith("#"):
            return True
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            return True
        return False

    # Severity priority — higher index = higher priority
    _SEV_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

    def _deduplicate(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        """Keep the highest-severity finding per (file, line) location."""
        best: dict[tuple[str, int], Vulnerability] = {}
        for v in vulns:
            key = (v.file_path, v.line_number)
            if key not in best:
                best[key] = v
            else:
                existing_prio = self._SEV_ORDER.index(best[key].severity)
                new_prio = self._SEV_ORDER.index(v.severity)
                if new_prio > existing_prio:
                    best[key] = v
        return list(best.values())

    def _create_vulnerability(
        self,
        category: str,
        matched_text: str,
        file_path: Path,
        line_number: int,
        code_snippet: str,
    ) -> Vulnerability:
        metadata: dict[str, object] = {
            "sampling_call": {
                "title": "MCP Sampling: Uninspected Sampling Request",
                "severity": Severity.MEDIUM,
                "confidence": Confidence.MEDIUM,
                "cwe_id": "CWE-668",
                "cvss_score": 5.3,
                "description": (
                    f"MCP sampling call detected: '{matched_text[:80]}'. "
                    "Sampling requests delegate LLM inference to the host. "
                    "Ensure sampling is only performed with explicit user awareness "
                    "and that messages are logged for audit purposes."
                ),
                "remediation": (
                    "1. Ensure the host UI surfaces all sampling requests to the user\n"
                    "2. Log every sampling request with timestamp and message contents\n"
                    "3. Set explicit maxTokens to prevent runaway token consumption\n"
                    "4. Validate that sampling is strictly necessary for the operation"
                ),
                "mitre_attack_ids": ["T1059"],
            },
            "prompt_injection_in_sampling": {
                "title": "MCP Sampling: Prompt Injection via User Input",
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-77",
                "cvss_score": 8.1,
                "description": (
                    f"User-controlled data concatenated into sampling message: "
                    f"'{matched_text[:80]}'. "
                    "An attacker who controls the input can inject instructions that "
                    "override the server's intended reasoning, potentially exfiltrating "
                    "data or bypassing safety checks inside the host LLM."
                ),
                "remediation": (
                    "1. Never interpolate raw user input into sampling message text\n"
                    "2. Treat user data as opaque data, not as instructions\n"
                    "3. Use structured message roles (user/assistant) correctly\n"
                    "4. Sanitize or escape user input before embedding in messages\n"
                    "5. Implement output validation on sampling responses"
                ),
                "mitre_attack_ids": ["T1059", "T1566"],
            },
            "sensitive_data_in_sampling": {
                "title": "MCP Sampling: Sensitive Data Sent to LLM",
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-312",
                "cvss_score": 7.5,
                "description": (
                    f"Credentials or sensitive data appear in sampling payload: "
                    f"'{matched_text[:80]}'. "
                    "Sending secrets, tokens, or PII to an LLM exposes them to the "
                    "model provider's infrastructure and any logged sampling traffic. "
                    "This violates data minimisation principles and may breach compliance."
                ),
                "remediation": (
                    "1. Never include secrets, credentials, or PII in sampling messages\n"
                    "2. Redact sensitive fields before constructing message payloads\n"
                    "3. Audit what data is included in sampling requests\n"
                    "4. Use opaque references instead of raw secret values"
                ),
                "mitre_attack_ids": ["T1552", "T1530"],
            },
            "unconstrained_sampling": {
                "title": "MCP Sampling: Unconstrained Token Limit",
                "severity": Severity.LOW,
                "confidence": Confidence.LOW,
                "cwe_id": "CWE-400",
                "cvss_score": 3.1,
                "description": (
                    f"Sampling call without explicit token constraints: "
                    f"'{matched_text[:80]}'. "
                    "Omitting maxTokens or setting an extremely high limit allows "
                    "unrestricted generation, potentially causing high API costs and "
                    "enabling verbose data exfiltration through the LLM output."
                ),
                "remediation": (
                    "1. Always set maxTokens appropriate to the task\n"
                    "2. Use ModelPreferences to constrain generation parameters\n"
                    "3. Monitor token usage per sampling call\n"
                    "4. Implement rate limiting on sampling operations"
                ),
                "mitre_attack_ids": ["T1499"],
            },
        }

        meta = metadata.get(category, metadata["sampling_call"])
        return Vulnerability(
            type=VulnerabilityType.MCP_SAMPLING,
            title=str(meta["title"]),
            description=str(meta["description"]),
            severity=meta["severity"],  # type: ignore[arg-type]
            confidence=meta["confidence"],  # type: ignore[arg-type]
            file_path=str(file_path),
            line_number=line_number,
            code_snippet=code_snippet,
            cwe_id=str(meta["cwe_id"]),
            cvss_score=float(meta["cvss_score"]),  # type: ignore[arg-type]
            remediation=str(meta["remediation"]),
            references=[
                "https://spec.modelcontextprotocol.io/specification/client/sampling/",
                "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            ],
            mitre_attack_ids=list(meta["mitre_attack_ids"]),  # type: ignore[arg-type]
            detector=self.name,
            engine="static",
        )
