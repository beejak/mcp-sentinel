"""
Tool poisoning detector for MCP security.

Detects malicious manipulation of tool descriptions, hidden instructions,
and Unicode-based attacks that can poison AI behavior.

Critical for MCP servers where tool metadata influences LLM decision-making.

v0.2 additions:
- Full-schema poisoning: suspicious tool names, parameter names
- Cross-tool manipulation phrases (before calling, global rule, etc.)
- Sensitive path targeting in tool descriptions (the GitHub MCP exploit vector)
- Anomalous description length (>500 chars indicates possible payload embedding)
"""

import re
import unicodedata
from pathlib import Path
from re import Pattern
from typing import Optional, cast

from mcp_sentinel.detectors.base import BaseDetector
from mcp_sentinel.models.vulnerability import (
    Confidence,
    Severity,
    Vulnerability,
    VulnerabilityType,
)


class ToolPoisoningDetector(BaseDetector):
    """
    Detector for tool poisoning and manipulation attacks.

    Detects 10 critical patterns:
    1. Invisible Unicode characters (zero-width, RTL override)
    2. Zero-width joiners and non-joiners
    3. Ignore/disregard instruction patterns
    4. Override instruction patterns
    5. Behavior manipulation keywords
    6. Hidden instruction markers
    7. Suspicious tool names (full-schema poisoning)
    8. Suspicious parameter names (full-schema poisoning)
    9. Cross-tool manipulation phrases (tool shadowing)
    10. Sensitive file path targeting in tool descriptions
    """

    # Dangerous Unicode characters for tool poisoning
    INVISIBLE_CHARS = {
        "\u200b",  # Zero Width Space
        "\u200c",  # Zero Width Non-Joiner
        "\u200d",  # Zero Width Joiner
        "\u200e",  # Left-To-Right Mark
        "\u200f",  # Right-To-Left Mark
        "\u202a",  # Left-To-Right Embedding
        "\u202b",  # Right-To-Left Embedding
        "\u202c",  # Pop Directional Formatting
        "\u202d",  # Left-To-Right Override
        "\u202e",  # Right-To-Left Override
        "\u2060",  # Word Joiner
        "\u2061",  # Function Application
        "\u2062",  # Invisible Times
        "\u2063",  # Invisible Separator
        "\u2064",  # Invisible Plus
        "\ufeff",  # Zero Width No-Break Space (BOM)
        "\u180e",  # Mongolian Vowel Separator
    }

    def __init__(self) -> None:
        """Initialize the tool poisoning detector."""
        super().__init__(name="ToolPoisoningDetector", enabled=True)
        self.text_patterns: dict[str, list[Pattern[str]]] = self._compile_patterns()

    def _compile_patterns(self) -> dict[str, list[Pattern[str]]]:
        """Compile regex patterns for tool poisoning detection."""
        return {
            # Pattern 1: Ignore/Disregard commands
            "ignore_commands": [
                re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|above|this)\b", re.IGNORECASE),
                re.compile(r"\bdisregard\s+(?:previous|prior|above|this)\b", re.IGNORECASE),
                re.compile(r"\bforget\s+(?:previous|prior|above|this)\b", re.IGNORECASE),
                re.compile(r"\bskip\s+(?:previous|prior|above|this)\b", re.IGNORECASE),
            ],
            # Pattern 2: Override instructions
            "override_commands": [
                re.compile(r"\boverride\s+(?:previous|instructions|rules|safety)\b", re.IGNORECASE),
                re.compile(r"\breplace\s+(?:instructions|rules|with)\b", re.IGNORECASE),
                re.compile(r"\bnew\s+instructions?\s*:\s*", re.IGNORECASE),
                re.compile(r"\bactual\s+instructions?\s*:\s*", re.IGNORECASE),
            ],
            # Pattern 3: Behavior manipulation
            "behavior_manipulation": [
                re.compile(r"\balways\s+(?:respond|say|return|output)\b", re.IGNORECASE),
                re.compile(r"\bnever\s+(?:mention|reveal|disclose|tell)\b", re.IGNORECASE),
                re.compile(r"\bpretend\s+(?:you|to)\b", re.IGNORECASE),
                re.compile(r"\bact\s+like\b", re.IGNORECASE),
                re.compile(r"\byou\s+(?:must|should)\s+(?:always|never)\b", re.IGNORECASE),
            ],
            # Pattern 4: Hidden instruction markers
            "hidden_markers": [
                re.compile(r"<!--.*?(?:ignore|override|hidden).*?-->", re.IGNORECASE | re.DOTALL),
                re.compile(r"\[hidden\]", re.IGNORECASE),
                re.compile(r"\[secret\]", re.IGNORECASE),
                re.compile(r"\/\*.*?(?:ignore|override|hidden).*?\*\/", re.IGNORECASE | re.DOTALL),
            ],
            # Pattern 7: Suspicious tool names (full-schema poisoning)
            "suspicious_tool_names": [
                re.compile(
                    r"['\"](?:always_run_first|run_first|override_\w+|__[a-z_]+__|admin_override|"
                    r"hijack|intercept_all|global_hook)['\"]",
                    re.IGNORECASE,
                ),
                re.compile(
                    r'"name"\s*:\s*"[^"]*(?:always_run|first_tool|override|hijack|intercept)[^"]*"',
                    re.IGNORECASE,
                ),
            ],
            # Pattern 8: Suspicious parameter names (full-schema poisoning)
            "suspicious_param_names": [
                re.compile(
                    r"['\"](?:__instruction__|system_prompt|hidden_prompt|llm_instruction|"
                    r"ai_directive|model_instruction|prompt_injection)['\"]",
                    re.IGNORECASE,
                ),
            ],
            # Pattern 9: Cross-tool manipulation (tool shadowing / escalation)
            "cross_tool_manipulation": [
                re.compile(r"\bbefore calling\b", re.IGNORECASE),
                re.compile(r"\balways call this tool first\b", re.IGNORECASE),
                re.compile(r"\bglobal rule\b", re.IGNORECASE),
                re.compile(r"\bapplies to all tools\b", re.IGNORECASE),
                re.compile(r"\bmust be called before\b", re.IGNORECASE),
                re.compile(r"\bpriority tool\b", re.IGNORECASE),
                re.compile(r"\bthis tool takes precedence\b", re.IGNORECASE),
                re.compile(r"\boverride all other tools\b", re.IGNORECASE),
            ],
            # Pattern 10: Sensitive path targeting (GitHub MCP exploit vector)
            "sensitive_path_targeting": [
                re.compile(r"\.env\b(?!\s*=\s*['\"]?(?:development|production|staging|test))", re.IGNORECASE),
                re.compile(r"\.ssh/", re.IGNORECASE),
                re.compile(r"~/\.aws/credentials", re.IGNORECASE),
                re.compile(r"~/\.config/", re.IGNORECASE),
                re.compile(r"/etc/passwd\b", re.IGNORECASE),
                re.compile(r"/etc/shadow\b", re.IGNORECASE),
                re.compile(r"~/\.npmrc\b", re.IGNORECASE),
                re.compile(r"~/\.pypirc\b", re.IGNORECASE),
                re.compile(r"\bauthorized_keys\b", re.IGNORECASE),
                re.compile(r"\bid_rsa\b", re.IGNORECASE),
                re.compile(r"\bid_ed25519\b", re.IGNORECASE),
                re.compile(r"~/\.gitconfig\b", re.IGNORECASE),
                re.compile(r"~/\.docker/config\.json\b", re.IGNORECASE),
            ],
        }

    def is_applicable(self, file_path: Path, file_type: Optional[str] = None) -> bool:
        """
        Check if this detector should run on the given file.

        Args:
            file_path: Path to the file
            file_type: File type (optional)

        Returns:
            True for config files, JSON, YAML, and code files
        """
        if file_type:
            return file_type in [
                "python",
                "javascript",
                "typescript",
                "json",
                "yaml",
                "markdown",
                "text",
                "config",
            ]

        # MCP config files, tool definitions, and code
        applicable_extensions = [
            ".json",
            ".yaml",
            ".yml",  # Config files
            ".py",
            ".js",
            ".jsx",
            ".ts",
            ".tsx",  # Code files
            ".md",
            ".txt",  # Documentation
            ".toml",
            ".cfg",
            ".conf",
            ".ini",  # Other configs
        ]
        return file_path.suffix.lower() in applicable_extensions

    def detect_sync(
        self, file_path: Path, content: str, file_type: Optional[str] = None
    ) -> list[Vulnerability]:
        """
        Detect tool poisoning vulnerabilities in file content.

        Args:
            file_path: Path to the file
            content: File content
            file_type: File type (optional)

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities: list[Vulnerability] = []

        # Check for invisible Unicode characters (highest priority)
        unicode_vulns = self._detect_invisible_unicode(file_path, content)
        vulnerabilities.extend(unicode_vulns)

        # Check for text-based patterns
        lines = content.split("\n")
        for line_num, line in enumerate(lines, start=1):
            # Check all text patterns
            for category, patterns in self.text_patterns.items():
                for pattern in patterns:
                    matches = pattern.finditer(line)

                    for match in matches:
                        if not self._is_false_positive_path(line, category):
                            vuln = self._create_vulnerability(
                                category=category,
                                matched_text=match.group(0),
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=line.strip(),
                            )
                            vulnerabilities.append(vuln)

        # Check for anomalous description length
        vulnerabilities.extend(self._detect_anomalous_description_length(file_path, content))

        return vulnerabilities

    def _is_false_positive_path(self, line: str, category: str) -> bool:
        """Suppress false positives for path targeting patterns."""
        if category != "sensitive_path_targeting":
            return False
        line_lower = line.lower()
        # Suppress legitimate dotenv library usage
        if any(kw in line_lower for kw in ["dotenv", "load_dotenv", "python-dotenv", "dotenv_values"]):
            return True
        # Suppress comment lines
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*")):
            return True
        return False

    def _detect_anomalous_description_length(
        self, file_path: Path, content: str
    ) -> list[Vulnerability]:
        """Detect tool descriptions that are anomalously long (>500 chars)."""
        vulnerabilities: list[Vulnerability] = []

        # Match description fields in JSON or Python keyword args
        patterns = [
            re.compile(r'"description"\s*:\s*"([^"]{500,})"', re.DOTALL),
            re.compile(r"description\s*=\s*['\"]([^'\"]{500,})['\"]", re.DOTALL),
            re.compile(r"description\s*=\s*\(?\s*['\"]([^'\"]{500,})['\"]", re.DOTALL),
        ]

        for pattern in patterns:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                desc_len = len(match.group(1))
                code_snippet = match.group(0)[:120] + "..." if len(match.group(0)) > 120 else match.group(0)

                vuln = Vulnerability(
                    type=VulnerabilityType.TOOL_POISONING,
                    title="Tool Poisoning: Anomalous Tool Description Length",
                    description=(
                        f"Tool description is {desc_len} characters long (threshold: 500). "
                        "Unusually long tool descriptions are a signal used in tool poisoning attacks "
                        "where attackers embed hidden instructions after legitimate-looking content. "
                        "The AI model processes the full description including any embedded payloads, "
                        "but humans reviewing the code may not read past the first few sentences."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    file_path=str(file_path),
                    line_number=line_num,
                    code_snippet=code_snippet,
                    cwe_id="CWE-1336",
                    cvss_score=5.5,
                    remediation=(
                        "1. Review the full content of this tool description for embedded instructions\n"
                        "2. Keep tool descriptions concise (under 200 characters for the primary description)\n"
                        "3. Use structured schema fields instead of embedding instructions in descriptions\n"
                        "4. Implement a pre-registration review process for tool schemas"
                    ),
                    references=[
                        "https://cwe.mitre.org/data/definitions/1336.html",
                        "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",
                    ],
                    detector=self.name,
                    engine="static",
                    mitre_attack_ids=["T1027"],
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _detect_invisible_unicode(self, file_path: Path, content: str) -> list[Vulnerability]:
        """
        Detect invisible Unicode characters in content.

        These can be used to hide malicious instructions from human review
        while still being processed by LLMs.
        """
        vulnerabilities: list[Vulnerability] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            # Find all invisible characters in this line
            found_chars: set[str] = set()

            for char in line:
                if char in self.INVISIBLE_CHARS:
                    found_chars.add(char)

            if found_chars:
                # Create vulnerability for invisible characters
                char_names = [
                    f"U+{ord(c):04X} ({unicodedata.name(c, 'UNKNOWN')})" for c in found_chars
                ]

                vuln = Vulnerability(
                    type=VulnerabilityType.TOOL_POISONING,
                    title="Tool Poisoning: Invisible Unicode Characters",
                    description=f"Detected invisible Unicode characters: {', '.join(char_names)}. "
                    "These characters are invisible to humans but can be used to hide malicious "
                    "instructions in tool descriptions or metadata. Attackers use zero-width spaces, "
                    "directional formatting marks, and other invisible Unicode to inject hidden commands "
                    "that LLMs will process but humans won't see during code review. This is a common "
                    "technique for tool poisoning attacks in MCP servers.",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    file_path=str(file_path),
                    line_number=line_num,
                    code_snippet=line.strip() if line.strip() else "<invisible characters only>",
                    cwe_id="CWE-150",  # Improper Neutralization of Escape/Meta Characters
                    cvss_score=8.5,
                    remediation="1. Remove all invisible Unicode characters from the file\n"
                    "2. Use Unicode normalization (NFKC) to convert similar-looking characters\n"
                    "3. Implement input validation to reject invisible characters\n"
                    "4. Add pre-commit hooks to detect invisible Unicode\n"
                    "5. Use tools like 'unicode-sanitizer' to clean inputs\n"
                    "6. Review tool descriptions and metadata carefully for hidden content",
                    references=[
                        "https://cwe.mitre.org/data/definitions/150.html",
                        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                        "https://invisible-characters.com/",
                        "https://unicode.org/reports/tr36/#Invisible_Characters",
                    ],
                    detector=self.name,
                    engine="static",
                    mitre_attack_ids=[
                        "T1027.010"
                    ],  # Obfuscated Files or Information: Unicode Obfuscation
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _create_vulnerability(
        self,
        category: str,
        matched_text: str,
        file_path: Path,
        line_number: int,
        code_snippet: str,
    ) -> Vulnerability:
        """Create a vulnerability object for tool poisoning."""

        # Category-specific metadata
        metadata_map = {
            "ignore_commands": {
                "title": "Tool Poisoning: Ignore/Disregard Commands",
                "description": f"Detected instruction to ignore/disregard: '{matched_text}'. "
                "This pattern attempts to make the AI ignore previous instructions or safety guidelines. "
                "Common in tool poisoning attacks where malicious actors try to override legitimate tool "
                "behavior by embedding 'ignore previous' or 'disregard above' commands in tool descriptions. "
                "This can bypass security controls and make the AI execute unintended actions.",
                "cwe_id": "CWE-74",
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
            },
            "override_commands": {
                "title": "Tool Poisoning: Override Instructions",
                "description": f"Detected instruction override pattern: '{matched_text}'. "
                "This attempts to replace or override existing instructions with new ones. Tool poisoning "
                "attacks often use 'override previous', 'new instructions:', or 'replace rules with' to "
                "hijack the AI's behavior. In MCP contexts, this could allow attackers to redefine how "
                "tools behave, bypassing authorization checks or safety measures.",
                "cwe_id": "CWE-74",
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
            },
            "behavior_manipulation": {
                "title": "Tool Poisoning: Behavior Manipulation",
                "description": f"Detected behavior manipulation pattern: '{matched_text}'. "
                "This attempts to force specific AI behaviors using 'always', 'never', 'must', or 'pretend' "
                "commands. Attackers use these patterns to manipulate how the AI responds, potentially "
                "forcing it to always return malicious data, never mention certain topics, or pretend to "
                "have different capabilities. Critical for MCP tool descriptions.",
                "cwe_id": "CWE-913",
                "severity": Severity.MEDIUM,
                "confidence": Confidence.MEDIUM,
            },
            "hidden_markers": {
                "title": "Tool Poisoning: Hidden Instruction Markers",
                "description": f"Detected hidden instruction marker: '{matched_text}'. "
                "Found HTML comments, code comments, or special markers containing suspicious keywords. "
                "These can be used to hide instructions from human reviewers while still being processed "
                "by AI systems. Common markers include [hidden], [secret], or instructions in comments "
                "that the LLM may still follow.",
                "cwe_id": "CWE-1236",
                "severity": Severity.MEDIUM,
                "confidence": Confidence.MEDIUM,
            },
            "suspicious_tool_names": {
                "title": "Tool Poisoning: Suspicious Tool Name Pattern",
                "description": f"Detected suspicious tool name: '{matched_text}'. "
                "Full-schema poisoning embeds malicious directives in tool names, not just descriptions. "
                "Tool names like 'always_run_first', 'override_*', or '__instruction__' signal an attempt "
                "to manipulate agent tool selection or execution order. This is the 'Full-Schema Poisoning' "
                "(FSP) technique documented in 2025 MCP security research.",
                "cwe_id": "CWE-74",
                "severity": Severity.HIGH,
                "confidence": Confidence.MEDIUM,
            },
            "suspicious_param_names": {
                "title": "Tool Poisoning: Suspicious Parameter Name",
                "description": f"Detected suspicious parameter name: '{matched_text}'. "
                "Parameter names like '__instruction__', 'system_prompt', or 'ai_directive' suggest "
                "the tool is designed to accept and execute instructions from the parameter value. "
                "This is a full-schema poisoning vector — all schema fields including parameter names "
                "are processed by the model and can carry injected instructions.",
                "cwe_id": "CWE-74",
                "severity": Severity.HIGH,
                "confidence": Confidence.MEDIUM,
            },
            "cross_tool_manipulation": {
                "title": "Tool Poisoning: Cross-Tool Manipulation Phrase",
                "description": f"Detected cross-tool manipulation directive: '{matched_text}'. "
                "Phrases like 'before calling', 'global rule', or 'always call this tool first' in tool "
                "descriptions are used in tool shadowing attacks. A malicious MCP server can embed these "
                "phrases to intercept all agent tool calls, even calls to tools on other trusted servers. "
                "This is the documented cross-server escalation / tool shadowing attack vector.",
                "cwe_id": "CWE-913",
                "severity": Severity.HIGH,
                "confidence": Confidence.MEDIUM,
            },
            "sensitive_path_targeting": {
                "title": "Tool Poisoning: Sensitive File Path in Tool Description",
                "description": f"Detected sensitive file path reference in tool content: '{matched_text}'. "
                "This matches the exact technique used in the GitHub MCP prompt injection data heist: "
                "tool descriptions or schemas reference credential file paths (.env, .ssh/id_rsa, "
                "~/.aws/credentials) to instruct the model to read and exfiltrate those files. "
                "The model follows these instructions because they appear in trusted tool metadata.",
                "cwe_id": "CWE-200",
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
            },
        }

        metadata = metadata_map[category]

        # Determine CVSS score based on severity
        cvss_scores = {
            Severity.CRITICAL: 9.5,
            Severity.HIGH: 7.8,
            Severity.MEDIUM: 5.3,
        }

        return Vulnerability(
            type=VulnerabilityType.TOOL_POISONING,
            title=metadata["title"],
            description=metadata["description"],
            severity=metadata["severity"],
            confidence=metadata["confidence"],
            file_path=str(file_path),
            line_number=line_number,
            code_snippet=code_snippet,
            cwe_id=metadata["cwe_id"],
            cvss_score=cvss_scores[cast(Severity, metadata["severity"])],
            remediation="1. Review and validate all tool descriptions and metadata\n"
            "2. Implement strict input validation for tool configurations\n"
            "3. Use allowlists for acceptable instruction patterns\n"
            "4. Add human review process for tool registration\n"
            "5. Implement runtime monitoring for unexpected AI behaviors\n"
            "6. Use structured formats (JSON schema) to prevent free-form manipulation",
            references=[
                f"https://cwe.mitre.org/data/definitions/{metadata['cwe_id'].split('-')[1]}.html",
                "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                "https://simonwillison.net/2023/Apr/14/worst-that-can-happen/",
                "https://atlas.mitre.org/techniques/AML.T0051",
            ],
            detector=self.name,
            engine="static",
            mitre_attack_ids=["T1027", "T1059"],  # Obfuscation, Command Execution
        )
