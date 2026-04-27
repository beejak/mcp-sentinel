"""
Tool poisoning detector for MCP security.

Detects malicious manipulation of tool descriptions, hidden instructions,
and Unicode-based attacks that can poison AI behavior.

Critical for MCP servers where tool metadata influences LLM decision-making.
"""

import re
import unicodedata
from pathlib import Path
from re import Pattern

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

    Detects 6 critical patterns:
    1. Invisible Unicode characters (zero-width, RTL override)
    2. Zero-width joiners and non-joiners
    3. Ignore/disregard instruction patterns
    4. Override instruction patterns
    5. Behavior manipulation keywords
    6. Hidden instruction markers
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

    def __init__(self):
        """Initialize the tool poisoning detector."""
        super().__init__(name="ToolPoisoningDetector", enabled=True)
        self.text_patterns: dict[str, list[Pattern]] = self._compile_patterns()

    def _compile_patterns(self) -> dict[str, list[Pattern]]:
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
        }

    def is_applicable(self, file_path: Path, file_type: str | None = None) -> bool:
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

    async def detect(
        self, file_path: Path, content: str, file_type: str | None = None
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
                        vuln = self._create_vulnerability(
                            category=category,
                            matched_text=match.group(0),
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=line.strip(),
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
        }

        metadata = metadata_map[category]

        # Determine CVSS score based on severity
        cvss_scores = {
            Severity.CRITICAL: 9.1,
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
            cvss_score=cvss_scores[metadata["severity"]],
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
