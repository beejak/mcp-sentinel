"""
Prompt injection detector for finding AI/LLM prompt manipulation vulnerabilities.

Detects:
- Role manipulation attempts ("you are now", "act as", "pretend to be")
- System prompt indicators and leakage
- Role assignment patterns in configuration
- Jailbreak keywords and attempts
"""

import re
from pathlib import Path
from re import Pattern

from mcp_sentinel.detectors.base import BaseDetector
from mcp_sentinel.models.vulnerability import (
    Confidence,
    Severity,
    Vulnerability,
    VulnerabilityType,
)


class PromptInjectionDetector(BaseDetector):
    """
    Detector for prompt injection and jailbreak attempts.

    Detects 4 pattern families across various contexts:
    - Role manipulation ("you are now", "act as")
    - System prompt indicators
    - Role assignment in configs
    - Jailbreak keywords
    """

    def __init__(self):
        """Initialize the prompt injection detector."""
        super().__init__(name="PromptInjectionDetector", enabled=True)
        self.patterns: dict[str, list[Pattern]] = self._compile_patterns()

    def _compile_patterns(self) -> dict[str, list[Pattern]]:
        """Compile regex patterns for prompt injection detection."""
        return {
            # Family 1: Role Manipulation
            "role_manipulation": [
                re.compile(r"\byou\s+are\s+now\b", re.IGNORECASE),
                re.compile(r"\bact\s+as\b", re.IGNORECASE),
                re.compile(r"\bpretend\s+to\s+be\b", re.IGNORECASE),
                re.compile(r"\byou\s+must\s+act\b", re.IGNORECASE),
                re.compile(r"\bfrom\s+now\s+on\b", re.IGNORECASE),
                re.compile(r"\byou\s+will\s+be\b", re.IGNORECASE),
                re.compile(r"\bbecome\s+a\b", re.IGNORECASE),
            ],
            # Family 2: System Prompt Indicators
            "system_prompt": [
                re.compile(r"\bsystem\s+prompt\b", re.IGNORECASE),
                re.compile(r"\bsystem\s+message\b", re.IGNORECASE),
                re.compile(r"\bsystem:\s*", re.IGNORECASE),
                re.compile(r"\bassistant\s+prompt\b", re.IGNORECASE),
                re.compile(r"\bprompt\s+template\b", re.IGNORECASE),
            ],
            # Family 3: Role Assignment (in configs/code)
            "role_assignment": [
                re.compile(r"[\"']role[\"']\s*:\s*[\"']system[\"']", re.IGNORECASE),
                re.compile(r"[\"']role[\"']\s*:\s*[\"']assistant[\"']", re.IGNORECASE),
                re.compile(r"[\"']role[\"']\s*:\s*[\"']user[\"']", re.IGNORECASE),
                re.compile(r"\brole\s*=\s*[\"']system[\"']", re.IGNORECASE),
            ],
            # Family 4: Jailbreak Keywords
            "jailbreak": [
                re.compile(r"\bjailbreak\b", re.IGNORECASE),
                re.compile(r"\bdan\s+mode\b", re.IGNORECASE),
                re.compile(r"\bdeveloper\s+mode\b", re.IGNORECASE),
                re.compile(r"\bgod\s+mode\b", re.IGNORECASE),
                re.compile(r"\bignore\s+previous\b", re.IGNORECASE),
                re.compile(r"\bignore\s+prior\b", re.IGNORECASE),
                re.compile(r"\bignore\s+above\b", re.IGNORECASE),
                re.compile(r"\bdisregard\s+previous\b", re.IGNORECASE),
                re.compile(r"\bforget\s+previous\b", re.IGNORECASE),
            ],
        }

    def is_applicable(self, file_path: Path, file_type: str | None = None) -> bool:
        """
        Check if this detector should run on the given file.

        Args:
            file_path: Path to the file
            file_type: File type (optional)

        Returns:
            True for text files, configs, prompts, and code files
        """
        if file_type:
            # Apply to most file types that could contain prompts
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

        # Check file extension
        applicable_extensions = [
            ".py",
            ".js",
            ".jsx",
            ".ts",
            ".tsx",
            ".json",
            ".yaml",
            ".yml",
            ".txt",
            ".md",
            ".prompt",
            ".cfg",
            ".conf",
            ".config",
        ]
        return file_path.suffix.lower() in applicable_extensions

    async def detect(
        self, file_path: Path, content: str, file_type: str | None = None
    ) -> list[Vulnerability]:
        """
        Detect prompt injection vulnerabilities in file content.

        Args:
            file_path: Path to the file
            content: File content
            file_type: File type (optional)

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities: list[Vulnerability] = []
        lines = content.split("\n")

        # Scan for each pattern family
        for family_name, patterns in self.patterns.items():
            for pattern in patterns:
                for line_num, line in enumerate(lines, start=1):
                    # Skip obvious comments in code files
                    stripped = line.strip()
                    if self._is_comment(stripped, file_path):
                        continue

                    matches = pattern.finditer(line)

                    for match in matches:
                        # Check for false positives
                        if self._is_likely_false_positive(line, match.group(0), family_name):
                            continue

                        vuln = self._create_vulnerability(
                            family_name=family_name,
                            pattern_text=pattern.pattern,
                            matched_text=match.group(0),
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=line.strip(),
                        )
                        vulnerabilities.append(vuln)

        return vulnerabilities

    def _is_comment(self, line: str, file_path: Path) -> bool:
        """Check if a line is a comment based on file type."""
        if not line:
            return False

        # Python comments
        if file_path.suffix in [".py"]:
            return line.startswith("#")

        # JavaScript/TypeScript comments
        if file_path.suffix in [".js", ".jsx", ".ts", ".tsx"]:
            return line.startswith("//") or line.startswith("/*")

        # YAML comments
        if file_path.suffix in [".yaml", ".yml"]:
            return line.startswith("#")

        return False

    def _is_likely_false_positive(self, line: str, matched_text: str, family_name: str) -> bool:
        """
        Check if a match is likely a false positive.

        Args:
            line: The full line of code
            matched_text: The matched text
            family_name: The pattern family name

        Returns:
            True if likely false positive, False otherwise
        """
        line_lower = line.lower()

        # For role_manipulation family, check for educational/documentation context
        if family_name == "role_manipulation":
            # Educational/tutorial indicators
            educational_keywords = [
                "tutorial",
                "teach",
                "learn",
                "example",
                "guide",
                "documentation",
                "lesson",
                "course",
                "training",
                "instruction",
                "how to",
                "better",
            ]
            if any(keyword in line_lower for keyword in educational_keywords):
                # Specific pattern checks for common false positives
                if "become a" in matched_text.lower():
                    # "become a better/good/great X" is likely legitimate
                    if any(
                        word in line_lower for word in ["better", "good", "great", "professional"]
                    ):
                        return True

                if "act as" in matched_text.lower():
                    # "act as a responsible/professional X" is likely legitimate
                    if any(
                        word in line_lower for word in ["responsible", "professional", "ethical"]
                    ):
                        return True

        # For system_prompt family, check if match is inside a JSON string value
        if family_name == "system_prompt":
            # Check if the matched text is inside quotes (JSON string value)
            # Find position of matched text in line
            match_pos = line.find(matched_text)
            if match_pos == -1:
                return False

            # Check for JSON pattern: "key": "value"
            before_match = line[:match_pos]
            # If we see a colon before the match and quotes around it, it's a JSON value
            if '":' in before_match or "': " in before_match or "':" in before_match:
                # This looks like a JSON/dict value, likely false positive
                return True

            # Also check if the line contains "content": which is typical for JSON messages
            if '"content"' in line or "'content'" in line:
                # And the matched text appears after "content":
                content_pos = max(line.find('"content"'), line.find("'content'"))
                if content_pos != -1 and content_pos < match_pos:
                    # Matched text is after "content" key, likely the value
                    return True

        return False

    def _create_vulnerability(
        self,
        family_name: str,
        pattern_text: str,
        matched_text: str,
        file_path: Path,
        line_number: int,
        code_snippet: str,
    ) -> Vulnerability:
        """Create a vulnerability object for prompt injection."""

        # Family-specific metadata
        metadata_map = {
            "role_manipulation": {
                "title": "Prompt Injection: Role Manipulation",
                "description": f"Detected role manipulation pattern '{matched_text}'. "
                "This pattern is commonly used in prompt injection attacks to manipulate "
                "AI assistants into acting outside their intended role or ignoring safety "
                "guidelines. Attackers use phrases like 'you are now', 'act as', or "
                "'pretend to be' to override system instructions.",
                "cwe_id": "CWE-94",
                "severity": Severity.HIGH,
                "confidence": Confidence.MEDIUM,
                "remediation": "1. Validate and sanitize all user inputs before including in prompts\n"
                "2. Use input filtering to detect and block manipulation attempts\n"
                "3. Implement role-based access controls for prompt construction\n"
                "4. Add guardrails to detect attempts to override system role\n"
                "5. Consider using instruction hierarchies with system prompts taking precedence",
            },
            "system_prompt": {
                "title": "Prompt Injection: System Prompt Exposure",
                "description": f"Detected system prompt indicator '{matched_text}'. "
                "This may indicate exposure of system prompts or internal instructions. "
                "System prompts should remain confidential as they can be used to craft "
                "targeted attacks or reveal sensitive information about the AI's behavior "
                "and limitations.",
                "cwe_id": "CWE-200",
                "severity": Severity.HIGH,
                "confidence": Confidence.MEDIUM,
                "remediation": "1. Never include system prompts in user-accessible output\n"
                "2. Implement output filtering to prevent prompt leakage\n"
                "3. Use separate contexts for system and user content\n"
                "4. Avoid echoing or logging full prompts in production\n"
                "5. Add detection for prompt extraction attempts",
            },
            "role_assignment": {
                "title": "Prompt Injection: Role Assignment Pattern",
                "description": f"Detected role assignment pattern '{matched_text}'. "
                "Found structured role assignment in configuration or code. While not "
                "always malicious, improper role assignments can lead to privilege "
                "escalation where users gain system-level access to the AI. This pattern "
                "should be carefully reviewed to ensure proper access controls.",
                "cwe_id": "CWE-269",
                "severity": Severity.MEDIUM,
                "confidence": Confidence.MEDIUM,
                "remediation": "1. Review all role assignments for proper authorization\n"
                "2. Ensure 'system' role is only used in trusted contexts\n"
                "3. Validate role parameters against whitelist of allowed values\n"
                "4. Implement strict access controls for role configuration\n"
                "5. Audit role usage and detect unauthorized escalations",
            },
            "jailbreak": {
                "title": "Prompt Injection: Jailbreak Attempt",
                "description": f"Detected jailbreak keyword '{matched_text}'. "
                "This pattern is strongly associated with jailbreak attempts designed to "
                "bypass AI safety measures and content policies. Common jailbreak techniques "
                "include 'DAN mode' (Do Anything Now), 'developer mode', or instructions to "
                "'ignore previous' constraints. These represent serious security risks.",
                "cwe_id": "CWE-863",
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "remediation": "1. Implement strict input validation and filtering\n"
                "2. Block known jailbreak patterns and keywords\n"
                "3. Add rate limiting to detect repeated bypass attempts\n"
                "4. Log and alert on jailbreak attempts for security monitoring\n"
                "5. Use constitutional AI or similar techniques for robust safety\n"
                "6. Consider rejecting requests containing these patterns entirely",
            },
        }

        metadata = metadata_map[family_name]

        # Determine CVSS score based on severity
        cvss_scores = {
            Severity.CRITICAL: 9.1,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.3,
        }

        return Vulnerability(
            type=VulnerabilityType.PROMPT_INJECTION,
            title=metadata["title"],
            description=metadata["description"],
            severity=metadata["severity"],
            confidence=metadata["confidence"],
            file_path=str(file_path),
            line_number=line_number,
            code_snippet=code_snippet,
            cwe_id=metadata["cwe_id"],
            cvss_score=cvss_scores[metadata["severity"]],
            remediation=metadata["remediation"],
            references=[
                f"https://cwe.mitre.org/data/definitions/{metadata['cwe_id'].split('-')[1]}.html",
                "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                "https://simonwillison.net/2023/Apr/14/worst-that-can-happen/",
                "https://learnprompting.org/docs/prompt_hacking/injection",
            ],
            detector=self.name,
            engine="static",
            mitre_attack_ids=["T1055"],  # Process Injection (closest mapping)
        )
