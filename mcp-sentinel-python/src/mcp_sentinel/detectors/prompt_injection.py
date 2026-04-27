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
from re import Match, Pattern

from mcp_sentinel.detectors.base import BaseDetector
from mcp_sentinel.models.vulnerability import (
    Confidence,
    Severity,
    Vulnerability,
    VulnerabilityType,
)

# JSON/Python-style ``"content":`` / ``'content':`` key near a ``role`` field (Chat API payloads).
_CHAT_API_CONTENT_KEY = re.compile(r"""["']content["']\s*:""")


def _skip_quoted_string(text: str, start: int) -> int:
    """Advance past a ``"..."`` or ``'...'`` segment starting at ``start`` (opening quote)."""
    if start >= len(text):
        return len(text)
    quote = text[start]
    if quote not in "\"'":
        return start + 1
    i = start + 1
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == quote:
            return i + 1
        i += 1
    return len(text)


def _skip_block_comment(text: str, start: int) -> int:
    """Advance past a C-style ``/* ... */`` block starting at ``start``."""
    if start + 1 >= len(text) or text[start : start + 2] != "/*":
        return start
    i = start + 2
    while i + 1 < len(text):
        if text[i : i + 2] == "*/":
            return i + 2
        i += 1
    return len(text)


def _skip_line_comment_slash(text: str, start: int) -> int:
    """Advance past ``// ...`` to newline (guards ``://`` in URLs)."""
    if start + 1 >= len(text) or text[start : start + 2] != "//":
        return start
    if start > 0 and text[start - 1] == ":":
        return start
    i = start + 2
    while i < len(text) and text[i] != "\n":
        i += 1
    return i


def _skip_line_comment_hash(text: str, start: int) -> int:
    """Advance past ``# ...`` to newline (Python-style)."""
    if start >= len(text) or text[start] != "#":
        return start
    i = start + 1
    while i < len(text) and text[i] != "\n":
        i += 1
    return i


def _innermost_brace_open_before(text: str, anchor: int) -> int | None:
    """
    Return the index of the innermost ``{{`` whose matching ``}}`` encloses ``anchor``.

    Skips strings, ``/* */``, ``//``, and ``#`` line comments. Tracks ``[`` / ``]`` so nested
    arrays and objects align with JSON/JS structure. If ``anchor`` lies inside a string or
    comment, returns ``None``.
    """
    if anchor <= 0 or anchor > len(text):
        return None
    stack: list[tuple[str, int]] = []
    i = 0
    while i < anchor:
        ch = text[i]
        if ch in "\"'":
            end = _skip_quoted_string(text, i)
            if i < anchor < end:
                return None
            i = end
            continue
        if i + 1 < len(text) and text[i : i + 2] == "/*":
            end = _skip_block_comment(text, i)
            if i < anchor < end:
                return None
            i = end
            continue
        if i + 1 < len(text) and text[i : i + 2] == "//":
            end = _skip_line_comment_slash(text, i)
            if end == i:
                i += 1
                continue
            if i < anchor < end:
                return None
            i = end
            continue
        if ch == "#":
            end = _skip_line_comment_hash(text, i)
            if i < anchor < end:
                return None
            i = end
            continue
        if ch == "[":
            stack.append(("[", i))
            i += 1
        elif ch == "{":
            stack.append(("{", i))
            i += 1
        elif ch == "}":
            while stack and stack[-1][0] != "{":
                stack.pop()
            if stack and stack[-1][0] == "{":
                stack.pop()
            i += 1
        elif ch == "]":
            while stack and stack[-1][0] == "{":
                stack.pop()
            if stack and stack[-1][0] == "[":
                stack.pop()
            i += 1
        else:
            i += 1
    for kind, pos in reversed(stack):
        if kind == "{":
            return pos
    return None


def _matching_close_brace(text: str, open_idx: int) -> int | None:
    """Index of the ``}}`` matching ``{{`` at ``open_idx``, or ``None`` if unbalanced."""
    if open_idx >= len(text) or text[open_idx] != "{":
        return None
    depth = 0
    i = open_idx
    while i < len(text):
        ch = text[i]
        if ch in "\"'":
            i = _skip_quoted_string(text, i)
            continue
        if i + 1 < len(text) and text[i : i + 2] == "/*":
            i = _skip_block_comment(text, i)
            continue
        if i + 1 < len(text) and text[i : i + 2] == "//":
            ni = _skip_line_comment_slash(text, i)
            if ni == i:
                i += 1
            else:
                i = ni
            continue
        if ch == "#":
            i = _skip_line_comment_hash(text, i)
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _block_comment_spans_line(line: str) -> list[tuple[int, int]]:
    """Return ``(start, end)`` spans for ``/* ... */`` on a single line."""
    spans: list[tuple[int, int]] = []
    i = 0
    while i < len(line):
        if i + 1 < len(line) and line[i : i + 2] == "/*":
            close = line.find("*/", i + 2)
            if close == -1:
                spans.append((i, len(line)))
                break
            spans.append((i, close + 2))
            i = close + 2
            continue
        i += 1
    return spans


def _slash_line_comment_span(line: str) -> tuple[int, int] | None:
    """Span of ``// ...`` through end-of-line if present (guards ``://``)."""
    i = 0
    while i + 1 < len(line):
        if line[i : i + 2] == "//" and (i == 0 or line[i - 1] != ":"):
            return (i, len(line))
        i += 1
    return None


def _match_offset_in_skipped_comment(line: str, offset: int) -> bool:
    """True if ``offset`` falls inside a ``/* */`` block or ``//`` line comment on ``line``."""
    for a, b in _block_comment_spans_line(line):
        if a <= offset < b:
            return True
    sl = _slash_line_comment_span(line)
    if sl and sl[0] <= offset < sl[1]:
        return True
    return False


def _chat_api_content_key_in_same_brace_dict(full_text: str, anchor: int) -> bool:
    """True if ``full_text`` has a quoted ``content`` key inside the brace object enclosing ``anchor``."""
    open_brace = _innermost_brace_open_before(full_text, anchor)
    if open_brace is None:
        return False
    close_brace = _matching_close_brace(full_text, open_brace)
    if close_brace is None:
        return False
    span = full_text[open_brace : close_brace + 1]
    return bool(_CHAT_API_CONTENT_KEY.search(span))


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
        seen_line_family_match: set[tuple[int, str, str]] = set()

        # Scan for each pattern family
        for family_name, patterns in self.patterns.items():
            for pattern in patterns:
                for line_num, line in enumerate(lines, start=1):
                    # Skip obvious comments in code files
                    stripped = line.strip()
                    if self._is_comment(stripped, file_path):
                        continue

                    if self._is_role_json_line_suppressing_system_prompt(
                        line, family_name
                    ):
                        continue

                    matches = pattern.finditer(line)

                    for match in matches:
                        if _match_offset_in_skipped_comment(line, match.start()):
                            continue
                        if self._is_benign_role_manipulation(line, match.group(0), family_name):
                            continue
                        if self._is_benign_chat_api_role_assignment(
                            content,
                            family_name,
                            match,
                            lines,
                            line_num,
                        ):
                            continue
                        key = (line_num, family_name, match.group(0))
                        if key in seen_line_family_match:
                            continue
                        seen_line_family_match.add(key)
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

    def _is_role_json_line_suppressing_system_prompt(self, line: str, family_name: str) -> bool:
        """Avoid flagging chat JSON 'system' role lines as system-prompt extraction."""
        if family_name != "system_prompt":
            return False
        if '"role"' not in line and "'role'" not in line:
            return False
        return '"content"' in line or "'content'" in line

    def _is_benign_role_manipulation(self, line: str, matched: str, family_name: str) -> bool:
        """Skip common educational phrasing for role_manipulation."""
        if family_name != "role_manipulation":
            return False
        ll = line.lower()
        if "act as" in matched.lower() and any(
            phrase in ll
            for phrase in (
                "act as a responsible",
                "act as a good",
                "act as a professional",
                "act as an ethical",
            )
        ):
            return True
        return False

    def _is_benign_chat_api_role_assignment(
        self,
        full_text: str,
        family_name: str,
        match: Match[str],
        lines: list[str],
        line_num: int,
    ) -> bool:
        """
        Skip OpenAI/Anthropic-style payloads: ``user`` / ``assistant`` with a ``content`` key
        in the **same brace-delimited object** as the ``role`` field (string-aware brace matching).

        Still flag ``role: system`` and bare ``role: user`` objects with no sibling ``content``.
        """
        if family_name != "role_assignment":
            return False
        ms = match.group(0).lower()
        is_user_or_assistant = (
            '"user"' in ms
            or "'user'" in ms
            or '"assistant"' in ms
            or "'assistant'" in ms
        )
        if not is_user_or_assistant:
            return False

        idx = line_num - 1
        line_offset = sum(len(lines[i]) + 1 for i in range(idx))
        anchor = line_offset + match.start()
        return _chat_api_content_key_in_same_brace_dict(full_text, anchor)

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
