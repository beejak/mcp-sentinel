"""
XSS (Cross-Site Scripting) vulnerability detector for MCP security.

Detects various types of XSS vulnerabilities including DOM-based, stored,
and reflected XSS patterns in web application code.

Critical for MCP servers that serve web UIs or handle HTML/JavaScript generation.
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


class XSSDetector(BaseDetector):
    """
    Detector for Cross-Site Scripting (XSS) vulnerabilities.

    Detects 6 critical XSS patterns:
    1. DOM-based XSS (innerHTML, outerHTML manipulation)
    2. Reflected XSS (unescaped user input in responses)
    3. Stored XSS (unescaped data from storage)
    4. Event handler injection (onclick, onerror, onload)
    5. JavaScript URL schemes (javascript:, data:text/html)
    6. Dangerous sinks (document.write, eval with HTML)
    """

    def __init__(self):
        """Initialize the XSS detector."""
        super().__init__(name="XSSDetector", enabled=True)
        self.patterns: dict[str, list[Pattern]] = self._compile_patterns()

    def _compile_patterns(self) -> dict[str, list[Pattern]]:
        """Compile regex patterns for XSS detection."""
        return {
            # Pattern 1: DOM-based XSS (innerHTML manipulation)
            "dom_xss": [
                re.compile(r"\.innerHTML\s*=\s*[^;]+", re.IGNORECASE),
                re.compile(r"\.outerHTML\s*=\s*[^;]+", re.IGNORECASE),
                re.compile(r"\.insertAdjacentHTML\s*\(", re.IGNORECASE),
                re.compile(
                    r"\.write\s*\(\s*[^)]*\+", re.IGNORECASE
                ),  # document.write with concatenation
                re.compile(r"\.writeln\s*\(\s*[^)]*\+", re.IGNORECASE),
            ],
            # Pattern 2: Event handler injection
            "event_handler_xss": [
                re.compile(
                    r"on(?:click|load|error|mouseover|focus|blur)\s*=\s*[\"']?\s*(?!null|false)",
                    re.IGNORECASE,
                ),
                re.compile(r"<\w+[^>]*\son\w+\s*=", re.IGNORECASE),  # HTML with event handlers
                re.compile(r"setAttribute\s*\(\s*[\"']on\w+[\"']", re.IGNORECASE),
            ],
            # Pattern 3: JavaScript URL schemes
            "javascript_protocol": [
                re.compile(r"javascript:\s*", re.IGNORECASE),
                re.compile(r"data:text/html", re.IGNORECASE),
                re.compile(r"vbscript:", re.IGNORECASE),
            ],
            # Pattern 4: Dangerous HTML insertion (React/Vue)
            "dangerous_html": [
                re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\{", re.IGNORECASE),
                re.compile(r"v-html\s*=", re.IGNORECASE),  # Vue.js
                re.compile(r"\[innerHTML\]\s*=", re.IGNORECASE),  # Angular
            ],
            # Pattern 5: Unescaped template rendering
            "template_xss": [
                # Python (Jinja2, Django) - match templates with |safe or |mark_safe filters
                re.compile(r"\{\{[^}]*\|\s*safe[^}]*\}\}", re.IGNORECASE),
                re.compile(r"\{\{[^}]*\|\s*mark_safe[^}]*\}\}", re.IGNORECASE),
                re.compile(r"\bsafe\s*\(\s*[^)]*\)"),  # Django safe() function
                # JavaScript template literals with user input
                re.compile(r"`[^`]*\$\{[^}]*(?:params|query|input|user|request)[^}]*\}[^`]*`"),
            ],
            # Pattern 6: jQuery XSS (legacy but still common)
            "jquery_xss": [
                re.compile(r"\$\([^)]*\)\.html\s*\(", re.IGNORECASE),
                re.compile(r"\$\([^)]*\)\.append\s*\([^)]*\+", re.IGNORECASE),
                re.compile(r"\$\([^)]*\)\.prepend\s*\([^)]*\+", re.IGNORECASE),
            ],
        }

    def is_applicable(self, file_path: Path, file_type: str | None = None) -> bool:
        """
        Check if this detector should run on the given file.

        Args:
            file_path: Path to the file
            file_type: File type (optional)

        Returns:
            True for web-related files (HTML, JS, TS, Python templates, etc.)
        """
        if file_type:
            return file_type in [
                "javascript",
                "typescript",
                "html",
                "python",
                "jsx",
                "tsx",
                "vue",
                "svelte",
                "template",
            ]

        # Check file extensions
        web_extensions = [
            ".html",
            ".htm",
            ".xhtml",  # HTML files
            ".js",
            ".jsx",
            ".ts",
            ".tsx",  # JavaScript/TypeScript
            ".py",
            ".jinja",
            ".jinja2",
            ".j2",  # Python templates
            ".vue",
            ".svelte",  # Modern frameworks
            ".php",
            ".asp",
            ".aspx",
            ".jsp",  # Server-side templates
        ]
        return file_path.suffix.lower() in web_extensions

    async def detect(
        self, file_path: Path, content: str, file_type: str | None = None
    ) -> list[Vulnerability]:
        """
        Detect XSS vulnerabilities in file content.

        Args:
            file_path: Path to the file
            content: File content
            file_type: File type (optional)

        Returns:
            List of detected XSS vulnerabilities
        """
        vulnerabilities: list[Vulnerability] = []
        lines = content.split("\n")
        # Track detected matches per line to avoid duplicates
        # For event handlers: track by (category, handler_name) e.g., ('event_handler_xss', 'onclick')
        # For other patterns: track by (category, position)
        detected_per_line: dict[int, set] = {}

        for line_num, line in enumerate(lines, start=1):
            # Skip comments
            if self._is_comment(line, file_type):
                continue

            # Initialize tracking for this line
            if line_num not in detected_per_line:
                detected_per_line[line_num] = set()

            # Check all pattern categories
            for category, patterns in self.patterns.items():
                for pattern in patterns:
                    matches = pattern.finditer(line)

                    for match in matches:
                        # Create a unique key for this match
                        # For event handlers, extract the handler name (onclick, onerror, etc.)
                        # to avoid reporting the same handler twice from different patterns
                        if category == "event_handler_xss":
                            # Extract event handler name (e.g., "onclick", "onerror")
                            handler_match = re.search(
                                r"\bon(click|load|error|mouseover|focus|blur|[a-z]+)",
                                match.group(0),
                                re.IGNORECASE,
                            )
                            if handler_match:
                                handler_name = handler_match.group(0).lower()
                                match_key = (category, handler_name)
                            else:
                                # Fallback to position if we can't extract handler name
                                match_key = (category, match.start())
                        else:
                            # For non-event-handler patterns, use position
                            match_key = (category, match.start())

                        # Skip if we've already reported this exact match
                        if match_key in detected_per_line[line_num]:
                            continue

                        # Additional context checks to reduce false positives
                        if not self._is_likely_false_positive(line, match.group(0), category):
                            vuln = self._create_vulnerability(
                                category=category,
                                matched_text=match.group(0),
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=line.strip(),
                            )
                            vulnerabilities.append(vuln)
                            # Mark this specific match as detected
                            detected_per_line[line_num].add(match_key)

        return vulnerabilities

    def _is_comment(self, line: str, file_type: str | None) -> bool:
        """
        Check if line is a comment.

        Args:
            line: Line of code to check
            file_type: Type of file (optional)

        Returns:
            True if the line is a comment, False otherwise
        """
        stripped = line.strip()

        # Empty lines
        if not stripped:
            return False

        # Python comments
        if stripped.startswith("#"):
            return True

        # JavaScript/CSS single-line comments
        if stripped.startswith("//"):
            return True

        # JavaScript/CSS multi-line comments
        if stripped.startswith("/*") or stripped.startswith("*"):
            return True

        # HTML comments
        if stripped.startswith("<!--") or "<!--" in stripped:
            # Check if the whole line is a comment
            if stripped.startswith("<!--") and stripped.endswith("-->"):
                return True

        return False

    def _is_likely_false_positive(self, line: str, matched_text: str, category: str) -> bool:
        """
        Check if the match is likely a false positive.

        Args:
            line: The full line of code
            matched_text: The matched pattern text
            category: The pattern category

        Returns:
            True if likely false positive, False otherwise
        """
        # Check for sanitization functions (must be function calls, not just strings)
        sanitization_patterns = [
            r"\.escape\s*\(",  # .escape(
            r"\bsanitize\s*\(",  # sanitize(
            r"\bclean\s*\(",  # clean(
            r"\bfilter\s*\(",  # filter(
            r"\.encode\s*\(",  # .encode(
            r"\bhtmlspecialchars\s*\(",  # htmlspecialchars(
            r"\bhtmlentities\s*\(",  # htmlentities(
            r"DOMPurify\.",  # DOMPurify.sanitize or DOMPurify.clean
            r"xssFilter\.",  # xssFilter.clean
        ]

        for pattern in sanitization_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True

        # For DOM XSS, check if setting to static string
        if category == "dom_xss":
            # If innerHTML = "static string", it's safe
            if (
                re.search(r'innerHTML\s*=\s*["\'][^"\']*["\']', line)
                and "+" not in line
                and "${" not in line
            ):
                return True

        # For event handlers, check if set to null or false (check full line)
        if category == "event_handler_xss":
            if re.search(r'on\w+\s*=\s*["\']?\s*(null|false)\s*["\']?', line, re.IGNORECASE):
                return True

        # For template XSS, check if using safe in test files
        if category == "template_xss":
            if "test" in str(line).lower() or "example" in str(line).lower():
                return True
            # Check if "safe()" is actually a function definition, not a call
            if re.search(r"\b(def|function)\s+safe\s*\(", line, re.IGNORECASE):
                return True
            # Check if "safe()" is a class method definition
            if re.search(r"\bclass\s+\w+.*safe\s*\(", line, re.IGNORECASE):
                return True
            # Check if "safe()" is an arrow function or method
            if re.search(r"\bconst\s+safe\s*=|let\s+safe\s*=|var\s+safe\s*=", line, re.IGNORECASE):
                return True

        return False

    def _create_vulnerability(
        self,
        category: str,
        matched_text: str,
        file_path: Path,
        line_number: int,
        code_snippet: str,
    ) -> Vulnerability:
        """Create a vulnerability object for XSS."""

        # Category-specific metadata
        metadata_map = {
            "dom_xss": {
                "title": "XSS: DOM-Based (innerHTML Manipulation)",
                "description": f"Detected dangerous DOM manipulation: '{matched_text}'. "
                "Direct manipulation of innerHTML, outerHTML, or document.write with unsanitized input "
                "can lead to XSS attacks. Attackers can inject malicious scripts that execute in the "
                "user's browser context, potentially stealing cookies, session tokens, or performing "
                "actions on behalf of the user. This is especially critical in MCP web UIs where "
                "user-provided tool descriptions or results might be rendered.",
                "cwe_id": "CWE-79",
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cvss_score": 7.4,
            },
            "event_handler_xss": {
                "title": "XSS: Event Handler Injection",
                "description": f"Detected event handler injection: '{matched_text}'. "
                "Setting event handlers (onclick, onerror, onload, etc.) with unsanitized input allows "
                "attackers to inject JavaScript that executes on user interaction. This is a common XSS "
                "vector that can bypass some sanitization filters. Particularly dangerous in MCP contexts "
                "where tool metadata might contain malicious event handlers.",
                "cwe_id": "CWE-79",
                "severity": Severity.HIGH,
                "confidence": Confidence.MEDIUM,
                "cvss_score": 7.1,
            },
            "javascript_protocol": {
                "title": "XSS: JavaScript Protocol Injection",
                "description": f"Detected javascript: or data: protocol usage: '{matched_text}'. "
                "Using javascript:, data:text/html, or vbscript: URLs can execute arbitrary JavaScript. "
                "These protocols bypass many XSS filters and are commonly used in stored XSS attacks. "
                "Never use these protocols with user-controlled input. In MCP servers, tool URLs or "
                "resource links should never use these dangerous protocols.",
                "cwe_id": "CWE-79",
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "cvss_score": 8.2,
            },
            "dangerous_html": {
                "title": "XSS: Dangerous HTML Insertion (React/Vue/Angular)",
                "description": f"Detected dangerous HTML insertion: '{matched_text}'. "
                "Using dangerouslySetInnerHTML (React), v-html (Vue), or [innerHTML] (Angular) bypasses "
                "the framework's XSS protection. This should only be used with fully trusted, sanitized "
                "HTML. Any user input passed to these properties can result in XSS. Use DOMPurify or "
                "similar sanitization libraries if HTML rendering is required.",
                "cwe_id": "CWE-79",
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cvss_score": 7.8,
            },
            "template_xss": {
                "title": "XSS: Unescaped Template Rendering",
                "description": f"Detected unescaped template rendering: '{matched_text}'. "
                "Using '|safe', 'mark_safe', or similar template filters disables automatic HTML escaping. "
                "This is dangerous when rendering user-provided content. Template engines like Jinja2 and "
                "Django automatically escape variables by default for security. Marking content as 'safe' "
                "removes this protection and can lead to stored XSS if the content comes from user input "
                "or untrusted sources.",
                "cwe_id": "CWE-79",
                "severity": Severity.MEDIUM,
                "confidence": Confidence.MEDIUM,
                "cvss_score": 6.1,
            },
            "jquery_xss": {
                "title": "XSS: jQuery HTML Injection",
                "description": f"Detected jQuery HTML manipulation: '{matched_text}'. "
                "Using jQuery's .html(), .append(), or .prepend() with string concatenation can lead to "
                "XSS if the input contains unsanitized user data. jQuery does not automatically sanitize "
                "HTML content. Use .text() instead of .html() when displaying user content, or sanitize "
                "input with DOMPurify before insertion.",
                "cwe_id": "CWE-79",
                "severity": Severity.HIGH,
                "confidence": Confidence.MEDIUM,
                "cvss_score": 7.2,
            },
        }

        metadata = metadata_map[category]

        return Vulnerability(
            type=VulnerabilityType.XSS,
            title=metadata["title"],
            description=metadata["description"],
            severity=metadata["severity"],
            confidence=metadata["confidence"],
            file_path=str(file_path),
            line_number=line_number,
            code_snippet=code_snippet,
            cwe_id=metadata["cwe_id"],
            cvss_score=metadata["cvss_score"],
            remediation="1. Always sanitize and validate user input before rendering\n"
            "2. Use framework-provided auto-escaping (enabled by default in most frameworks)\n"
            "3. Avoid innerHTML, outerHTML, and document.write with user input\n"
            "4. Use .textContent or .innerText instead of .innerHTML for text\n"
            "5. Implement Content Security Policy (CSP) headers\n"
            "6. Use DOMPurify or similar library if HTML rendering is required\n"
            "7. Never use javascript:, data:, or vbscript: protocols with user input\n"
            "8. Prefer safe framework methods: .text() in jQuery, default rendering in React",
            references=[
                "https://owasp.org/www-community/attacks/xss/",
                "https://cwe.mitre.org/data/definitions/79.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                "https://portswigger.net/web-security/cross-site-scripting",
                "https://developer.mozilla.org/en-US/docs/Web/Security/Types_of_attacks#cross-site_scripting_xss",
            ],
            detector=self.name,
            engine="static",
            mitre_attack_ids=[
                "T1189",
                "T1203",
            ],  # Drive-by Compromise, Exploitation for Client Execution
        )
