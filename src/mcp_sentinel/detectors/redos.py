"""
ReDoS (Regular Expression Denial of Service) vulnerability detector.

Detects regex patterns with catastrophic backtracking that can be exploited
for denial of service attacks:
- Nested quantifiers: (a+)+, (x*)+
- Alternation with overlap: (a|a)+
- Repeated groups: (\\w+)*
"""

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

APPLICABLE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx"}


class ReDoSDetector(BaseDetector):
    """Detector for ReDoS (Regular Expression Denial of Service) vulnerabilities."""

    def __init__(self) -> None:
        super().__init__(name="ReDoSDetector", enabled=True)
        # Patterns to extract regex content from source.
        # Require regex-literal context: preceded by = ( , [ or a keyword (new|return|case)
        # to avoid matching division operators like `value / 10 / 2`.
        self.js_regex_literal = re.compile(
            r"(?:(?:=|\(|,|\[|return|new|case)\s*)/([^/\n]{3,})/[gimsuy]*"
        )
        self.py_regex_call = re.compile(
            r"re\.(?:compile|match|search|fullmatch|sub|findall|finditer)\s*\(\s*r?[\"']([^\"']{3,})[\"']"
        )

        # Vulnerable nested quantifier patterns applied to extracted regex content
        self.vuln_patterns = [
            re.compile(r"\([^)]+[+*]\)[+*]"),          # (x+)+, (x*)+, (x+)*, (x*)*
            re.compile(r"\([^)]+\|[^)]+\)[+*\{]"),      # (a|b)+ with potential overlap
            re.compile(r"\(\\w\+[^)]*\)[+*]"),           # (\w+...)+
            re.compile(r"\(\\d\+[^)]*\)[+*]"),           # (\d+...)+
            re.compile(r"\(\\s\*[^)]*\)[+*]"),           # (\s*...)+
        ]

    def _is_vulnerable_regex(self, regex_content: str) -> bool:
        for vp in self.vuln_patterns:
            if vp.search(regex_content):
                return True
        return False

    def is_applicable(self, file_path: Path, file_type: Optional[str] = None) -> bool:
        if file_type:
            return file_type in ("python", "javascript", "typescript")
        return file_path.suffix.lower() in APPLICABLE_EXTENSIONS

    def detect_sync(
        self, file_path: Path, content: str, file_type: Optional[str] = None
    ) -> list[Vulnerability]:
        if not self.is_applicable(file_path, file_type):
            return []

        if self._is_test_file(file_path):
            return []

        findings: list[Vulnerability] = []
        lines = content.splitlines()
        is_python = (file_type == "python") or file_path.suffix.lower() == ".py"

        for i, line in enumerate(lines):
            line_num = i + 1
            extracted = []

            if is_python:
                for m in self.py_regex_call.finditer(line):
                    extracted.append(m.group(1))
            else:
                for m in self.js_regex_literal.finditer(line):
                    extracted.append(m.group(1))

            for regex_str in extracted:
                if self._is_vulnerable_regex(regex_str):
                    findings.append(
                        Vulnerability(
                            type=VulnerabilityType.REDOS,
                            title="ReDoS: Catastrophic Backtracking Regex",
                            description=(
                                f"Potentially catastrophic backtracking regex pattern: /{regex_str}/. "
                                "Nested quantifiers or alternation with overlap can cause exponential "
                                "time complexity when matching certain inputs, enabling denial of service."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet=line.strip(),
                            cwe_id="CWE-1333",
                            cvss_score=7.5,
                            remediation=(
                                "1. Avoid nested quantifiers like (a+)+ or (\\w+)*\n"
                                "2. Use atomic groups or possessive quantifiers if available\n"
                                "3. Rewrite regex to avoid ambiguity in repetitions\n"
                                "4. Use a regex linter (e.g., safe-regex, recheck)\n"
                                "5. Set a timeout for regex operations\n"
                                "6. Validate and limit input length before applying regex"
                            ),
                            references=[
                                "https://cwe.mitre.org/data/definitions/1333.html",
                                "https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS",
                                "https://portswigger.net/daily-swig/redos",
                            ],
                            detector=self.name,
                            engine="static",
                        )
                    )

        return findings
