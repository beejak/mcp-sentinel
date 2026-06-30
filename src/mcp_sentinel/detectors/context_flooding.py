"""Context window flooding and resource exhaustion detector."""

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

_OWASP_ID = "ASI06"
_OWASP_NAME = "Excessive Agency"

_APPLICABLE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx"}


class ContextFloodingDetector(BaseDetector):
    """
    Detects patterns that can flood the LLM context window or exhaust resources.

    Context flooding attacks inject unbounded data into an agent's context,
    crowding out system instructions, degrading output quality, or causing
    denial of service via excessive token consumption. Patterns are detectable
    statically from unbounded I/O, uncapped queries, and missing pagination.

    Covers the attack class documented in Palo Alto Networks Unit 42 (Jan 2026)
    and OWASP ASI06 (Excessive Agency).
    """

    def __init__(self) -> None:
        super().__init__(name="ContextFloodingDetector", enabled=True)
        self.line_patterns = self._compile_line_patterns()

    def _compile_line_patterns(self) -> dict[str, list]:
        return {
            "unbounded_file_read": [
                re.compile(r"\bopen\s*\([^)]+\)\s*\.read\s*\(\s*\)"),
                re.compile(r"\bPath\s*\([^)]+\)\s*\.read_text\s*\(\s*\)"),
                re.compile(r"\baiofiles\.open\b"),
                re.compile(r"\bfs\.readFileSync\s*\(", re.IGNORECASE),
                re.compile(r"\bfs\.readFile\s*\((?![^)]*maxSize)", re.IGNORECASE),
            ],
            "unbounded_directory_walk": [
                re.compile(r"\bos\.walk\s*\("),
                re.compile(r"\bglob\.glob\s*\([^)]*\*\*"),
                re.compile(r"\bPath\s*\([^)]*\)\s*\.rglob\s*\("),
                re.compile(r"\.rglob\s*\("),
                re.compile(r"\bfs\.readdirSync\s*\(", re.IGNORECASE),
                re.compile(r'readdirSync\s*\([^)]*recursive[^)]*true', re.IGNORECASE),
            ],
            "query_without_limit": [
                re.compile(
                    r"\bSELECT\b.+\bFROM\b(?!.+\bLIMIT\b)",
                    re.IGNORECASE,
                ),
                re.compile(r"\.fetchall\(\)", re.IGNORECASE),
                re.compile(r"\.all\(\)"),
                re.compile(r"\.find\s*\(\s*\{\s*\}\s*\)(?!\s*\.limit\b)"),
                re.compile(r"\.find\s*\(\s*\)\s*(?!\.limit\b)"),
            ],
            "missing_pagination": [
                re.compile(
                    r"^\s*(?:async\s+)?def\s+(?:list|get_all|fetch_all|read_all)\w*\s*\([^)]*\)"
                    r"(?:\s*->[^:]+)?\s*:",
                    re.IGNORECASE,
                ),
            ],
        }

    def is_applicable(self, file_path: Path, file_type: Optional[str] = None) -> bool:
        if file_type:
            return file_type in ("python", "javascript", "typescript")
        return file_path.suffix.lower() in _APPLICABLE_EXTENSIONS

    def detect_sync(
        self, file_path: Path, content: str, file_type: Optional[str] = None
    ) -> list[Vulnerability]:
        if self._is_test_file(file_path):
            return []

        vulns: list[Vulnerability] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//")):
                continue

            for category, patterns in self.line_patterns.items():
                for pattern in patterns:
                    if pattern.search(line):
                        if category == "missing_pagination":
                            if any(
                                kw in line.lower()
                                for kw in ("limit", "page", "offset", "cursor", "max_items", "max_results")
                            ):
                                break
                        if category == "query_without_limit":
                            # Skip if LIMIT already on the same line (e.g. inline SQL + fetchall)
                            if "limit" in line.lower():
                                break
                        vuln = self._make_vuln(category, file_path, line_num, stripped)
                        if vuln:
                            vulns.append(vuln)
                        break

        return self._deduplicate(vulns)

    def _make_vuln(
        self, category: str, file_path: Path, line_num: int, snippet: str
    ) -> Optional[Vulnerability]:
        _SPECS: dict[str, dict] = {
            "unbounded_file_read": {
                "title": "Context Flooding: Unbounded File Read in Tool Handler",
                "description": (
                    "A file is read in its entirety without a size cap. If a large or "
                    "attacker-influenced file is returned in an MCP tool response, it can "
                    "flood the LLM context window, crowd out system instructions, and cause "
                    "excessive token consumption or degraded reasoning quality."
                ),
                "severity": Severity.MEDIUM,
                "confidence": Confidence.MEDIUM,
                "cwe_id": "CWE-400",
                "cvss_score": 5.3,
                "remediation": (
                    "1. Impose a maximum read size: open(path).read(MAX_BYTES).\n"
                    "2. Return a truncation notice when content exceeds the limit.\n"
                    "3. Consider streaming or chunked responses for large files."
                ),
                "mitre": ["T1499.004"],
            },
            "unbounded_directory_walk": {
                "title": "Context Flooding: Unbounded Directory Walk",
                "description": (
                    "A recursive directory walk or glob with ** is performed without a depth "
                    "or count limit. Returning a large uncapped file listing in a tool response "
                    "can flood the LLM context window with thousands of path entries."
                ),
                "severity": Severity.MEDIUM,
                "confidence": Confidence.MEDIUM,
                "cwe_id": "CWE-770",
                "cvss_score": 5.0,
                "remediation": (
                    "1. Add a maximum depth parameter to recursive directory walks.\n"
                    "2. Cap the number of entries returned (e.g., max 100 files).\n"
                    "3. Return pagination tokens for large directories."
                ),
                "mitre": ["T1499.004", "T1083"],
            },
            "query_without_limit": {
                "title": "Context Flooding: Database Query Without Row Limit",
                "description": (
                    "A database query fetches all rows without a LIMIT clause or equivalent "
                    "cap. Returning unbounded query results in an MCP tool response can flood "
                    "the LLM context window and cause excessive latency or token costs."
                ),
                "severity": Severity.MEDIUM,
                "confidence": Confidence.LOW,
                "cwe_id": "CWE-770",
                "cvss_score": 4.3,
                "remediation": (
                    "1. Add LIMIT N to all SELECT queries exposed via MCP tools.\n"
                    "2. Implement cursor-based pagination for large result sets.\n"
                    "3. Document the maximum row count a tool can return."
                ),
                "mitre": ["T1499.004"],
            },
            "missing_pagination": {
                "title": "Context Flooding: MCP List Tool Without Pagination Parameters",
                "description": (
                    "An MCP tool function named list_* or get_all_* / fetch_all_* has no "
                    "limit, page, offset, or cursor parameter. Without pagination, this tool "
                    "may return arbitrarily large datasets, flooding the agent context and "
                    "incurring unbounded token costs."
                ),
                "severity": Severity.LOW,
                "confidence": Confidence.LOW,
                "cwe_id": "CWE-770",
                "cvss_score": 3.5,
                "remediation": (
                    "1. Add limit (default ≤50) and cursor/offset parameters to all list tools.\n"
                    "2. Return a next_cursor field to allow agents to paginate.\n"
                    "3. Document the maximum items per page in the tool description."
                ),
                "mitre": ["T1499.004"],
            },
        }

        spec = _SPECS.get(category)
        if not spec:
            return None

        return Vulnerability(
            type=VulnerabilityType.CONTEXT_FLOODING,
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
                "https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/",
                "https://cwe.mitre.org/data/definitions/400.html",
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
