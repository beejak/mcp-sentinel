"""
Prototype pollution detector (JavaScript/TypeScript) for CWE-1321.

Flags high-signal patterns: ``__proto__`` object keys, direct ``__proto__`` assignment, and
``setPrototypeOf`` calls. Relevant to MCP servers built on Node and express/body-parser-style
merge paths.
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


def _strip_block_comments_one_line(line: str) -> str:
    """Remove ``/* ... */`` spans on a single line so matches are not triggered inside comments."""
    out = re.sub(r"/\*.*?\*/", "", line)
    return re.sub(r"/\*.*", "", out)


class PrototypePollutionDetector(BaseDetector):
    """
    Static patterns for JavaScript prototype pollution (CWE-1321).
    """

    def __init__(self) -> None:
        super().__init__(name="PrototypePollutionDetector", enabled=True)
        self.patterns: dict[str, list[Pattern]] = self._compile_patterns()

    def _compile_patterns(self) -> dict[str, list[Pattern]]:
        return {
            "proto_key_literal": [
                re.compile(r"""["']__proto__["']\s*:"""),
            ],
            "proto_direct_assign": [
                re.compile(r"\.__proto__\s*="),
            ],
            "set_prototype_of": [
                re.compile(r"Object\s*\.\s*setPrototypeOf\s*\("),
                re.compile(r"Reflect\s*\.\s*setPrototypeOf\s*\("),
            ],
            # Deep-merge sinks + heuristic untrusted-input hints (no full dataflow).
            "deep_merge_taint": [
                re.compile(
                    r"(?:^|[^\w.])(?:_\.(?:merge|mergeWith|defaultsDeep)|lodash\.(?:merge|mergeWith|defaultsDeep))\s*\("
                    r"[^;\n]{0,600}?(?:req\.(?:body|query|params)|request\.(?:body|query)|JSON\.parse\b|axios\b|fetch\s*\(|payload\b|\buntrusted\b)",
                    re.IGNORECASE,
                ),
            ],
        }

    def is_applicable(self, file_path: Path, file_type: str | None = None) -> bool:
        if file_type:
            return file_type in (
                "javascript",
                "typescript",
                "json",
                "config",
            )
        ext = file_path.suffix.lower()
        return ext in (
            ".js",
            ".jsx",
            ".mjs",
            ".cjs",
            ".ts",
            ".tsx",
            ".json",
        )

    async def detect(
        self, file_path: Path, content: str, file_type: str | None = None
    ) -> list[Vulnerability]:
        vulnerabilities: list[Vulnerability] = []
        lines = content.split("\n")
        seen: set[tuple[int, str, str]] = set()

        for line_num, line in enumerate(lines, start=1):
            if self._is_comment_line(line.strip(), file_path):
                continue

            scan_line = _strip_block_comments_one_line(line)

            for category, plist in self.patterns.items():
                for pattern in plist:
                    for match in pattern.finditer(scan_line):
                        mt = match.group(0)
                        key = (line_num, category, mt)
                        if key in seen:
                            continue
                        seen.add(key)
                        vulnerabilities.append(
                            self._create_vulnerability(
                                category=category,
                                matched_text=mt,
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=line.strip(),
                            )
                        )

        return vulnerabilities

    def _is_comment_line(self, stripped: str, file_path: Path) -> bool:
        if not stripped:
            return False
        suf = file_path.suffix.lower()
        if suf == ".py":
            return stripped.startswith("#")
        if suf in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            return stripped.startswith("//") or stripped.startswith("*")
        return False

    def _create_vulnerability(
        self,
        category: str,
        matched_text: str,
        file_path: Path,
        line_number: int,
        code_snippet: str,
    ) -> Vulnerability:
        meta_map = {
            "proto_key_literal": {
                "title": "Prototype Pollution: __proto__ object key",
                "description": (
                    f"Detected quoted '__proto__' as an object key ('{matched_text}'). "
                    "Merge utilities and recursive assignment often honor this key and may "
                    "modify Object.prototype, affecting all objects in the process — a classic "
                    "prototype pollution primitive (CWE-1321)."
                ),
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cvss_score": 8.2,
            },
            "proto_direct_assign": {
                "title": "Prototype Pollution: __proto__ assignment",
                "description": (
                    f"Detected direct assignment to __proto__ ('{matched_text}'). "
                    "This can alter an object's prototype chain and, when influenced by "
                    "user-controlled input, lead to prototype pollution."
                ),
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cvss_score": 8.0,
            },
            "set_prototype_of": {
                "title": "Prototype Pollution risk: setPrototypeOf",
                "description": (
                    f"Detected Object.setPrototypeOf or Reflect.setPrototypeOf ('{matched_text}'). "
                    "Legitimate uses exist, but combined with untrusted input this can change "
                    "prototype chains in unsafe ways; review call sites carefully."
                ),
                "severity": Severity.MEDIUM,
                "confidence": Confidence.MEDIUM,
                "cvss_score": 6.5,
            },
            "deep_merge_taint": {
                "title": "Prototype Pollution risk: deep merge with untrusted hint",
                "description": (
                    f"Detected lodash-style deep merge (match: {matched_text[:100]!r}{'...' if len(matched_text) > 100 else ''}) with a nearby "
                    "identifier that often denotes **untrusted** input (e.g. `req.body`, "
                    "`JSON.parse`, `payload`). Deep merges are common prototype-pollution sinks "
                    "when user-controlled objects include `__proto__` or `constructor` paths "
                    "(CWE-1321). Verify inputs are sanitized or use safe merge utilities."
                ),
                "severity": Severity.MEDIUM,
                "confidence": Confidence.MEDIUM,
                "cvss_score": 6.8,
            },
        }
        meta = meta_map[category]

        return Vulnerability(
            type=VulnerabilityType.PROTOTYPE_POLLUTION,
            title=meta["title"],
            description=meta["description"],
            severity=meta["severity"],
            confidence=meta["confidence"],
            file_path=str(file_path),
            line_number=line_number,
            code_snippet=code_snippet,
            cwe_id="CWE-1321",
            cvss_score=meta["cvss_score"],
            remediation=(
                "1. Avoid merging untrusted JSON/YAML into plain objects without schema validation\n"
                "2. Block or strip '__proto__', 'constructor', and 'prototype' keys from user input\n"
                "3. Prefer Object.create(null) for maps when merging dynamic keys\n"
                "4. Use structured cloning or schema-validated parsers instead of deep merge utilities "
                "on untrusted data\n"
                "5. Upgrade vulnerable lodash/merge libraries; use freeze/seal where appropriate"
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/1321.html",
                "https://owasp.org/www-community/vulnerabilities/Prototype_Pollution",
            ],
            detector=self.name,
            engine="static",
            mitre_attack_ids=["T1190"],
        )
