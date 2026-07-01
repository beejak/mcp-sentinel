"""
Prototype Pollution vulnerability detector.

Detects patterns that enable prototype pollution attacks in JavaScript/TypeScript:
- Object.assign with JSON.parse input
- Direct __proto__ key assignment
- Constructor key manipulation
- Unsafe merge functions without prototype guard
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

APPLICABLE_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx"}


class PrototypePollutionDetector(BaseDetector):
    """Detector for prototype pollution vulnerabilities in JavaScript/TypeScript."""

    def __init__(self) -> None:
        super().__init__(name="PrototypePollutionDetector", enabled=True)
        self.patterns = {
            "object_assign_json_parse": re.compile(
                r"Object\.assign\s*\([^,]+,\s*JSON\.parse\s*\("
            ),
            "proto_key_set": re.compile(r"""\[['"]__proto__['"]\]\s*="""),
            "constructor_key_set": re.compile(r"""\[['"]constructor['"]\]\s*\["""),
        }
        self.merge_func_pattern = re.compile(
            r"(?:function\s+|const\s+|let\s+|var\s+)\w*[Mm]erge\w*\s*[=(]"
        )
        self.target_assign = re.compile(r"target\s*\[\s*key\s*\]\s*=")
        self.proto_guard = re.compile(
            r"__proto__|constructor.*continue|prototype.*guard", re.IGNORECASE
        )

    def is_applicable(self, file_path: Path, file_type: Optional[str] = None) -> bool:
        if file_type:
            return file_type in ("javascript", "typescript")
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

        # Line-by-line scan for direct patterns
        for i, line in enumerate(lines, 1):
            for pattern_name, pattern in self.patterns.items():
                if pattern.search(line):
                    if pattern_name == "object_assign_json_parse":
                        title = "Prototype Pollution via Object.assign + JSON.parse"
                        description = (
                            "Object.assign with JSON.parse input enables prototype pollution. "
                            "An attacker can craft JSON with a '__proto__' key to pollute "
                            "the Object prototype and affect all objects in the application."
                        )
                    elif pattern_name == "proto_key_set":
                        title = "Direct __proto__ Assignment"
                        description = (
                            "Direct assignment to __proto__ key detected. This directly "
                            "modifies the prototype chain and is a classic prototype pollution vector."
                        )
                    else:
                        title = "Constructor Key Manipulation"
                        description = (
                            "Constructor key assignment detected - potential prototype pollution "
                            "via constructor.prototype manipulation."
                        )

                    findings.append(
                        Vulnerability(
                            type=VulnerabilityType.PROTOTYPE_POLLUTION,
                            title=title,
                            description=description,
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            file_path=str(file_path),
                            line_number=i,
                            code_snippet=line.strip(),
                            cwe_id="CWE-1321",
                            cvss_score=9.0,
                            remediation=(
                                "1. Validate keys before property assignment\n"
                                "2. Use Object.freeze(Object.prototype) in tests\n"
                                "3. Reject '__proto__', 'constructor', 'prototype' keys\n"
                                "4. Use Object.create(null) for safe dictionaries\n"
                                "5. Use libraries like lodash with prototype pollution fixes"
                            ),
                            references=[
                                "https://cwe.mitre.org/data/definitions/1321.html",
                                "https://portswigger.net/web-security/prototype-pollution",
                            ],
                            detector=self.name,
                            engine="static",
                        )
                    )

        # Find merge-like functions and check for target[key] = without guard
        for i, line in enumerate(lines):
            if self.merge_func_pattern.search(line):
                func_start = i
                brace_depth = 0
                func_body_start = False
                func_end = min(i + 50, len(lines))
                for j in range(i, min(i + 100, len(lines))):
                    if "{" in lines[j]:
                        brace_depth += lines[j].count("{")
                        func_body_start = True
                    if "}" in lines[j]:
                        brace_depth -= lines[j].count("}")
                    if func_body_start and brace_depth <= 0:
                        func_end = j
                        break

                for k in range(func_start, func_end + 1):
                    if k >= len(lines):
                        break
                    if self.target_assign.search(lines[k]):
                        start_check = max(0, k - 15)
                        has_guard = any(
                            self.proto_guard.search(lines[m])
                            for m in range(start_check, k)
                        )
                        if not has_guard:
                            findings.append(
                                Vulnerability(
                                    type=VulnerabilityType.PROTOTYPE_POLLUTION,
                                    title="Prototype Pollution: Unchecked Merge Function",
                                    description=(
                                        "Unchecked target[key] = in merge function - potential "
                                        "prototype pollution. Without a guard against '__proto__' "
                                        "and 'constructor' keys, an attacker can pollute the prototype."
                                    ),
                                    severity=Severity.HIGH,
                                    confidence=Confidence.MEDIUM,
                                    file_path=str(file_path),
                                    line_number=k + 1,
                                    code_snippet=lines[k].strip(),
                                    cwe_id="CWE-1321",
                                    cvss_score=9.0,
                                    remediation=(
                                        "1. Add key validation: if (key === '__proto__') continue;\n"
                                        "2. Use Object.hasOwn() to check own properties\n"
                                        "3. Use lodash merge which has prototype pollution protection\n"
                                        "4. Validate all keys against an allowlist"
                                    ),
                                    references=[
                                        "https://cwe.mitre.org/data/definitions/1321.html",
                                        "https://portswigger.net/web-security/prototype-pollution",
                                    ],
                                    detector=self.name,
                                    engine="static",
                                )
                            )

        return findings
