"""
XML External Entity (XXE) injection vulnerability detector.

Detects patterns that enable XXE attacks:
- External entity declarations (SYSTEM/PUBLIC)
- Vulnerable XML parsers (lxml, ElementTree, minidom, expat, libxmljs)
- Manual entity resolvers with file reads
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

APPLICABLE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".xml"}


class XXEDetector(BaseDetector):
    """Detector for XML External Entity (XXE) injection vulnerabilities."""

    def __init__(self) -> None:
        super().__init__(name="XXEDetector", enabled=True)
        self.patterns = {
            "xxe_entity_system": re.compile(
                r"<!ENTITY\s+\w+\s+SYSTEM\s", re.IGNORECASE
            ),
            "xxe_entity_public": re.compile(
                r"<!ENTITY\s+\w+\s+PUBLIC\s", re.IGNORECASE
            ),
            "lxml_parse_vulnerable": re.compile(
                r"lxml\.(etree|objectify)\.parse\s*\("
            ),
            "elementtree_parse": re.compile(
                r"(?:ET|ElementTree|xml\.etree\.\w+)\.parse\s*\("
            ),
            "minidom_parse": re.compile(
                r"minidom\.parse\s*\(|xml\.dom\.minidom\.parse\s*\("
            ),
            "expat_parser": re.compile(
                r"xml\.parsers\.expat\.ParserCreate\s*\("
            ),
            "libxml_no_noent": re.compile(r"libxmljs\.parseXml\s*\("),
        }
        self.resolve_entities_false = re.compile(r"resolve_entities\s*=\s*False")
        self.defusedxml_import = re.compile(r"import\s+defusedxml|from\s+defusedxml")
        self.noent_false = re.compile(r"noent.*false", re.IGNORECASE)

    def is_applicable(self, file_path: Path, file_type: Optional[str] = None) -> bool:
        if file_type:
            return file_type in ("python", "javascript", "typescript", "xml")
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
        has_defusedxml = bool(self.defusedxml_import.search(content))

        for i, line in enumerate(lines):
            line_num = i + 1

            # Direct entity patterns - always CRITICAL
            for pname in ("xxe_entity_system", "xxe_entity_public"):
                if self.patterns[pname].search(line):
                    findings.append(
                        Vulnerability(
                            type=VulnerabilityType.XXE,
                            title="XXE: External Entity Declaration",
                            description=(
                                "External entity declaration found - potential XXE attack vector. "
                                "An attacker can use SYSTEM or PUBLIC entity references to read "
                                "arbitrary files, perform SSRF, or cause denial of service."
                            ),
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet=line.strip(),
                            cwe_id="CWE-611",
                            cvss_score=9.1,
                            remediation=(
                                "1. Disable external entity processing in your XML parser\n"
                                "2. Use defusedxml library for Python XML parsing\n"
                                "3. Set resolve_entities=False in lxml\n"
                                "4. Validate and sanitize all XML input\n"
                                "5. Use a whitelist approach for allowed XML features"
                            ),
                            references=[
                                "https://cwe.mitre.org/data/definitions/611.html",
                                "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                                "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
                            ],
                            detector=self.name,
                            engine="static",
                        )
                    )

            # lxml parse - suppress if resolve_entities=False nearby
            if self.patterns["lxml_parse_vulnerable"].search(line):
                start = max(0, i - 5)
                end = min(len(lines), i + 6)
                nearby = "\n".join(lines[start:end])
                if not self.resolve_entities_false.search(nearby):
                    findings.append(
                        Vulnerability(
                            type=VulnerabilityType.XXE,
                            title="XXE: lxml.parse Without Entity Protection",
                            description=(
                                "lxml.parse without resolve_entities=False - vulnerable to XXE. "
                                "lxml by default resolves external entities which can be exploited "
                                "to read files or make network requests."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet=line.strip(),
                            cwe_id="CWE-611",
                            cvss_score=9.1,
                            remediation=(
                                "Use: parser = etree.XMLParser(resolve_entities=False)\n"
                                "Then: etree.parse(source, parser=parser)"
                            ),
                            references=[
                                "https://cwe.mitre.org/data/definitions/611.html",
                                "https://lxml.de/parsing.html#parsers",
                            ],
                            detector=self.name,
                            engine="static",
                        )
                    )

            # ElementTree - suppress if defusedxml imported
            if self.patterns["elementtree_parse"].search(line) and not has_defusedxml:
                findings.append(
                    Vulnerability(
                        type=VulnerabilityType.XXE,
                        title="XXE: ElementTree.parse May Be Vulnerable",
                        description=(
                            "ElementTree.parse may be vulnerable to XXE - use defusedxml. "
                            "Python's standard library xml.etree.ElementTree does not protect "
                            "against XXE attacks by default."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=line.strip(),
                        cwe_id="CWE-611",
                        cvss_score=9.1,
                        remediation=(
                            "Replace xml.etree.ElementTree with defusedxml.ElementTree:\n"
                            "  import defusedxml.ElementTree as ET\n"
                            "  tree = ET.parse(source)"
                        ),
                        references=[
                            "https://cwe.mitre.org/data/definitions/611.html",
                            "https://github.com/tiran/defusedxml",
                        ],
                        detector=self.name,
                        engine="static",
                    )
                )

            # minidom and expat parsers
            for pname in ("minidom_parse", "expat_parser"):
                if self.patterns[pname].search(line):
                    findings.append(
                        Vulnerability(
                            type=VulnerabilityType.XXE,
                            title=f"XXE: Potentially Vulnerable XML Parser ({pname})",
                            description=(
                                f"Detected {pname} - potentially vulnerable XML parser. "
                                "This parser may process external entities without protection."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet=line.strip(),
                            cwe_id="CWE-611",
                            cvss_score=9.1,
                            remediation=(
                                "Use defusedxml library as a safe replacement:\n"
                                "  import defusedxml.minidom\n"
                                "  doc = defusedxml.minidom.parseString(xml_string)"
                            ),
                            references=[
                                "https://cwe.mitre.org/data/definitions/611.html",
                                "https://github.com/tiran/defusedxml",
                            ],
                            detector=self.name,
                            engine="static",
                        )
                    )

            # libxmljs - suppress if noent=false nearby
            if self.patterns["libxml_no_noent"].search(line):
                start = max(0, i - 5)
                end = min(len(lines), i + 6)
                nearby = "\n".join(lines[start:end])
                if not self.noent_false.search(nearby):
                    findings.append(
                        Vulnerability(
                            type=VulnerabilityType.XXE,
                            title="XXE: libxmljs.parseXml Without noent:false",
                            description=(
                                "libxmljs.parseXml without noent:false - vulnerable to XXE. "
                                "By default libxmljs resolves external entities."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet=line.strip(),
                            cwe_id="CWE-611",
                            cvss_score=9.1,
                            remediation=(
                                "Pass { noent: false } option:\n"
                                "  libxmljs.parseXml(xml, { noent: false })"
                            ),
                            references=[
                                "https://cwe.mitre.org/data/definitions/611.html",
                            ],
                            detector=self.name,
                            engine="static",
                        )
                    )

        # Detect manual XXE entity resolver pattern (full-content scan)
        if re.search(r"ENTITY", content) and re.search(r"readFile|readFileSync", content):
            entity_lines = [i for i, line in enumerate(lines) if "ENTITY" in line]
            for ei in entity_lines:
                window = "\n".join(lines[ei : min(ei + 20, len(lines))])
                if re.search(r"readFile|readFileSync", window):
                    already_flagged = any(f.line_number == ei + 1 for f in findings)
                    if not already_flagged:
                        findings.append(
                            Vulnerability(
                                type=VulnerabilityType.XXE,
                                title="XXE: Manual Entity Resolver with File Read",
                                description=(
                                    "Manual entity resolver with file read - XXE vulnerability. "
                                    "Combining ENTITY parsing with file system reads creates a "
                                    "classic XXE attack path."
                                ),
                                severity=Severity.CRITICAL,
                                confidence=Confidence.HIGH,
                                file_path=str(file_path),
                                line_number=ei + 1,
                                code_snippet=lines[ei].strip(),
                                cwe_id="CWE-611",
                                cvss_score=9.1,
                                remediation=(
                                    "1. Do not manually resolve XML entities\n"
                                    "2. Use a safe XML parser like defusedxml\n"
                                    "3. Disable external entity processing entirely"
                                ),
                                references=[
                                    "https://cwe.mitre.org/data/definitions/611.html",
                                    "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                                ],
                                detector=self.name,
                                engine="static",
                            )
                        )

        return findings
