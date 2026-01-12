"""
Path Traversal vulnerability detector for MCP security.

Detects directory traversal and path manipulation vulnerabilities that could
allow attackers to access files outside intended directories.

Critical for MCP servers that handle file operations or serve files.
"""

import re
from typing import List, Dict, Pattern, Optional
from pathlib import Path

from mcp_sentinel.detectors.base import BaseDetector
from mcp_sentinel.models.vulnerability import (
    Vulnerability,
    VulnerabilityType,
    Severity,
    Confidence,
)


class PathTraversalDetector(BaseDetector):
    """
    Detector for path traversal vulnerabilities.

    Detects 5 critical path traversal patterns:
    1. Direct path manipulation with user input
    2. Unsafe file operations (open, read, write)
    3. Directory traversal sequences (../)
    4. Archive extraction vulnerabilities (Zip Slip)
    5. Missing path sanitization
    """

    def __init__(self):
        """Initialize the Path Traversal detector."""
        super().__init__(name="PathTraversalDetector", enabled=True)
        self.patterns: Dict[str, List[Pattern]] = self._compile_patterns()

    def _compile_patterns(self) -> Dict[str, List[Pattern]]:
        """Compile regex patterns for path traversal detection."""
        return {
            # Pattern 1: Direct path manipulation
            "path_manipulation": [
                re.compile(r"open\s*\([^)]*(?:request|params|query|input|user)[^)]*\)", re.IGNORECASE),
                re.compile(r"readFile\s*\([^)]*(?:req|params|query|input)[^)]*\)", re.IGNORECASE),
                re.compile(r"writeFile\s*\([^)]*(?:req|params|query|input)[^)]*\)", re.IGNORECASE),
                re.compile(r"Path\s*\([^)]*(?:request|params|query|user)[^)]*\)", re.IGNORECASE),
            ],

            # Pattern 2: Unsafe file operations
            "unsafe_file_ops": [
                re.compile(r"open\s*\([^)]*\+\s*[^)]*\)", re.IGNORECASE),  # Concatenation in open()
                re.compile(r"\.read\s*\(\s*[^)]*(?:input|user|request)[^)]*\)", re.IGNORECASE),
                re.compile(r"file_get_contents\s*\([^)]*\$_(?:GET|POST|REQUEST)", re.IGNORECASE),  # PHP
                re.compile(r"fopen\s*\([^)]*\$_(?:GET|POST|REQUEST)", re.IGNORECASE),  # PHP
            ],

            # Pattern 3: Directory traversal sequences
            "traversal_sequences": [
                re.compile(r"['\"]\.\.\/", re.IGNORECASE),  # Literal "../" in strings
                re.compile(r"['\"]\.\.\\", re.IGNORECASE),  # Literal "..\" in strings
                re.compile(r"\.\.\/.*\.\.\/", re.IGNORECASE),  # Multiple "../" sequences
                re.compile(r"\%2e\%2e\%2f", re.IGNORECASE),  # URL-encoded "../"
                re.compile(r"\%2e\%2e\/", re.IGNORECASE),  # Partially encoded
            ],

            # Pattern 4: Archive extraction (Zip Slip)
            "zip_slip": [
                re.compile(r"\.extract\s*\([^)]*\)", re.IGNORECASE),  # Python zipfile.extract()
                re.compile(r"\.extractall\s*\([^)]*\)", re.IGNORECASE),  # Python zipfile.extractall()
                re.compile(r"ZipFile.*extract", re.IGNORECASE),
                re.compile(r"tarfile\.extract", re.IGNORECASE),
                re.compile(r"unzip\s+.*\$", re.IGNORECASE),  # Shell unzip with variable
            ],

            # Pattern 5: Path joining without sanitization
            "unsafe_path_join": [
                re.compile(r"os\.path\.join\s*\([^)]*(?:request|params|query|input|user)[^)]*\)", re.IGNORECASE),
                re.compile(r"path\.join\s*\([^)]*(?:req|params|query)[^)]*\)", re.IGNORECASE),
                re.compile(r"File\s*\([^)]*,\s*[^)]*(?:request|params|input)", re.IGNORECASE),  # Java
                re.compile(r"Paths\.get\s*\([^)]*(?:request|params|query)", re.IGNORECASE),  # Java
            ],
        }

    def is_applicable(self, file_path: Path, file_type: Optional[str] = None) -> bool:
        """
        Check if this detector should run on the given file.

        Args:
            file_path: Path to the file
            file_type: File type (optional)

        Returns:
            True for code files that may handle file operations
        """
        if file_type:
            return file_type in [
                "python", "javascript", "typescript", "java", "php",
                "ruby", "go", "rust", "csharp"
            ]

        # Check file extensions
        code_extensions = [
            ".py", ".js", ".ts", ".jsx", ".tsx",  # Python, JavaScript/TypeScript
            ".java", ".kt",  # Java, Kotlin
            ".php", ".php5",  # PHP
            ".rb",  # Ruby
            ".go",  # Go
            ".rs",  # Rust
            ".cs",  # C#
            ".cpp", ".c", ".h",  # C/C++
        ]
        return file_path.suffix.lower() in code_extensions

    async def detect(
        self, file_path: Path, content: str, file_type: Optional[str] = None
    ) -> List[Vulnerability]:
        """
        Detect path traversal vulnerabilities in file content.

        Args:
            file_path: Path to the file
            content: File content
            file_type: File type (optional)

        Returns:
            List of detected path traversal vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            # Skip comments
            if self._is_comment(line, file_type):
                continue

            # Check all pattern categories
            for category, patterns in self.patterns.items():
                for pattern in patterns:
                    matches = pattern.finditer(line)

                    for match in matches:
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

        return vulnerabilities

    def _is_comment(self, line: str, file_type: Optional[str]) -> bool:
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

        # Python/Ruby comments
        if stripped.startswith("#"):
            return True

        # JavaScript/Java/C/C++ comments
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
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
        # Check for path sanitization functions
        sanitization_patterns = [
            r"\.resolve\s*\(",           # path.resolve()
            r"realpath\s*\(",            # realpath()
            r"abspath\s*\(",             # os.path.abspath()
            r"normpath\s*\(",            # os.path.normpath()
            r"canonical",                # getCanonicalPath()
            r"sanitize",                 # sanitize_path()
            r"validate",                 # validate_path()
            r"is_safe_path",             # is_safe_path()
            r"\.normalize\s*\(",         # path.normalize()
        ]

        for pattern in sanitization_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True

        # Check for test/example indicators
        test_indicators = ["test", "example", "mock", "fixture", "sample"]
        line_lower = line.lower()
        for indicator in test_indicators:
            if indicator in line_lower:
                return True

        # For traversal sequences, allow in test strings or documentation
        if category == "traversal_sequences":
            if any(marker in line_lower for marker in ["test", "example", "comment", "doc"]):
                return True

        # For zip extraction, allow if checking member names
        if category == "zip_slip":
            if "member" in line_lower and any(check in line_lower for check in ["startswith", "in", "if"]):
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
        """
        Create a vulnerability object from detected pattern.

        Args:
            category: The vulnerability category
            matched_text: The matched text
            file_path: Path to the file
            line_number: Line number where vulnerability was found
            code_snippet: The code snippet containing the vulnerability

        Returns:
            Vulnerability object
        """
        vuln_metadata = {
            "path_manipulation": {
                "title": "Path Traversal: Direct Path Manipulation",
                "cwe_id": "CWE-22",
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "cvss_score": 9.1,
                "description": (
                    f"Detected unsafe path manipulation: '{matched_text}'. "
                    "Using user-controlled input directly in file paths allows attackers to access "
                    "files outside the intended directory using '../' sequences. This can lead to "
                    "unauthorized file access, information disclosure, or even code execution if "
                    "combined with file upload functionality. Critical for MCP servers handling "
                    "file operations."
                ),
                "remediation": (
                    "1. Never use user input directly in file paths\n"
                    "2. Use allowlists of permitted files/directories\n"
                    "3. Validate and sanitize all path inputs\n"
                    "4. Use path.resolve() or realpath() to normalize paths\n"
                    "5. Check that resolved path stays within allowed directory\n"
                    "6. Use os.path.basename() to extract only filename\n"
                    "7. Implement proper access controls on file operations\n"
                    "8. Consider using UUIDs for file references instead of paths"
                ),
                "mitre_attack_ids": ["T1083", "T1005"],
            },
            "unsafe_file_ops": {
                "title": "Path Traversal: Unsafe File Operation",
                "cwe_id": "CWE-22",
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cvss_score": 7.5,
                "description": (
                    f"Detected unsafe file operation: '{matched_text}'. "
                    "File operations using concatenated or user-controlled paths are vulnerable "
                    "to directory traversal attacks. Attackers can manipulate paths to read, "
                    "write, or delete arbitrary files on the system."
                ),
                "remediation": (
                    "1. Avoid string concatenation for file paths\n"
                    "2. Use safe path joining with validation\n"
                    "3. Implement allowlist of permitted file operations\n"
                    "4. Validate file extensions and types\n"
                    "5. Use absolute paths with validation\n"
                    "6. Implement file access logging\n"
                    "7. Apply principle of least privilege"
                ),
                "mitre_attack_ids": ["T1083", "T1005", "T1565"],
            },
            "traversal_sequences": {
                "title": "Path Traversal: Directory Traversal Sequence",
                "cwe_id": "CWE-23",
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cvss_score": 8.6,
                "description": (
                    f"Detected directory traversal sequence: '{matched_text}'. "
                    "Hardcoded or dynamically constructed paths containing '../' or '..\' sequences "
                    "can allow attackers to navigate outside intended directories. This includes "
                    "URL-encoded variants like %2e%2e%2f used to bypass simple filters."
                ),
                "remediation": (
                    "1. Block or sanitize '../', '..\', and encoded variants\n"
                    "2. Use canonical path resolution\n"
                    "3. Validate resolved paths stay within allowed directory\n"
                    "4. Implement strict input validation\n"
                    "5. Use security libraries for path handling\n"
                    "6. Log suspicious path access attempts\n"
                    "7. Consider using chroot or containers for isolation"
                ),
                "mitre_attack_ids": ["T1083", "T1005"],
            },
            "zip_slip": {
                "title": "Path Traversal: Zip Slip Vulnerability",
                "cwe_id": "CWE-22",
                "severity": Severity.CRITICAL,
                "confidence": Confidence.MEDIUM,
                "cvss_score": 9.8,
                "description": (
                    f"Detected potentially unsafe archive extraction: '{matched_text}'. "
                    "Extracting archives without validating member paths can allow attackers to "
                    "write files outside the target directory (Zip Slip). Malicious archives can "
                    "contain entries like '../../../../tmp/evil.sh' leading to arbitrary file writes "
                    "and potential remote code execution."
                ),
                "remediation": (
                    "1. Validate all archive member paths before extraction\n"
                    "2. Check that resolved paths stay within target directory\n"
                    "3. Use path.is_relative_to() or similar checks\n"
                    "4. Remove leading '/' and '../' from member names\n"
                    "5. Use security-hardened archive libraries\n"
                    "6. Extract to temporary isolated directory first\n"
                    "7. Scan archive contents before extraction\n"
                    "8. Apply strict file permissions after extraction"
                ),
                "mitre_attack_ids": ["T1005", "T1083", "T1204"],
            },
            "unsafe_path_join": {
                "title": "Path Traversal: Unsafe Path Joining",
                "cwe_id": "CWE-23",
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cvss_score": 7.8,
                "description": (
                    f"Detected unsafe path joining: '{matched_text}'. "
                    "Using os.path.join() or similar functions with user-controlled input can be "
                    "exploited if the user input contains absolute paths or '../' sequences. "
                    "Many path joining functions have counterintuitive behavior with absolute paths."
                ),
                "remediation": (
                    "1. Validate user input before path joining\n"
                    "2. Check for absolute paths and reject them\n"
                    "3. Sanitize '../' and '..' from user input\n"
                    "4. Use path.resolve() after joining to normalize\n"
                    "5. Verify result stays within intended directory\n"
                    "6. Consider using only basenames from user input\n"
                    "7. Implement allowlist of permitted paths"
                ),
                "mitre_attack_ids": ["T1083", "T1005"],
            },
        }

        metadata = vuln_metadata.get(category, {})

        return Vulnerability(
            type=VulnerabilityType.PATH_TRAVERSAL,
            title=metadata.get("title", "Path Traversal Vulnerability"),
            description=metadata.get("description", f"Detected: {matched_text}"),
            severity=metadata.get("severity", Severity.MEDIUM),
            confidence=metadata.get("confidence", Confidence.MEDIUM),
            file_path=str(file_path),
            line_number=line_number,
            code_snippet=code_snippet,
            cwe_id=metadata.get("cwe_id", "CWE-22"),
            cvss_score=metadata.get("cvss_score", 7.5),
            remediation=metadata.get("remediation", "Validate and sanitize file paths"),
            references=[
                "https://owasp.org/www-community/attacks/Path_Traversal",
                "https://cwe.mitre.org/data/definitions/22.html",
                "https://portswigger.net/web-security/file-path-traversal",
                "https://snyk.io/research/zip-slip-vulnerability",
            ],
            detector=self.name,
            engine="static",
            mitre_attack_ids=metadata.get("mitre_attack_ids", []),
        )
