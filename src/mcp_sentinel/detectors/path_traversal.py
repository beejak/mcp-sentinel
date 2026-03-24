"""
Path Traversal vulnerability detector for MCP security.

Detects directory traversal and path manipulation vulnerabilities that could
allow attackers to access files outside intended directories.

Critical for MCP servers that handle file operations or serve files.
"""

import ast
import re
from pathlib import Path
from re import Pattern
from typing import Optional

from mcp_sentinel.detectors.base import BaseDetector
from mcp_sentinel.models.vulnerability import (
    Confidence,
    Severity,
    Vulnerability,
    VulnerabilityType,
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

    def __init__(self) -> None:
        super().__init__(name="PathTraversalDetector", enabled=True)
        self.patterns: dict[str, list[Pattern[str]]] = self._compile_patterns()

    def _compile_patterns(self) -> dict[str, list[Pattern[str]]]:
        """Compile regex patterns for path traversal detection."""
        return {
            # Pattern 1: Direct path manipulation
            "path_manipulation": [
                re.compile(
                    r"open\s*\([^)]*(?:request|params|query|input|user)[^)]*\)", re.IGNORECASE
                ),
                re.compile(r"readFile\s*\([^)]*(?:req|params|query|input)[^)]*\)", re.IGNORECASE),
                re.compile(r"writeFile\s*\([^)]*(?:req|params|query|input)[^)]*\)", re.IGNORECASE),
                re.compile(r"Path\s*\([^)]*(?:request|params|query|user)[^)]*\)", re.IGNORECASE),
            ],
            # Pattern 2: Unsafe file operations
            "unsafe_file_ops": [
                re.compile(r"open\s*\([^)]*\+\s*[^)]*\)", re.IGNORECASE),  # Concatenation in open()
                re.compile(r"\.read\s*\(\s*[^)]*(?:input|user|request)[^)]*\)", re.IGNORECASE),
                re.compile(
                    r"file_get_contents\s*\([^)]*\$_(?:GET|POST|REQUEST)", re.IGNORECASE
                ),  # PHP
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
                re.compile(
                    r"\.extractall\s*\([^)]*\)", re.IGNORECASE
                ),  # Python zipfile.extractall()
                re.compile(r"ZipFile.*extract", re.IGNORECASE),
                re.compile(r"tarfile\.extract", re.IGNORECASE),
                re.compile(r"unzip\s+.*\$", re.IGNORECASE),  # Shell unzip with variable
            ],
            # Pattern 5: Path joining without sanitization
            "unsafe_path_join": [
                re.compile(
                    r"os\.path\.join\s*\([^)]*(?:request|params|query|input|user)[^)]*\)",
                    re.IGNORECASE,
                ),
                re.compile(r"path\.join\s*\([^)]*(?:req|params|query)[^)]*\)", re.IGNORECASE),
                re.compile(
                    r"File\s*\([^)]*,\s*[^)]*(?:request|params|input)", re.IGNORECASE
                ),  # Java
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
                "python",
                "javascript",
                "typescript",
                "java",
                "php",
                "ruby",
                "go",
                "rust",
                "csharp",
            ]

        # Check file extensions
        code_extensions = [
            ".py",
            ".js",
            ".ts",
            ".jsx",
            ".tsx",  # Python, JavaScript/TypeScript
            ".java",
            ".kt",  # Java, Kotlin
            ".php",
            ".php5",  # PHP
            ".rb",  # Ruby
            ".go",  # Go
            ".rs",  # Rust
            ".cs",  # C#
            ".cpp",
            ".c",
            ".h",  # C/C++
        ]
        return file_path.suffix.lower() in code_extensions

    # ── taint source patterns ──────────────────────────────────────────────────
    # Matches the RHS of an assignment that pulls data from user-controlled input.
    _PY_SOURCE = re.compile(
        r"\b(\w+)\s*=\s*(?:request|req)\s*(?:\.\s*(?:args|form|values|GET|POST|json|data)"
        r"(?:\s*\.\s*get\s*\([^)]*\)|\s*\[\s*['\"][^'\"]+['\"]\s*\])"
        r"|\s*\.\s*get_json\s*\(\s*\)(?:\s*\.\s*get\s*\([^)]*\))?)",
        re.IGNORECASE,
    )
    _JS_SOURCE = re.compile(
        r"\b(\w+)\s*=\s*(?:req|request)\s*\.\s*(?:query|body|params)\s*(?:\.\s*\w+|\[\s*['\"][^'\"]*['\"]\s*\])",
        re.IGNORECASE,
    )
    _JAVA_SOURCE = re.compile(
        r"\b(\w+)\s*=\s*(?:request|req)\s*\.\s*getParameter\s*\([^)]*\)",
        re.IGNORECASE,
    )

    # ── taint sink patterns (category, pattern) ────────────────────────────────
    _PY_OPEN_SINK = re.compile(r"\bopen\s*\(\s*(\w+)", re.IGNORECASE)
    _PY_JOIN_SINK = re.compile(r"\bos\s*\.\s*path\s*\.\s*join\s*\([^)]*\b(\w+)\b", re.IGNORECASE)
    _JS_SINKS = re.compile(
        r"(?:path\.join|fs\.readFile|fs\.readFileSync|fs\.writeFile|fs\.createReadStream)"
        r"\s*\([^)]*\b(\w+)\b",
        re.IGNORECASE,
    )
    _JAVA_FILE_SINK = re.compile(
        r"(?:new\s+File|Paths\.get|FileInputStream|FileReader)\s*\([^)]*\b(\w+)\b",
        re.IGNORECASE,
    )

    _TAINT_WINDOW = 30  # lines to look ahead from a source assignment

    def detect_sync(
        self, file_path: Path, content: str, file_type: Optional[str] = None
    ) -> list[Vulnerability]:
        """
        Detect path traversal vulnerabilities in file content.

        Uses two-phase detection:
        1. Pattern-based detection (fast, single-line baseline)
        2. Lightweight taint analysis (cross-line variable def-use chains)

        Args:
            file_path: Path to the file
            content: File content
            file_type: File type (optional)

        Returns:
            List of detected path traversal vulnerabilities
        """
        vulnerabilities: list[Vulnerability] = []
        vulnerabilities.extend(self._pattern_based_detection(file_path, content, file_type))
        vulnerabilities.extend(self._taint_analysis(file_path, content, file_type))
        return self._deduplicate_vulnerabilities(vulnerabilities)

    def _taint_analysis(
        self, file_path: Path, content: str, file_type: Optional[str]
    ) -> list[Vulnerability]:
        """
        Lightweight single-file taint analysis.

        Finds variables assigned from user-controlled sources (request.args,
        req.query, request.getParameter) and checks whether they reach file-
        operation sinks (open, os.path.join, path.join, fs.readFile, new File)
        within a look-ahead window of _TAINT_WINDOW lines.

        Works for Python (AST-assisted), JavaScript/TypeScript, and Java.
        """
        ext = file_path.suffix.lower()
        is_python = (file_type == "python") or ext == ".py"
        is_js = (file_type in ("javascript", "typescript")) or ext in (".js", ".ts", ".jsx", ".tsx")
        is_java = (file_type == "java") or ext in (".java", ".kt")

        if is_python:
            return self._taint_python(file_path, content)
        if is_js:
            return self._taint_js(file_path, content)
        if is_java:
            return self._taint_java(file_path, content)
        return []

    def _taint_python(self, file_path: Path, content: str) -> list[Vulnerability]:
        """
        Python-specific taint: use stdlib ast to find def-use chains inside
        each function body.  Catches:
          x = request.args.get('k')  →  open(x)            [path_manipulation]
          x = request.args.get('k')  →  os.path.join(b, x) [unsafe_path_join]
        """
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        lines = content.splitlines()
        vulnerabilities: list[Vulnerability] = []

        class _TaintVisitor(ast.NodeVisitor):
            """Collects (varname, lineno) for tainted source assignments."""

            def __init__(self) -> None:
                self.sources: list[tuple[str, int]] = []  # (varname, lineno)

            def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
                if self._is_request_source(node.value):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.sources.append((target.id, node.lineno))
                self.generic_visit(node)

            def _is_request_source(self, node: ast.expr) -> bool:
                """Return True if node looks like request.args.get(...) etc."""
                # request.args.get(...)  /  request.form.get(...)  etc.
                if isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Attribute) and func.attr == "get":
                        obj = func.value
                        if isinstance(obj, ast.Attribute) and isinstance(obj.value, ast.Name):
                            return obj.value.id in ("request", "req")
                    # request.get_json() style
                    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                        return func.value.id in ("request", "req")
                # request.json['key']  /  request.args['key']
                if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute):
                    if isinstance(node.value.value, ast.Name):
                        return node.value.value.id in ("request", "req")
                return False

        visitor = _TaintVisitor()
        visitor.visit(tree)

        for varname, src_line in visitor.sources:
            window_end = min(src_line + self._TAINT_WINDOW, len(lines))
            for lineno in range(src_line, window_end + 1):
                line = lines[lineno - 1] if lineno <= len(lines) else ""

                # open(varname, ...) sink
                m = self._PY_OPEN_SINK.search(line)
                if m and m.group(1) == varname:
                    snippet = line.strip()
                    vulnerabilities.append(
                        self._create_vulnerability("path_manipulation", f"open({varname})",
                                                   file_path, lineno, snippet)
                    )

                # os.path.join(..., varname, ...) sink
                m2 = self._PY_JOIN_SINK.search(line)
                if m2 and m2.group(1) == varname:
                    snippet = line.strip()
                    vulnerabilities.append(
                        self._create_vulnerability("unsafe_path_join",
                                                   f"os.path.join(..., {varname})",
                                                   file_path, lineno, snippet)
                    )

        return vulnerabilities

    # Matches `const/let/var X = <sink>` to detect one-step taint propagation.
    _JS_ASSIGN_LHS = re.compile(r"(?:const|let|var)\s+(\w+)\s*=", re.IGNORECASE)

    def _taint_js(self, file_path: Path, content: str) -> list[Vulnerability]:
        """
        JavaScript/TypeScript taint: regex-based window.
        Finds  const x = req.query.y  then looks for path.join/fs.readFile
        using x within _TAINT_WINDOW lines.  Also propagates taint one step:
        if  const y = path.join(..., x)  is found, y is also flagged as tainted
        and its use in further file-I/O sinks is reported.
        """
        lines = content.splitlines()
        vulnerabilities: list[Vulnerability] = []

        for src_lineno, line in enumerate(lines, start=1):
            m = self._JS_SOURCE.match(line.strip()) or self._JS_SOURCE.search(line)
            if not m:
                continue
            varname = m.group(1)

            window_end = min(src_lineno + self._TAINT_WINDOW, len(lines))
            for sink_lineno in range(src_lineno + 1, window_end + 1):
                sink_line = lines[sink_lineno - 1] if sink_lineno <= len(lines) else ""
                sm = self._JS_SINKS.search(sink_line)
                if not sm or sm.group(1) != varname:
                    continue
                cat = "unsafe_path_join" if "join" in sink_line.lower() else "path_manipulation"
                vulnerabilities.append(
                    self._create_vulnerability(
                        cat, sm.group(0), file_path, sink_lineno, sink_line.strip()
                    )
                )
                # One-step taint propagation: if this sink is assigned to a new
                # variable (e.g. `const filePath = path.join(..., x)`), track
                # that variable and report its use in further file-I/O sinks.
                lhs_m = self._JS_ASSIGN_LHS.search(sink_line)
                if lhs_m:
                    derived = lhs_m.group(1)
                    prop_end = min(sink_lineno + self._TAINT_WINDOW, len(lines))
                    for prop_lineno in range(sink_lineno + 1, prop_end + 1):
                        prop_line = lines[prop_lineno - 1] if prop_lineno <= len(lines) else ""
                        pm = self._JS_SINKS.search(prop_line)
                        if pm and pm.group(1) == derived:
                            pcat = (
                                "unsafe_path_join"
                                if "join" in prop_line.lower()
                                else "path_manipulation"
                            )
                            vulnerabilities.append(
                                self._create_vulnerability(
                                    pcat, pm.group(0), file_path, prop_lineno, prop_line.strip()
                                )
                            )

        return vulnerabilities

    def _taint_java(self, file_path: Path, content: str) -> list[Vulnerability]:
        """
        Java taint: regex-based window.
        Finds  String x = request.getParameter(...)  then checks for
        new File / Paths.get / FileInputStream using x within window.
        """
        lines = content.splitlines()
        vulnerabilities: list[Vulnerability] = []

        for src_lineno, line in enumerate(lines, start=1):
            m = self._JAVA_SOURCE.search(line)
            if not m:
                continue
            varname = m.group(1)

            window_end = min(src_lineno + self._TAINT_WINDOW, len(lines))
            for sink_lineno in range(src_lineno + 1, window_end + 1):
                sink_line = lines[sink_lineno - 1] if sink_lineno <= len(lines) else ""
                sm = self._JAVA_FILE_SINK.search(sink_line)
                if sm and sm.group(1) == varname:
                    cat = "unsafe_path_join" if "Paths" in sink_line else "path_manipulation"
                    vulnerabilities.append(
                        self._create_vulnerability(cat, sm.group(0),
                                                   file_path, sink_lineno, sink_line.strip())
                    )

        return vulnerabilities

    def _pattern_based_detection(
        self, file_path: Path, content: str, file_type: Optional[str]
    ) -> list[Vulnerability]:
        """
        Pattern-based detection (Phase 1 - fast baseline).

        Args:
            file_path: Path to the file
            content: File content
            file_type: File type (optional)

        Returns:
            List of vulnerabilities found by pattern matching
        """
        vulnerabilities: list[Vulnerability] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            if self._is_comment(line, file_type):
                continue

            for category, patterns in self.patterns.items():
                for pattern in patterns:
                    matches = pattern.finditer(line)
                    for match in matches:
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

    def _deduplicate_vulnerabilities(
        self, vulnerabilities: list[Vulnerability]
    ) -> list[Vulnerability]:
        """Deduplicate vulnerabilities by (file_path, line_number)."""
        vuln_map: dict[tuple[str, int], Vulnerability] = {}
        for vuln in vulnerabilities:
            key = (vuln.file_path, vuln.line_number)
            if key not in vuln_map:
                vuln_map[key] = vuln
        return list(vuln_map.values())

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
            r"\.resolve\s*\(",  # path.resolve()
            r"realpath\s*\(",  # realpath()
            r"abspath\s*\(",  # os.path.abspath()
            r"normpath\s*\(",  # os.path.normpath()
            r"canonical",  # getCanonicalPath()
            r"sanitize",  # sanitize_path()
            r"validate",  # validate_path()
            r"is_safe_path",  # is_safe_path()
            r"\.normalize\s*\(",  # path.normalize()
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
            if "member" in line_lower and any(
                check in line_lower for check in ["startswith", "in", "if"]
            ):
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
                    "Hardcoded or dynamically constructed paths containing '../' or '..' sequences "
                    "can allow attackers to navigate outside intended directories. This includes "
                    "URL-encoded variants like %2e%2e%2f used to bypass simple filters."
                ),
                "remediation": (
                    "1. Block or sanitize '../', '..', and encoded variants\n"
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
