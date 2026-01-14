"""
Path Traversal vulnerability detector for MCP security.

Detects directory traversal and path manipulation vulnerabilities that could
allow attackers to access files outside intended directories.

Critical for MCP servers that handle file operations or serve files.
"""

import re
import ast
from typing import List, Dict, Pattern, Optional, Set, Tuple
from pathlib import Path

from mcp_sentinel.detectors.base import BaseDetector
from mcp_sentinel.models.vulnerability import (
    Vulnerability,
    VulnerabilityType,
    Severity,
    Confidence,
)
from mcp_sentinel.engines.semantic import get_semantic_engine, SemanticEngine
from mcp_sentinel.engines.semantic.models import TaintPath, SinkType
from mcp_sentinel.engines.semantic.cfg_builder import SimpleCFGBuilder


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

    def __init__(self, enable_semantic_analysis: bool = True):
        """
        Initialize the Path Traversal detector.

        Args:
            enable_semantic_analysis: Enable semantic analysis for multi-line detection (default: True)
        """
        super().__init__(name="PathTraversalDetector", enabled=True)
        self.patterns: Dict[str, List[Pattern]] = self._compile_patterns()
        self.enable_semantic_analysis = enable_semantic_analysis
        self.semantic_engine: Optional[SemanticEngine] = None
        self.cfg_builder = SimpleCFGBuilder()  # For guard detection

        # Initialize semantic engine if enabled
        if self.enable_semantic_analysis:
            try:
                self.semantic_engine = get_semantic_engine()
            except Exception as e:
                # Graceful degradation if semantic engine fails to load
                self.enable_semantic_analysis = False
                self.semantic_engine = None

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

        Uses two-phase detection:
        1. Pattern-based detection (fast, baseline)
        2. Semantic analysis (slower, more accurate, multi-line)

        Args:
            file_path: Path to the file
            content: File content
            file_type: File type (optional)

        Returns:
            List of detected path traversal vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []

        # Phase 1: Pattern-based detection (fast)
        pattern_vulns = self._pattern_based_detection(file_path, content, file_type)
        vulnerabilities.extend(pattern_vulns)

        # Phase 2: Semantic analysis (accurate, multi-line)
        if self._should_use_semantic_analysis(file_path, file_type):
            semantic_vulns = self._semantic_analysis_detection(file_path, content, file_type)
            vulnerabilities.extend(semantic_vulns)

        # Phase 3: Deduplication
        return self._deduplicate_vulnerabilities(vulnerabilities)

    def _pattern_based_detection(
        self, file_path: Path, content: str, file_type: Optional[str]
    ) -> List[Vulnerability]:
        """
        Pattern-based detection (Phase 1 - fast baseline).

        Args:
            file_path: Path to the file
            content: File content
            file_type: File type (optional)

        Returns:
            List of vulnerabilities found by pattern matching
        """
        vulnerabilities: List[Vulnerability] = []
        lines = content.split("\n")

        # Build CFG for guard detection (if Python code)
        cfg = None
        if file_type == "python" or (file_path.suffix.lower() == ".py"):
            try:
                code_ast = ast.parse(content)
                cfg = self.cfg_builder.build(code_ast)
            except SyntaxError:
                # If AST parsing fails, proceed without guard detection
                cfg = None

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
                            # Check for validation guards (if CFG available)
                            if cfg and self._has_guard_before_line(cfg, line_num):
                                # This vulnerability is protected by a validation guard
                                continue

                            vuln = self._create_vulnerability(
                                category=category,
                                matched_text=match.group(0),
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=line.strip(),
                            )
                            vulnerabilities.append(vuln)

        return vulnerabilities

    def _should_use_semantic_analysis(
        self, file_path: Path, file_type: Optional[str]
    ) -> bool:
        """
        Check if semantic analysis should be used.

        Args:
            file_path: Path to the file
            file_type: File type (optional)

        Returns:
            True if semantic analysis should be used
        """
        if not self.enable_semantic_analysis or not self.semantic_engine:
            return False

        # Enable for Python, JavaScript, TypeScript, and Java (Phase 4.2.2)
        # JS/Java use regex-based fallbacks until full AST parsing is implemented
        if file_type:
            return file_type in ["python", "javascript", "typescript", "java"]

        supported_extensions = [".py", ".js", ".ts", ".jsx", ".tsx", ".java"]
        return file_path.suffix.lower() in supported_extensions

    def _semantic_analysis_detection(
        self, file_path: Path, content: str, file_type: Optional[str]
    ) -> List[Vulnerability]:
        """
        Semantic analysis detection (Phase 2 - accurate, multi-line).

        Uses AST parsing and taint tracking to detect vulnerabilities
        that span multiple lines (e.g., request.args.get() on line N,
        open() on line N+M).

        Also performs CFG-based guard detection to reduce false positives
        by recognizing validation checks.

        Args:
            file_path: Path to the file
            content: File content
            file_type: File type (optional)

        Returns:
            List of vulnerabilities found by semantic analysis
        """
        if not self.semantic_engine:
            return []

        vulnerabilities: List[Vulnerability] = []

        try:
            # Run semantic analysis
            language = file_type or "python"
            semantic_result = self.semantic_engine.analyze(content, str(file_path), language)

            # Build CFG for guard detection
            cfg = None
            try:
                code_ast = ast.parse(content)
                cfg = self.cfg_builder.build(code_ast)
            except SyntaxError:
                # If AST parsing fails, proceed without guard detection
                cfg = None

            # Convert taint paths to vulnerabilities
            for taint_path in semantic_result.taint_paths:
                # Only process path traversal related sinks
                if taint_path.sink.sink_type in [
                    SinkType.FILE_OPERATION,
                    SinkType.PATH_OPERATION,
                ]:
                    # Check for validation guards between source and sink
                    if cfg and self._has_validation_guard(cfg, taint_path):
                        # Path is validated - skip this vulnerability
                        continue

                    vuln = self._convert_taint_path_to_vulnerability(
                        taint_path, file_path, content
                    )
                    vulnerabilities.append(vuln)

        except Exception as e:
            # Graceful degradation - log error but don't crash
            # In production, this would log to a proper logger
            pass

        return vulnerabilities

    def _has_validation_guard(self, cfg, taint_path: TaintPath) -> bool:
        """
        Check if a taint path has validation guards between source and sink.

        Args:
            cfg: Control flow graph
            taint_path: Taint path to check

        Returns:
            True if path is protected by validation guards, False otherwise
        """
        source_line = taint_path.source.line
        sink_line = taint_path.sink.line

        # Try to extract variable name from source
        # This is a simplified approach - Phase 4.3 will have better variable tracking
        var_name = None
        if hasattr(taint_path.source, 'name'):
            var_name = taint_path.source.name
        elif taint_path.path:
            # Try to get first variable in the flow
            var_name = taint_path.path[0] if taint_path.path else None

        # Check if path is safe using CFG builder
        if var_name:
            is_safe = self.cfg_builder.is_path_safe(cfg, source_line, sink_line, var_name)
            return is_safe

        # If we can't determine variable name, check for any validation guards
        # between source and sink lines
        guards = self.cfg_builder.find_guards_before_line(cfg, sink_line)
        for guard in guards:
            if guard.line > source_line and guard.line < sink_line:
                # Found a guard between source and sink
                if guard.is_exit and guard.guard_type == "validation":
                    # This is a validation guard with early exit (continue/raise/return)
                    return True

        return False

    def _has_guard_before_line(self, cfg, line_num: int) -> bool:
        """
        Check if there are validation guards before a given line.

        Simpler version for pattern-based detection - just checks if any
        validation guards exist before the line.

        Args:
            cfg: Control flow graph
            line_num: Line number to check

        Returns:
            True if validation guards exist before this line, False otherwise
        """
        guards = self.cfg_builder.find_guards_before_line(cfg, line_num)

        for guard in guards:
            if guard.line < line_num:
                # Found a validation guard before this line
                if guard.is_exit and guard.guard_type == "validation":
                    # This is a validation guard with early exit (continue/raise/return)
                    # which suggests the path is protected
                    return True

        return False

    def _convert_taint_path_to_vulnerability(
        self, taint_path: TaintPath, file_path: Path, content: str
    ) -> Vulnerability:
        """
        Convert a TaintPath from semantic analysis to a Vulnerability.

        Args:
            taint_path: Taint path from semantic engine
            file_path: Path to the file
            content: File content

        Returns:
            Vulnerability object
        """
        # Get code snippet around the sink line
        lines = content.split("\n")
        sink_line_num = taint_path.sink.line
        if 0 < sink_line_num <= len(lines):
            code_snippet = lines[sink_line_num - 1].strip()
        else:
            code_snippet = ""

        # Build description with taint flow information
        flow_description = " → ".join(taint_path.path) if taint_path.path else "direct"
        description = (
            f"Path traversal vulnerability detected via semantic analysis. "
            f"Tainted data from {taint_path.source.origin} (line {taint_path.source.line}) "
            f"flows to {taint_path.sink.function_name}() (line {sink_line_num}). "
            f"Flow: {flow_description}. "
            f"User-controlled input can manipulate file paths, allowing access to files "
            f"outside the intended directory."
        )

        # Adjust severity based on sink type and sanitization
        if taint_path.sink.sink_type == SinkType.FILE_OPERATION:
            # Direct file operations (open, read, write) are CRITICAL
            severity = Severity.CRITICAL if not taint_path.sanitized else Severity.HIGH
        elif taint_path.sink.sink_type == SinkType.PATH_OPERATION:
            # Path joining/manipulation is HIGH (less severe than direct file ops)
            severity = Severity.HIGH if not taint_path.sanitized else Severity.MEDIUM
        else:
            severity = Severity.HIGH

        confidence = Confidence.HIGH if taint_path.confidence >= 0.8 else Confidence.MEDIUM

        # Determine title based on sink function
        if "join" in taint_path.sink.function_name.lower():
            title = "Path Traversal: Unsafe Path Joining"
        elif taint_path.sink.function_name in ["open", "readFile", "writeFile"]:
            title = "Path Traversal: Multi-line Path Manipulation"
        else:
            title = "Path Traversal: Multi-line Path Manipulation"

        return Vulnerability(
            type=VulnerabilityType.PATH_TRAVERSAL,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            file_path=str(file_path),
            line_number=sink_line_num,
            code_snippet=code_snippet,
            cwe_id="CWE-22",
            cvss_score=9.1 if not taint_path.sanitized else 7.5,
            remediation=(
                "1. Validate and sanitize all user input before using in file paths\n"
                "2. Use allowlists of permitted files/directories\n"
                "3. Use path.resolve() or realpath() to normalize paths\n"
                "4. Verify resolved path stays within intended directory\n"
                "5. Use os.path.basename() to extract only filename\n"
                "6. Implement proper access controls"
            ),
            references=[
                "https://owasp.org/www-community/attacks/Path_Traversal",
                "https://cwe.mitre.org/data/definitions/22.html",
            ],
            detector=self.name,
            engine="semantic",  # Mark as semantic engine detection
            mitre_attack_ids=["T1083", "T1005"],
            context={
                "source": taint_path.source.origin,
                "source_line": taint_path.source.line,
                "sink": taint_path.sink.function_name,
                "sink_line": sink_line_num,
                "flow": flow_description,
                "sanitized": taint_path.sanitized,
                "sanitizers": taint_path.sanitizers,
            },
        )

    def _deduplicate_vulnerabilities(
        self, vulnerabilities: List[Vulnerability]
    ) -> List[Vulnerability]:
        """
        Deduplicate vulnerabilities from pattern-based and semantic analysis.

        Semantic analysis findings take precedence over pattern-based findings
        for the same line, as they have more context.

        Args:
            vulnerabilities: List of all vulnerabilities

        Returns:
            Deduplicated list
        """
        # Group by (file_path, line_number)
        vuln_map: Dict[Tuple[str, int], Vulnerability] = {}

        for vuln in vulnerabilities:
            key = (vuln.file_path, vuln.line_number)

            if key in vuln_map:
                existing = vuln_map[key]

                # Prefer semantic engine results (more accurate)
                if vuln.engine == "semantic" and existing.engine != "semantic":
                    vuln_map[key] = vuln
                # Keep higher severity
                elif vuln.severity.value > existing.severity.value:
                    vuln_map[key] = vuln
                # Keep higher confidence
                elif (
                    vuln.severity == existing.severity
                    and vuln.confidence.value > existing.confidence.value
                ):
                    vuln_map[key] = vuln
            else:
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
