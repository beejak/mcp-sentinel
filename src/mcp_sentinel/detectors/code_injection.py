"""
Code injection detector for finding command injection and code execution vulnerabilities.

Detects:
- Python: os.system(), subprocess with shell=True, eval(), exec()
- JavaScript/TypeScript: child_process.exec(), eval(), Function() constructor
"""

import re
from typing import List, Dict, Pattern, Optional, Tuple
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


class CodeInjectionDetector(BaseDetector):
    """
    Detector for code injection and command injection vulnerabilities.

    Detects 9 dangerous patterns across Python and JavaScript/TypeScript:
    - Python command injection (os.system, subprocess with shell=True)
    - Python code execution (eval, exec)
    - JavaScript command injection (child_process.exec)
    - JavaScript code execution (eval, Function constructor)
    """

    def __init__(self, enable_semantic_analysis: bool = True):
        """
        Initialize the code injection detector.

        Args:
            enable_semantic_analysis: Enable semantic analysis for multi-line detection (default: True)
        """
        super().__init__(name="CodeInjectionDetector", enabled=True)
        self.python_patterns: Dict[str, Pattern] = self._compile_python_patterns()
        self.javascript_patterns: Dict[str, Pattern] = self._compile_javascript_patterns()
        self.enable_semantic_analysis = enable_semantic_analysis
        self.semantic_engine: Optional[SemanticEngine] = None

        # Initialize semantic engine if enabled
        if self.enable_semantic_analysis:
            try:
                self.semantic_engine = get_semantic_engine()
            except Exception as e:
                # Graceful degradation if semantic engine fails to load
                self.enable_semantic_analysis = False
                self.semantic_engine = None

    def _compile_python_patterns(self) -> Dict[str, Pattern]:
        """Compile regex patterns for Python code injection detection."""
        return {
            # os.system() - Direct command execution
            "os_system": re.compile(r"os\.system\s*\("),

            # subprocess.call() with shell=True
            "subprocess_call_shell": re.compile(
                r"subprocess\.call\s*\([^)]*shell\s*=\s*True"
            ),

            # subprocess.run() with shell=True
            "subprocess_run_shell": re.compile(
                r"subprocess\.run\s*\([^)]*shell\s*=\s*True"
            ),

            # subprocess.Popen() with shell=True
            "subprocess_popen_shell": re.compile(
                r"subprocess\.Popen\s*\([^)]*shell\s*=\s*True"
            ),

            # eval() - Code execution
            "eval_usage": re.compile(r"\beval\s*\("),

            # exec() - Code execution
            "exec_usage": re.compile(r"\bexec\s*\("),
        }

    def _compile_javascript_patterns(self) -> Dict[str, Pattern]:
        """Compile regex patterns for JavaScript/TypeScript code injection detection."""
        return {
            # child_process.exec() - Command execution
            "child_process_exec": re.compile(
                r"(child_process|require\s*\(\s*['\"]child_process['\"]\s*\))\.exec\s*\("
            ),

            # Standalone exec() - From destructured import: const { exec } = require('child_process')
            "exec_standalone": re.compile(r"\bexec\s*\("),

            # eval() - Code execution
            "eval_usage": re.compile(r"\beval\s*\("),

            # Function() constructor - Dynamic code execution
            "function_constructor": re.compile(r"\bnew\s+Function\s*\("),
        }

    def is_applicable(self, file_path: Path, file_type: Optional[str] = None) -> bool:
        """
        Check if this detector should run on the given file.

        Args:
            file_path: Path to the file
            file_type: File type (e.g., "python", "javascript")

        Returns:
            True if file is Python, JavaScript, or TypeScript
        """
        if file_type:
            return file_type in ["python", "javascript", "typescript"]

        # Check file extension
        return file_path.suffix.lower() in [".py", ".js", ".jsx", ".ts", ".tsx"]

    async def detect(
        self, file_path: Path, content: str, file_type: Optional[str] = None
    ) -> List[Vulnerability]:
        """
        Detect code injection vulnerabilities in file content.

        Uses two-phase detection:
        1. Pattern-based detection (fast, baseline)
        2. Semantic analysis (slower, more accurate, multi-line)

        Args:
            file_path: Path to the file
            content: File content
            file_type: File type (optional)

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []

        # Determine which patterns to use based on file type
        if not file_type:
            file_type = self._guess_file_type(file_path)

        # Phase 1: Pattern-based detection (fast)
        if file_type == "python":
            vulnerabilities.extend(
                self._detect_python_injection(file_path, content)
            )
        elif file_type in ["javascript", "typescript"]:
            vulnerabilities.extend(
                self._detect_javascript_injection(file_path, content)
            )

        # Phase 2: Semantic analysis (accurate, multi-line)
        if self._should_use_semantic_analysis(file_path, file_type):
            semantic_vulns = self._semantic_analysis_detection(file_path, content, file_type)
            vulnerabilities.extend(semantic_vulns)

        # Phase 3: Deduplication
        return self._deduplicate_vulnerabilities(vulnerabilities)

    def _detect_python_injection(
        self, file_path: Path, content: str
    ) -> List[Vulnerability]:
        """
        Detect Python code injection vulnerabilities.

        Args:
            file_path: Path to the file
            content: File content

        Returns:
            List of vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []
        lines = content.split("\n")

        for pattern_name, pattern in self.python_patterns.items():
            for line_num, line in enumerate(lines, start=1):
                # Skip comments
                if line.strip().startswith("#"):
                    continue

                matches = pattern.finditer(line)

                for match in matches:
                    vuln = self._create_python_vulnerability(
                        pattern_name=pattern_name,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line.strip(),
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _detect_javascript_injection(
        self, file_path: Path, content: str
    ) -> List[Vulnerability]:
        """
        Detect JavaScript/TypeScript code injection vulnerabilities.

        Args:
            file_path: Path to the file
            content: File content

        Returns:
            List of vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []
        lines = content.split("\n")

        for pattern_name, pattern in self.javascript_patterns.items():
            for line_num, line in enumerate(lines, start=1):
                # Skip comments
                stripped = line.strip()
                if stripped.startswith("//") or stripped.startswith("/*"):
                    continue

                matches = pattern.finditer(line)

                for match in matches:
                    vuln = self._create_javascript_vulnerability(
                        pattern_name=pattern_name,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line.strip(),
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _create_python_vulnerability(
        self,
        pattern_name: str,
        file_path: Path,
        line_number: int,
        code_snippet: str,
    ) -> Vulnerability:
        """Create a vulnerability object for Python code injection."""
        # Pattern-specific metadata
        metadata_map = {
            "os_system": {
                "title": "Command Injection via os.system()",
                "description": "Direct command execution using os.system() detected. "
                "This allows execution of arbitrary shell commands and can lead to "
                "remote code execution if user input is not properly sanitized.",
                "cwe_id": "CWE-78",
                "confidence": Confidence.HIGH,
                "remediation": "1. Avoid os.system() for executing commands\n"
                "2. Use subprocess.run() with shell=False and list arguments\n"
                "3. Validate and sanitize all user inputs\n"
                "4. Use shlex.quote() for shell argument escaping if shell is necessary\n"
                "5. Consider using safer alternatives like pathlib for file operations",
            },
            "subprocess_call_shell": {
                "title": "Command Injection via subprocess.call(shell=True)",
                "description": "subprocess.call() with shell=True detected. "
                "Using shell=True passes commands through the shell, enabling "
                "command injection if user input is included.",
                "cwe_id": "CWE-78",
                "confidence": Confidence.HIGH,
                "remediation": "1. Use shell=False (default) with subprocess.call()\n"
                "2. Pass command as a list of arguments instead of string\n"
                "3. Example: subprocess.call(['ls', '-l']) instead of subprocess.call('ls -l', shell=True)\n"
                "4. If shell features are needed, use shlex.quote() for argument escaping",
            },
            "subprocess_run_shell": {
                "title": "Command Injection via subprocess.run(shell=True)",
                "description": "subprocess.run() with shell=True detected. "
                "Shell interpretation of commands enables injection attacks when "
                "user-controlled data is included.",
                "cwe_id": "CWE-78",
                "confidence": Confidence.HIGH,
                "remediation": "1. Use shell=False (default) with subprocess.run()\n"
                "2. Pass command as a list: subprocess.run(['command', 'arg1', 'arg2'])\n"
                "3. Validate all inputs before including in commands\n"
                "4. Use shlex.quote() if shell=True is absolutely necessary",
            },
            "subprocess_popen_shell": {
                "title": "Command Injection via subprocess.Popen(shell=True)",
                "description": "subprocess.Popen() with shell=True detected. "
                "This creates a shell subprocess that can be exploited for command injection.",
                "cwe_id": "CWE-78",
                "confidence": Confidence.HIGH,
                "remediation": "1. Use shell=False with subprocess.Popen()\n"
                "2. Pass arguments as a list instead of shell command string\n"
                "3. Avoid concatenating user input into commands\n"
                "4. Use shlex.split() to safely parse shell commands if needed",
            },
            "eval_usage": {
                "title": "Code Injection via eval()",
                "description": "Usage of eval() detected. The eval() function executes "
                "arbitrary Python code and is extremely dangerous when used with user input. "
                "It can lead to remote code execution and complete system compromise.",
                "cwe_id": "CWE-95",
                "confidence": Confidence.HIGH,
                "remediation": "1. NEVER use eval() with user-controlled input\n"
                "2. Use ast.literal_eval() for safe evaluation of literals\n"
                "3. Use json.loads() for parsing JSON data\n"
                "4. Consider using safer alternatives like configparser or yaml.safe_load()\n"
                "5. If dynamic code execution is absolutely necessary, use sandboxing",
            },
            "exec_usage": {
                "title": "Code Injection via exec()",
                "description": "Usage of exec() detected. The exec() function executes "
                "arbitrary Python code and poses severe security risks when used with "
                "untrusted input. Can lead to complete system compromise.",
                "cwe_id": "CWE-95",
                "confidence": Confidence.HIGH,
                "remediation": "1. Avoid exec() entirely - there's almost always a better solution\n"
                "2. NEVER use exec() with user-provided input\n"
                "3. Refactor code to use proper function calls or imports\n"
                "4. If dynamic behavior is needed, use plugin architectures with importlib\n"
                "5. Consider using __import__() with strict module name validation",
            },
        }

        metadata = metadata_map[pattern_name]

        return Vulnerability(
            type=VulnerabilityType.CODE_INJECTION,
            title=metadata["title"],
            description=metadata["description"],
            severity=Severity.CRITICAL,
            confidence=metadata["confidence"],
            file_path=str(file_path),
            line_number=line_number,
            code_snippet=code_snippet,
            cwe_id=metadata["cwe_id"],
            cvss_score=9.8,  # Critical severity for RCE
            remediation=metadata["remediation"],
            references=[
                f"https://cwe.mitre.org/data/definitions/{metadata['cwe_id'].split('-')[1]}.html",
                "https://owasp.org/www-community/attacks/Code_Injection",
                "https://owasp.org/Top10/A03_2021-Injection/",
            ],
            detector=self.name,
            engine="static",
            mitre_attack_ids=["T1059"],  # Command and Scripting Interpreter
        )

    def _create_javascript_vulnerability(
        self,
        pattern_name: str,
        file_path: Path,
        line_number: int,
        code_snippet: str,
    ) -> Vulnerability:
        """Create a vulnerability object for JavaScript code injection."""
        metadata_map = {
            "child_process_exec": {
                "title": "Command Injection via child_process.exec()",
                "description": "Usage of child_process.exec() detected. This function "
                "spawns a shell and executes commands, making it vulnerable to command "
                "injection when user input is included. Attackers can execute arbitrary "
                "system commands.",
                "cwe_id": "CWE-78",
                "confidence": Confidence.HIGH,
                "remediation": "1. Use child_process.execFile() instead of exec()\n"
                "2. Use child_process.spawn() with array arguments (no shell)\n"
                "3. Example: spawn('ls', ['-l']) instead of exec('ls -l')\n"
                "4. Validate and sanitize all inputs before including in commands\n"
                "5. Never concatenate user input into command strings",
            },
            "exec_standalone": {
                "title": "Command Injection via exec()",
                "description": "Usage of exec() function detected. This function (typically "
                "from child_process) spawns a shell and executes commands, making it vulnerable "
                "to command injection when user input is included. Attackers can execute arbitrary "
                "system commands.",
                "cwe_id": "CWE-78",
                "confidence": Confidence.HIGH,
                "remediation": "1. Use execFile() instead of exec()\n"
                "2. Use spawn() with array arguments (no shell)\n"
                "3. Example: spawn('ls', ['-l']) instead of exec('ls -l')\n"
                "4. Validate and sanitize all inputs before including in commands\n"
                "5. Never concatenate user input into command strings",
            },
            "eval_usage": {
                "title": "Code Injection via eval()",
                "description": "Usage of eval() detected in JavaScript code. The eval() "
                "function executes arbitrary JavaScript code and is extremely dangerous. "
                "It can lead to XSS, code injection, and complete application compromise "
                "when used with untrusted input.",
                "cwe_id": "CWE-95",
                "confidence": Confidence.HIGH,
                "remediation": "1. NEVER use eval() - there are always better alternatives\n"
                "2. Use JSON.parse() for parsing JSON data\n"
                "3. Use Function constructors if dynamic code is absolutely necessary\n"
                "4. Consider using template literals or object property access\n"
                "5. Implement Content Security Policy (CSP) to block eval()",
            },
            "function_constructor": {
                "title": "Code Injection via Function() Constructor",
                "description": "Usage of Function() constructor detected. The Function() "
                "constructor creates functions from strings and can execute arbitrary "
                "JavaScript code. Similar to eval(), it poses severe security risks.",
                "cwe_id": "CWE-95",
                "confidence": Confidence.MEDIUM,
                "remediation": "1. Avoid Function() constructor when possible\n"
                "2. Never use user input in Function() constructor arguments\n"
                "3. Use named functions or arrow functions instead\n"
                "4. If dynamic functions are needed, use strict input validation\n"
                "5. Consider using safer alternatives like computed property names",
            },
        }

        metadata = metadata_map[pattern_name]

        return Vulnerability(
            type=VulnerabilityType.CODE_INJECTION,
            title=metadata["title"],
            description=metadata["description"],
            severity=Severity.CRITICAL,
            confidence=metadata["confidence"],
            file_path=str(file_path),
            line_number=line_number,
            code_snippet=code_snippet,
            cwe_id=metadata["cwe_id"],
            cvss_score=9.8,  # Critical severity for RCE
            remediation=metadata["remediation"],
            references=[
                f"https://cwe.mitre.org/data/definitions/{metadata['cwe_id'].split('-')[1]}.html",
                "https://owasp.org/www-community/attacks/Code_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html",
            ],
            detector=self.name,
            engine="static",
            mitre_attack_ids=["T1059.007"],  # Command and Scripting Interpreter: JavaScript
        )

    def _guess_file_type(self, file_path: Path) -> Optional[str]:
        """Guess file type from extension."""
        extension_map = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
        }
        return extension_map.get(file_path.suffix.lower())

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

        # Only use for Python files (JS/Java support in Phase 4.3)
        if file_type:
            return file_type == "python"

        return file_path.suffix.lower() == ".py"

    def _semantic_analysis_detection(
        self, file_path: Path, content: str, file_type: Optional[str]
    ) -> List[Vulnerability]:
        """
        Semantic analysis detection (Phase 2 - accurate, multi-line).

        Uses AST parsing and taint tracking to detect vulnerabilities
        that span multiple lines. Also detects dangerous patterns like
        shell=True with AST analysis.

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

            # Convert taint paths to vulnerabilities
            for taint_path in semantic_result.taint_paths:
                # Only process code injection related sinks
                if taint_path.sink.sink_type in [
                    SinkType.COMMAND_EXECUTION,
                    SinkType.CODE_EVALUATION,
                ]:
                    vuln = self._convert_taint_path_to_vulnerability(
                        taint_path, file_path, content
                    )
                    vulnerabilities.append(vuln)

            # Also check for shell=True in subprocess calls (even without taint tracking)
            import ast
            try:
                tree = ast.parse(content, filename=str(file_path))
                shell_true_vulns = self._detect_shell_true_with_ast(tree, file_path, content)
                vulnerabilities.extend(shell_true_vulns)
            except SyntaxError:
                pass

        except Exception as e:
            # Graceful degradation - log error but don't crash
            pass

        return vulnerabilities

    def _detect_shell_true_with_ast(
        self, tree: "ast.AST", file_path: Path, content: str
    ) -> List[Vulnerability]:
        """
        Detect subprocess calls with shell=True using AST analysis.

        This catches multi-line patterns where shell=True is on a different
        line than the subprocess call.

        Args:
            tree: Python AST
            file_path: Path to file
            content: File content

        Returns:
            List of vulnerabilities
        """
        import ast
        vulnerabilities: List[Vulnerability] = []
        lines = content.split("\n")

        class ShellTrueVisitor(ast.NodeVisitor):
            def __init__(self):
                self.shell_true_calls = []

            def visit_Call(self, node):
                # Check if this is a subprocess call
                func_name = ""
                if isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        if node.func.value.id == "subprocess":
                            func_name = f"subprocess.{node.func.attr}"
                    elif isinstance(node.func.value, ast.Attribute):
                        # Handle subprocess.Popen, subprocess.run, etc.
                        func_name = ast.unparse(node.func)

                # Check if shell=True is in kwargs
                has_shell_true = False
                for keyword in node.keywords:
                    if keyword.arg == "shell":
                        if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                            has_shell_true = True
                            break

                if func_name and has_shell_true and any(x in func_name for x in ["Popen", "run", "call"]):
                    self.shell_true_calls.append((func_name, node.lineno))

                self.generic_visit(node)

        visitor = ShellTrueVisitor()
        visitor.visit(tree)

        for func_name, line_num in visitor.shell_true_calls:
            # Get code snippet
            if 0 < line_num <= len(lines):
                code_snippet = lines[line_num - 1].strip()
            else:
                code_snippet = ""

            vuln = Vulnerability(
                type=VulnerabilityType.CODE_INJECTION,
                title=f"Code Injection: {func_name} with shell=True",
                description=f"Detected {func_name} with shell=True parameter. "
                           f"This allows shell command injection if user input is passed to the command. "
                           f"Use shell=False and pass arguments as a list instead.",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file_path=str(file_path),
                line_number=line_num,
                code_snippet=code_snippet,
                cwe_id="CWE-78",
                cvss_score=9.8,
                remediation=(
                    "1. Use shell=False (the default)\n"
                    "2. Pass command and arguments as a list: ['cmd', 'arg1', 'arg2']\n"
                    "3. Never pass user input directly to shell commands\n"
                    "4. Use shlex.quote() if shell=True is absolutely necessary"
                ),
                references=[
                    "https://docs.python.org/3/library/subprocess.html#security-considerations",
                    "https://cwe.mitre.org/data/definitions/78.html",
                ],
                detector=self.name,
                engine="semantic",  # AST-based detection
                mitre_attack_ids=["T1059"],
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

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
        
        # Determine vulnerability type based on sink type
        if taint_path.sink.sink_type == SinkType.COMMAND_EXECUTION:
            vuln_type_name = "Command Injection"
            title = f"Code Injection: {taint_path.sink.function_name}() Command Injection"
        else:  # CODE_EVALUATION
            vuln_type_name = "Code Evaluation"
            title = f"Code Injection: {taint_path.sink.function_name}() Code Evaluation"

        description = (
            f"{vuln_type_name} vulnerability detected via semantic analysis. "
            f"Tainted data from {taint_path.source.origin} (line {taint_path.source.line}) "
            f"flows to {taint_path.sink.function_name}() (line {sink_line_num}). "
            f"Flow: {flow_description}. "
            f"User-controlled input can be used to execute arbitrary commands or code."
        )

        # Adjust severity based on sanitization
        severity = Severity.CRITICAL if not taint_path.sanitized else Severity.HIGH
        confidence = Confidence.HIGH if taint_path.confidence >= 0.8 else Confidence.MEDIUM

        # Determine CWE ID and remediation based on sink type and function
        if taint_path.sink.sink_type == SinkType.COMMAND_EXECUTION:
            cwe_id = "CWE-78"  # OS Command Injection
            remediation = (
                "1. Never use user input directly in commands\n"
                "2. Use parameterized APIs instead of shell=True\n"
                "3. Implement strict input validation and sanitization\n"
                "4. Use allowlists for permitted values\n"
                "5. Apply principle of least privilege\n"
                "6. Consider using safer alternatives (e.g., subprocess without shell=True)"
            )
        elif taint_path.sink.function_name in ["eval", "exec"]:
            cwe_id = "CWE-95"  # Eval Injection (specific)
            # Customize remediation for specific function
            func_name = taint_path.sink.function_name
            remediation = (
                f"1. NEVER use {func_name}() with user-controlled input\n"
                "2. Use ast.literal_eval() for safe evaluation of simple Python literals\n"
                "3. Consider using JSON parsing instead of eval()\n"
                "4. If dynamic code execution is required, use sandboxing\n"
                "5. Implement strict input validation and allowlists\n"
                "6. Apply principle of least privilege"
            )
        else:
            cwe_id = "CWE-94"  # Code Injection (general)
            remediation = (
                "1. Never use user input directly in code evaluation\n"
                "2. Implement strict input validation and sanitization\n"
                "3. Use allowlists for permitted values\n"
                "4. Apply principle of least privilege\n"
                "5. Consider using safer alternatives"
            )

        return Vulnerability(
            type=VulnerabilityType.CODE_INJECTION,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            file_path=str(file_path),
            line_number=sink_line_num,
            code_snippet=code_snippet,
            cwe_id=cwe_id,
            cvss_score=9.8 if not taint_path.sanitized else 7.3,
            remediation=remediation,
            references=[
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://owasp.org/www-community/attacks/Code_Injection",
                "https://cwe.mitre.org/data/definitions/78.html",
                "https://cwe.mitre.org/data/definitions/94.html",
            ],
            detector=self.name,
            engine="semantic",  # Mark as semantic engine detection
            mitre_attack_ids=["T1059"],
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
