"""
Code injection detector for finding command injection and code execution vulnerabilities.

Detects:
- Python: os.system(), subprocess with shell=True, eval(), exec()
- JavaScript/TypeScript: child_process.exec(), eval(), Function() constructor
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


class CodeInjectionDetector(BaseDetector):
    """
    Detector for code injection and command injection vulnerabilities.

    Detects 9 dangerous patterns across Python and JavaScript/TypeScript:
    - Python command injection (os.system, subprocess with shell=True)
    - Python code execution (eval, exec)
    - JavaScript command injection (child_process.exec)
    - JavaScript code execution (eval, Function constructor)
    """

    def __init__(self):
        """Initialize the code injection detector."""
        super().__init__(name="CodeInjectionDetector", enabled=True)
        self.python_patterns: Dict[str, Pattern] = self._compile_python_patterns()
        self.javascript_patterns: Dict[str, Pattern] = self._compile_javascript_patterns()

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

        if file_type == "python":
            vulnerabilities.extend(
                self._detect_python_injection(file_path, content)
            )
        elif file_type in ["javascript", "typescript"]:
            vulnerabilities.extend(
                self._detect_javascript_injection(file_path, content)
            )

        return vulnerabilities

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
