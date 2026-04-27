"""Bandit adapter for SAST engine (Python-specific)."""

import asyncio
import json
import shutil
from pathlib import Path
from typing import Any

from mcp_sentinel.models.vulnerability import Confidence, Severity, Vulnerability, VulnerabilityType


class BanditAdapter:
    """Adapter for Bandit SAST tool (Python security)."""

    def __init__(
        self,
        enabled: bool = True,
        timeout: int = 300,
    ):
        """
        Initialize Bandit adapter.

        Args:
            enabled: Whether adapter is enabled
            timeout: Command timeout in seconds
        """
        self.enabled = enabled and shutil.which("bandit") is not None
        self.timeout = timeout

        if not self.enabled:
            print("[INFO] Bandit not available - adapter disabled")

    async def scan_directory(
        self,
        target_path: Path,
    ) -> list[Vulnerability]:
        """
        Scan directory with Bandit (Python files only).

        Args:
            target_path: Directory to scan

        Returns:
            List of vulnerabilities found
        """
        if not self.enabled:
            return []

        try:
            # Build Bandit command
            cmd = self._build_command(target_path)

            # Run Bandit
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout,
                )
            except TimeoutError:
                process.kill()
                print(f"[WARN] Bandit timeout after {self.timeout}s")
                return []

            # Parse results
            # Bandit returns 0 (no issues), 1 (issues found), or >1 (error)
            if process.returncode in (0, 1):
                return self._parse_results(stdout.decode("utf-8"), target_path)
            else:
                print(f"[WARN] Bandit failed: {stderr.decode('utf-8')}")
                return []

        except Exception as e:
            print(f"[ERROR] Bandit execution error: {e}")
            return []

    async def scan_file(
        self,
        file_path: Path,
    ) -> list[Vulnerability]:
        """
        Scan single Python file with Bandit.

        Args:
            file_path: File to scan

        Returns:
            List of vulnerabilities found
        """
        if not self.enabled:
            return []

        # Only scan Python files
        if file_path.suffix not in (".py", ".pyw"):
            return []

        try:
            # Build command for single file
            cmd = ["bandit", "-f", "json", str(file_path)]

            # Run Bandit
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout,
                )
            except TimeoutError:
                process.kill()
                print(f"[WARN] Bandit timeout for {file_path}")
                return []

            if process.returncode in (0, 1):
                return self._parse_results(stdout.decode("utf-8"), file_path.parent)
            else:
                return []

        except Exception as e:
            print(f"[ERROR] Bandit file scan error: {e}")
            return []

    def _build_command(self, target_path: Path) -> list[str]:
        """
        Build Bandit command.

        Args:
            target_path: Target to scan

        Returns:
            Command as list of arguments
        """
        return [
            "bandit",
            "-r",  # Recursive
            "-f",
            "json",  # JSON format
            str(target_path),
        ]

    def _parse_results(
        self,
        output: str,
        target_path: Path,
    ) -> list[Vulnerability]:
        """
        Parse Bandit JSON output.

        Args:
            output: Bandit JSON output
            target_path: Scanned directory

        Returns:
            List of vulnerabilities
        """
        vulnerabilities: list[Vulnerability] = []

        try:
            data = json.loads(output)
            results = data.get("results", [])

            for result in results:
                vuln = self._convert_to_vulnerability(result, target_path)
                if vuln:
                    vulnerabilities.append(vuln)

        except json.JSONDecodeError as e:
            print(f"[ERROR] Failed to parse Bandit output: {e}")
        except Exception as e:
            print(f"[ERROR] Error processing Bandit results: {e}")

        return vulnerabilities

    def _convert_to_vulnerability(
        self,
        result: dict[str, Any],
        target_path: Path,
    ) -> Vulnerability | None:
        """
        Convert Bandit result to Vulnerability.

        Args:
            result: Bandit result object
            target_path: Base scan directory

        Returns:
            Vulnerability object or None
        """
        try:
            # Extract file path
            file_path = Path(result.get("filename", ""))
            if not file_path.is_absolute():
                file_path = target_path / file_path

            # Extract location
            line_number = result.get("line_number", 0)

            # Extract issue info
            test_id = result.get("test_id", "unknown")
            test_name = result.get("test_name", "Security Issue")
            issue_text = result.get("issue_text", "")

            # Map severity
            issue_severity = result.get("issue_severity", "MEDIUM").upper()
            issue_confidence = result.get("issue_confidence", "MEDIUM").upper()
            severity = self._map_severity(issue_severity, issue_confidence)

            # Extract code
            code_snippet = result.get("code", "")

            # Extract CWE
            cwe = self._extract_cwe(result)

            # Build description
            description = f"{issue_text}"
            if "more_info" in result:
                description += f"\n\nMore info: {result['more_info']}"

            # Build remediation
            remediation = None
            if "more_info" in result:
                remediation = f"See Bandit documentation: {result['more_info']}"

            # Map test_id to VulnerabilityType
            vuln_type = self._map_test_id_to_type(test_id)

            # Map confidence string to enum
            confidence_map = {
                "HIGH": Confidence.HIGH,
                "MEDIUM": Confidence.MEDIUM,
                "LOW": Confidence.LOW,
            }
            confidence = confidence_map.get(issue_confidence, Confidence.MEDIUM)

            # Store original test_id in metadata
            metadata = {"bandit_test_id": test_id, "bandit_test_name": test_name}

            return Vulnerability(
                type=vuln_type,
                severity=severity,
                title=f"Bandit: {test_name}",
                description=description,
                file_path=str(file_path),
                line_number=line_number,
                code_snippet=code_snippet,
                remediation=remediation,
                cwe_id=cwe,
                confidence=confidence,
                detector="BanditAdapter",
                engine="sast",
                metadata=metadata,
            )

        except Exception as e:
            print(f"[ERROR] Failed to convert Bandit result: {e}")
            return None

    def _map_test_id_to_type(self, test_id: str) -> VulnerabilityType:
        """
        Map Bandit test_id to MCP Sentinel VulnerabilityType.

        Args:
            test_id: Bandit test ID (e.g., B608)

        Returns:
            VulnerabilityType enum value
        """
        # Mapping based on Bandit test IDs
        mapping = {
            # Code injection
            "B307": VulnerabilityType.CODE_INJECTION,  # eval
            "B308": VulnerabilityType.CODE_INJECTION,  # mark_safe
            "B401": VulnerabilityType.CODE_INJECTION,  # subprocess import
            "B601": VulnerabilityType.CODE_INJECTION,  # shell injection
            "B602": VulnerabilityType.CODE_INJECTION,  # shell=True
            "B603": VulnerabilityType.CODE_INJECTION,  # subprocess
            "B604": VulnerabilityType.CODE_INJECTION,  # shell=True variants
            "B605": VulnerabilityType.CODE_INJECTION,  # start with shell
            "B606": VulnerabilityType.CODE_INJECTION,  # start without shell
            "B607": VulnerabilityType.CODE_INJECTION,  # partial path
            "B608": VulnerabilityType.CODE_INJECTION,  # SQL
            "B609": VulnerabilityType.CODE_INJECTION,  # wildcard injection
            "B610": VulnerabilityType.CODE_INJECTION,  # SQL string format
            "B611": VulnerabilityType.CODE_INJECTION,  # SQL concat
            # Weak crypto
            "B303": VulnerabilityType.WEAK_CRYPTO,  # MD5
            "B304": VulnerabilityType.WEAK_CRYPTO,  # insecure ciphers
            "B305": VulnerabilityType.WEAK_CRYPTO,  # insecure cipher modes
            "B505": VulnerabilityType.WEAK_CRYPTO,  # weak crypto key
            # Insecure deserialization
            "B301": VulnerabilityType.INSECURE_DESERIALIZATION,  # pickle
            "B302": VulnerabilityType.INSECURE_DESERIALIZATION,  # marshal
            "B506": VulnerabilityType.INSECURE_DESERIALIZATION,  # YAML load
            # Config security
            "B201": VulnerabilityType.CONFIG_SECURITY,  # Flask debug
            "B306": VulnerabilityType.CONFIG_SECURITY,  # mktemp
            "B501": VulnerabilityType.CONFIG_SECURITY,  # SSL cert
            "B502": VulnerabilityType.CONFIG_SECURITY,  # SSL version
            "B503": VulnerabilityType.CONFIG_SECURITY,  # SSL cipher
            "B504": VulnerabilityType.CONFIG_SECURITY,  # SSL no validation
            # XSS
            "B701": VulnerabilityType.XSS,  # Jinja2 autoescape
            "B702": VulnerabilityType.XSS,  # Mako templates
            "B703": VulnerabilityType.XSS,  # Django mark_safe
            # Path traversal
            "B310": VulnerabilityType.PATH_TRAVERSAL,  # urllib.urlopen
            # Supply chain
            "B311": VulnerabilityType.SUPPLY_CHAIN,  # random
            "B313": VulnerabilityType.SUPPLY_CHAIN,  # XML parsing
            "B320": VulnerabilityType.SUPPLY_CHAIN,  # XML vulnerabilities
            "B312": VulnerabilityType.SUPPLY_CHAIN,  # telnetlib
        }

        # Return mapped type or default to CODE_INJECTION
        return mapping.get(test_id, VulnerabilityType.CODE_INJECTION)

    def _map_severity(
        self,
        issue_severity: str,
        issue_confidence: str,
    ) -> Severity:
        """
        Map Bandit severity + confidence to MCP Sentinel severity.

        Bandit severities: HIGH, MEDIUM, LOW
        Bandit confidence: HIGH, MEDIUM, LOW

        Mapping strategy:
        - HIGH severity + HIGH confidence → CRITICAL
        - HIGH severity + MEDIUM confidence → HIGH
        - HIGH severity + LOW confidence → MEDIUM
        - MEDIUM severity + HIGH confidence → HIGH
        - MEDIUM severity + MEDIUM confidence → MEDIUM
        - MEDIUM severity + LOW confidence → LOW
        - LOW severity → LOW

        Args:
            issue_severity: Bandit severity
            issue_confidence: Bandit confidence

        Returns:
            MCP Sentinel severity
        """
        if issue_severity == "HIGH":
            if issue_confidence == "HIGH":
                return Severity.CRITICAL
            elif issue_confidence == "MEDIUM":
                return Severity.HIGH
            else:
                return Severity.MEDIUM
        elif issue_severity == "MEDIUM":
            if issue_confidence == "HIGH":
                return Severity.HIGH
            elif issue_confidence == "MEDIUM":
                return Severity.MEDIUM
            else:
                return Severity.LOW
        else:  # LOW
            return Severity.LOW

    def _extract_cwe(self, result: dict[str, Any]) -> str | None:
        """
        Extract CWE ID from Bandit result.

        Args:
            result: Bandit result object

        Returns:
            CWE ID or None
        """
        # Bandit includes CWE in some test IDs
        test_id = result.get("test_id", "")

        # Map common Bandit test IDs to CWEs
        cwe_mapping = {
            "B201": "CWE-703",  # Flask debug mode
            "B301": "CWE-327",  # Pickle usage
            "B302": "CWE-327",  # marshal usage
            "B303": "CWE-327",  # MD5 usage
            "B304": "CWE-327",  # Insecure ciphers
            "B305": "CWE-327",  # Insecure cipher modes
            "B306": "CWE-327",  # mktemp usage
            "B307": "CWE-78",  # eval usage
            "B308": "CWE-22",  # mark_safe usage
            "B310": "CWE-918",  # urllib.urlopen
            "B311": "CWE-330",  # Random usage
            "B312": "CWE-327",  # telnetlib usage
            "B313": "CWE-776",  # XML parsing
            "B320": "CWE-776",  # XML parsing vulnerabilities
            "B401": "CWE-78",  # import of subprocess
            "B501": "CWE-295",  # SSL certificate verification
            "B502": "CWE-295",  # SSL/TLS insecure version
            "B503": "CWE-295",  # SSL/TLS weak cipher
            "B504": "CWE-295",  # SSL/TLS no certificate validation
            "B505": "CWE-327",  # Weak cryptographic key
            "B506": "CWE-20",  # YAML load
            "B601": "CWE-78",  # Shell injection
            "B602": "CWE-78",  # Shell=True
            "B603": "CWE-78",  # Subprocess without shell
            "B604": "CWE-78",  # Shell=True variants
            "B605": "CWE-78",  # Starting process with shell
            "B606": "CWE-78",  # Starting process without shell
            "B607": "CWE-78",  # Partial path in subprocess
            "B608": "CWE-89",  # SQL injection
            "B609": "CWE-78",  # Wildcard injection
            "B610": "CWE-89",  # SQL string format
            "B611": "CWE-89",  # SQL string concat
            "B701": "CWE-502",  # Jinja2 autoescape
            "B702": "CWE-502",  # Mako templates
            "B703": "CWE-502",  # Django mark_safe
        }

        return cwe_mapping.get(test_id)
