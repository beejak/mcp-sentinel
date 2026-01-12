"""Semgrep adapter for SAST engine."""

import asyncio
import json
import shutil
from pathlib import Path
from typing import List, Optional, Dict, Any

from mcp_sentinel.models.vulnerability import Vulnerability, Severity, VulnerabilityType, Confidence


class SemgrepAdapter:
    """Adapter for Semgrep SAST tool."""

    def __init__(
        self,
        enabled: bool = True,
        rulesets: Optional[List[str]] = None,
        timeout: int = 300,
    ):
        """
        Initialize Semgrep adapter.

        Args:
            enabled: Whether adapter is enabled
            rulesets: Semgrep rulesets to use (e.g., ["p/security-audit", "p/owasp-top-10"])
            timeout: Command timeout in seconds
        """
        self.enabled = enabled and shutil.which("semgrep") is not None
        self.rulesets = rulesets or [
            "p/security-audit",
            "p/owasp-top-10",
            "p/command-injection",
        ]
        self.timeout = timeout

        if not self.enabled:
            print("[INFO] Semgrep not available - adapter disabled")

    async def scan_directory(
        self,
        target_path: Path,
    ) -> List[Vulnerability]:
        """
        Scan directory with Semgrep.

        Args:
            target_path: Directory to scan

        Returns:
            List of vulnerabilities found
        """
        if not self.enabled:
            return []

        try:
            # Build Semgrep command
            cmd = self._build_command(target_path)

            # Run Semgrep
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
            except asyncio.TimeoutError:
                process.kill()
                print(f"[WARN] Semgrep timeout after {self.timeout}s")
                return []

            # Parse results
            if process.returncode == 0 or process.returncode == 1:
                # returncode 1 means findings found (not an error)
                return self._parse_results(stdout.decode("utf-8"), target_path)
            else:
                print(f"[WARN] Semgrep failed: {stderr.decode('utf-8')}")
                return []

        except Exception as e:
            print(f"[ERROR] Semgrep execution error: {e}")
            return []

    async def scan_file(
        self,
        file_path: Path,
    ) -> List[Vulnerability]:
        """
        Scan single file with Semgrep.

        Args:
            file_path: File to scan

        Returns:
            List of vulnerabilities found
        """
        if not self.enabled:
            return []

        # Semgrep works better on directories, so scan parent
        return await self.scan_directory(file_path.parent)

    def _build_command(self, target_path: Path) -> List[str]:
        """
        Build Semgrep command.

        Args:
            target_path: Target to scan

        Returns:
            Command as list of arguments
        """
        cmd = ["semgrep", "scan", "--json"]

        # Add rulesets
        for ruleset in self.rulesets:
            cmd.extend(["--config", ruleset])

        # Add target
        cmd.append(str(target_path))

        return cmd

    def _parse_results(
        self,
        output: str,
        target_path: Path,
    ) -> List[Vulnerability]:
        """
        Parse Semgrep JSON output.

        Args:
            output: Semgrep JSON output
            target_path: Scanned directory

        Returns:
            List of vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []

        try:
            data = json.loads(output)
            results = data.get("results", [])

            for result in results:
                vuln = self._convert_to_vulnerability(result, target_path)
                if vuln:
                    vulnerabilities.append(vuln)

        except json.JSONDecodeError as e:
            print(f"[ERROR] Failed to parse Semgrep output: {e}")
        except Exception as e:
            print(f"[ERROR] Error processing Semgrep results: {e}")

        return vulnerabilities

    def _convert_to_vulnerability(
        self,
        result: Dict[str, Any],
        target_path: Path,
    ) -> Optional[Vulnerability]:
        """
        Convert Semgrep result to Vulnerability.

        Args:
            result: Semgrep result object
            target_path: Base scan directory

        Returns:
            Vulnerability object or None
        """
        try:
            # Extract file path
            file_path = Path(result.get("path", ""))
            if not file_path.is_absolute():
                file_path = target_path / file_path

            # Extract location
            start = result.get("start", {})
            line_number = start.get("line", 0)

            # Extract rule info
            check_id = result.get("check_id", "unknown")
            extra = result.get("extra", {})
            message = extra.get("message", result.get("extra", {}).get("message", "Security issue detected"))

            # Map severity
            severity_str = extra.get("severity", "WARNING").upper()
            severity = self._map_severity(severity_str)

            # Extract CWE
            metadata = extra.get("metadata", {})
            cwe = self._extract_cwe(metadata)

            # Build description
            description = message
            if "lines" in extra:
                description += f"\n\nCode:\n{extra['lines']}"

            # Build remediation from fix or references
            remediation = None
            if "fix" in extra:
                remediation = f"Suggested fix: {extra['fix']}"
            elif "references" in metadata:
                refs = metadata["references"]
                if isinstance(refs, list) and refs:
                    remediation = f"References: {', '.join(refs[:3])}"

            # Map check_id to VulnerabilityType
            vuln_type = self._map_check_id_to_type(check_id)

            # Store original check_id in metadata
            metadata = {"semgrep_check_id": check_id}

            return Vulnerability(
                type=vuln_type,
                severity=severity,
                title=f"Semgrep: {check_id}",
                description=description,
                file_path=str(file_path),
                line_number=line_number,
                code_snippet=extra.get("lines", ""),
                remediation=remediation,
                cwe_id=cwe,
                confidence=Confidence.HIGH,
                detector="SemgrepAdapter",
                engine="sast",
                metadata=metadata,
            )

        except Exception as e:
            print(f"[ERROR] Failed to convert Semgrep result: {e}")
            return None

    def _map_check_id_to_type(self, check_id: str) -> VulnerabilityType:
        """
        Map Semgrep check_id to MCP Sentinel VulnerabilityType.

        Args:
            check_id: Semgrep check ID

        Returns:
            VulnerabilityType enum value
        """
        check_id_lower = check_id.lower()

        # SQL injection
        if "sql" in check_id_lower or "sqli" in check_id_lower:
            return VulnerabilityType.CODE_INJECTION

        # Command injection
        if "command" in check_id_lower or "shell" in check_id_lower or "exec" in check_id_lower:
            return VulnerabilityType.CODE_INJECTION

        # XSS
        if "xss" in check_id_lower or "cross-site" in check_id_lower:
            return VulnerabilityType.XSS

        # Path traversal
        if "path-traversal" in check_id_lower or "directory-traversal" in check_id_lower:
            return VulnerabilityType.PATH_TRAVERSAL

        # Secrets
        if "secret" in check_id_lower or "credential" in check_id_lower or "password" in check_id_lower or "key" in check_id_lower:
            return VulnerabilityType.SECRET_EXPOSURE

        # Crypto
        if "crypto" in check_id_lower or "hash" in check_id_lower or "cipher" in check_id_lower:
            return VulnerabilityType.WEAK_CRYPTO

        # Deserialization
        if "deserial" in check_id_lower or "pickle" in check_id_lower or "unmarshal" in check_id_lower:
            return VulnerabilityType.INSECURE_DESERIALIZATION

        # Supply chain
        if "supply-chain" in check_id_lower or "dependency" in check_id_lower:
            return VulnerabilityType.SUPPLY_CHAIN

        # Config
        if "config" in check_id_lower or "debug" in check_id_lower:
            return VulnerabilityType.CONFIG_SECURITY

        # Default to code injection for other security issues
        return VulnerabilityType.CODE_INJECTION

    def _map_severity(self, semgrep_severity: str) -> Severity:
        """
        Map Semgrep severity to MCP Sentinel severity.

        Semgrep severities: ERROR, WARNING, INFO
        MCP Sentinel: CRITICAL, HIGH, MEDIUM, LOW, INFO

        Args:
            semgrep_severity: Semgrep severity string

        Returns:
            MCP Sentinel severity
        """
        mapping = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
        }
        return mapping.get(semgrep_severity, Severity.MEDIUM)

    def _extract_cwe(self, metadata: Dict[str, Any]) -> Optional[str]:
        """
        Extract CWE ID from Semgrep metadata.

        Args:
            metadata: Semgrep rule metadata

        Returns:
            CWE ID or None
        """
        # Check various metadata fields
        if "cwe" in metadata:
            cwe = metadata["cwe"]
            if isinstance(cwe, list) and cwe:
                return f"CWE-{cwe[0]}" if isinstance(cwe[0], int) else str(cwe[0])
            return str(cwe)

        if "cwe-id" in metadata:
            return metadata["cwe-id"]

        # Check in OWASP metadata
        if "owasp" in metadata:
            owasp = metadata["owasp"]
            if isinstance(owasp, dict) and "cwe" in owasp:
                return owasp["cwe"]

        return None
