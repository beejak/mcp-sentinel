"""Semgrep adapter for SAST engine."""

import asyncio
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from mcp_sentinel.models.vulnerability import Confidence, Severity, Vulnerability, VulnerabilityType


def _semgrep_failure_hint(stderr_text: str) -> str:
    """Return user-facing hint when Semgrep fails (common OpenTelemetry skew on Windows)."""
    if "redact_url" in stderr_text or "opentelemetry" in stderr_text.lower():
        return (
            "Semgrep failed to import (often OpenTelemetry packages out of sync). Try: "
            "pip install --upgrade semgrep opentelemetry-util-http "
            "opentelemetry-instrumentation-requests opentelemetry-api opentelemetry-sdk "
            "(use one venv for MCP Sentinel + Semgrep, or upgrade exporters if pip reports conflicts)."
        )
    return "Check that `semgrep` runs in a terminal (`semgrep --version`) and matches your Python environment."


def _extract_first_json_object(text: str) -> str | None:
    """Parse the first JSON object from text that may contain logs or banners before JSON."""
    raw = text.strip()
    if not raw:
        return None
    if raw.startswith("\ufeff"):
        raw = raw.lstrip("\ufeff")
    decoder = json.JSONDecoder()
    try:
        _, end = decoder.raw_decode(raw)
        return raw[:end]
    except json.JSONDecodeError:
        pass
    start = raw.find("{")
    if start < 0:
        return None
    try:
        _, end = decoder.raw_decode(raw[start:])
        return raw[start : start + end]
    except json.JSONDecodeError:
        return None


class SemgrepAdapter:
    """Adapter for Semgrep SAST tool."""

    def __init__(
        self,
        enabled: bool = True,
        rulesets: list[str] | None = None,
        timeout: int = 300,
    ):
        """
        Initialize Semgrep adapter.

        Args:
            enabled: Whether adapter is enabled
            rulesets: Semgrep rulesets to use (e.g., ["p/security-audit", "p/owasp-top-ten"])
            timeout: Command timeout in seconds
        """
        self.enabled = enabled and shutil.which("semgrep") is not None
        self.rulesets = rulesets or [
            "p/security-audit",
            "p/owasp-top-ten",
            "p/command-injection",
        ]
        self.timeout = timeout

        if not self.enabled:
            print("[INFO] Semgrep not available - adapter disabled")

    def _build_command(self, target_path: Path, json_out: Path) -> list[str]:
        """
        Build Semgrep command.

        Uses --json -o <file> so results are read from disk (avoids broken / mixed stdout on Windows).
        --quiet reduces non-JSON noise when Semgrep still prints to stdout.
        """
        cmd = [
            "semgrep",
            "scan",
            "--json",
            "--quiet",
            "-o",
            str(json_out),
        ]

        for ruleset in self.rulesets:
            cmd.extend(["--config", ruleset])

        cmd.append(str(target_path))
        return cmd

    def _subprocess_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env.setdefault("SEMGREP_SEND_METRICS", "off")
        return env

    async def scan_directory(
        self,
        target_path: Path,
    ) -> list[Vulnerability]:
        """
        Scan directory with Semgrep.

        Args:
            target_path: Directory to scan

        Returns:
            List of vulnerabilities found
        """
        if not self.enabled:
            return []

        fd, tmp_name = tempfile.mkstemp(suffix=".semgrep.json")
        os.close(fd)
        out_path = Path(tmp_name)

        try:
            cmd = self._build_command(target_path, out_path)

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._subprocess_env(),
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout,
                )
            except TimeoutError:
                process.kill()
                print(f"[WARN] Semgrep timeout after {self.timeout}s")
                return []

            err_txt = (stderr or b"").decode("utf-8", errors="replace")
            out_txt = (stdout or b"").decode("utf-8", errors="replace")

            # Semgrep: 0 = clean, 1 = findings. Other codes may still write partial JSON.
            if process.returncode not in (0, 1):
                print(f"[WARN] Semgrep exited with code {process.returncode}")
                if err_txt.strip():
                    print(f"[WARN] Semgrep stderr:\n{err_txt[:2000]}")

            raw_json = ""
            if out_path.is_file() and out_path.stat().st_size > 0:
                raw_json = out_path.read_text(encoding="utf-8", errors="replace")
            elif out_txt.strip():
                raw_json = out_txt
            else:
                # Fall back: some installs only emit JSON on stdout when -o fails
                blob = _extract_first_json_object(out_txt)
                if blob:
                    raw_json = blob

            if not raw_json.strip():
                if err_txt.strip():
                    print(f"[ERROR] Semgrep produced no JSON output. stderr:\n{err_txt[:2000]}")
                    hint = _semgrep_failure_hint(err_txt)
                    print(f"[ERROR] {hint}")
                else:
                    print("[ERROR] Semgrep produced empty output (no JSON). Is Semgrep installed correctly?")
                return []

            return self._parse_results(raw_json, target_path, stderr_context=err_txt)

        except Exception as e:
            print(f"[ERROR] Semgrep execution error: {e}")
            return []
        finally:
            try:
                out_path.unlink(missing_ok=True)
            except OSError:
                pass

    async def scan_file(
        self,
        file_path: Path,
    ) -> list[Vulnerability]:
        """
        Scan single file with Semgrep.

        Args:
            file_path: Path to file

        Returns:
            List of vulnerabilities found
        """
        if not self.enabled:
            return []

        return await self.scan_directory(file_path.parent)

    def _parse_results(
        self,
        output: str,
        target_path: Path,
        *,
        stderr_context: str = "",
    ) -> list[Vulnerability]:
        """
        Parse Semgrep JSON output.

        Args:
            output: Semgrep JSON output (possibly prefixed with noise)
            target_path: Scanned directory
            stderr_context: Semgrep stderr for diagnostics

        Returns:
            List of vulnerabilities
        """
        vulnerabilities: list[Vulnerability] = []

        try:
            text = output.strip()
            if not text.startswith("{"):
                extracted = _extract_first_json_object(text)
                if extracted:
                    text = extracted
            data = json.loads(text)
            results = data.get("results", [])

            for result in results:
                vuln = self._convert_to_vulnerability(result, target_path)
                if vuln:
                    vulnerabilities.append(vuln)

        except json.JSONDecodeError as e:
            print(f"[ERROR] Failed to parse Semgrep output: {e}")
            if stderr_context.strip():
                print(f"[ERROR] Semgrep stderr (tail):\n{stderr_context[-1500:]}")
            blob = _extract_first_json_object(output)
            if blob:
                try:
                    data = json.loads(blob)
                    for result in data.get("results", []):
                        vuln = self._convert_to_vulnerability(result, target_path)
                        if vuln:
                            vulnerabilities.append(vuln)
                except json.JSONDecodeError:
                    hint = _semgrep_failure_hint(stderr_context)
                    print(f"[ERROR] {hint}")
        except Exception as e:
            print(f"[ERROR] Error processing Semgrep results: {e}")

        return vulnerabilities

    def _convert_to_vulnerability(
        self,
        result: dict[str, Any],
        target_path: Path,
    ) -> Vulnerability | None:
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
            message = extra.get(
                "message", result.get("extra", {}).get("message", "Security issue detected")
            )

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
        if (
            "secret" in check_id_lower
            or "credential" in check_id_lower
            or "password" in check_id_lower
            or "key" in check_id_lower
        ):
            return VulnerabilityType.SECRET_EXPOSURE

        # Crypto
        if "crypto" in check_id_lower or "hash" in check_id_lower or "cipher" in check_id_lower:
            return VulnerabilityType.WEAK_CRYPTO

        # Deserialization
        if (
            "deserial" in check_id_lower
            or "pickle" in check_id_lower
            or "unmarshal" in check_id_lower
        ):
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

    def _extract_cwe(self, metadata: dict[str, Any]) -> str | None:
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
