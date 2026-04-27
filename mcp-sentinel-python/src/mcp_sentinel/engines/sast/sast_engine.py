"""
SAST Integration Engine for MCP Sentinel.

Integrates Semgrep and Bandit for industry-standard static analysis.
"""

import shutil
from pathlib import Path

from mcp_sentinel.engines.base import BaseEngine, EngineStatus, EngineType
from mcp_sentinel.models.vulnerability import Vulnerability


class SASTEngine(BaseEngine):
    """
    SAST Integration Engine using Semgrep and Bandit.

    This engine delegates to external SAST tools:
    - Semgrep: Multi-language static analysis with community rules
    - Bandit: Python-specific security scanner
    """

    def __init__(
        self,
        enabled: bool = True,
        semgrep_enabled: bool = True,
        bandit_enabled: bool = True,
        semgrep_rulesets: list[str] | None = None,
    ):
        """
        Initialize the SAST engine.

        Args:
            enabled: Whether engine is enabled
            semgrep_enabled: Whether to use Semgrep
            bandit_enabled: Whether to use Bandit
            semgrep_rulesets: List of Semgrep rulesets to use
        """
        super().__init__(
            name="SAST Engine",
            engine_type=EngineType.SAST,
            enabled=enabled,
        )

        # Check if tools are available
        self.semgrep_available = semgrep_enabled and shutil.which("semgrep") is not None
        self.bandit_available = bandit_enabled and shutil.which("bandit") is not None

        if not self.semgrep_available and not self.bandit_available:
            print("[WARN] Neither Semgrep nor Bandit available. SAST engine disabled.")
            self.enabled = False

        # Initialize adapters (will create these next)
        self.semgrep = None
        self.bandit = None

        if self.semgrep_available:
            from mcp_sentinel.engines.sast.semgrep_adapter import SemgrepAdapter

            self.semgrep = SemgrepAdapter(
                enabled=semgrep_enabled,
                rulesets=semgrep_rulesets,
            )

        if self.bandit_available:
            from mcp_sentinel.engines.sast.bandit_adapter import BanditAdapter

            self.bandit = BanditAdapter(enabled=bandit_enabled)

    async def scan_file(
        self,
        file_path: Path,
        content: str,
        file_type: str | None = None,
    ) -> list[Vulnerability]:
        """
        Scan a single file (SAST tools work better on directories).

        For single file scans, we create a temporary directory scan.
        """
        vulnerabilities: list[Vulnerability] = []

        # Semgrep and Bandit work on directories, not individual files
        # For single file scans, scan the parent directory and filter
        parent_dir = file_path.parent
        all_vulns = await self.scan_directory(parent_dir)

        # Filter to only this file
        vulnerabilities = [v for v in all_vulns if Path(v.file_path) == file_path]

        return vulnerabilities

    async def scan_directory(
        self,
        target_path: Path,
        file_patterns: list[str] | None = None,
    ) -> list[Vulnerability]:
        """
        Scan a directory using Semgrep and Bandit.

        Args:
            target_path: Directory to scan
            file_patterns: Optional glob patterns (not used by SAST tools)

        Returns:
            List of all detected vulnerabilities
        """
        self.status = EngineStatus.RUNNING
        vulnerabilities: list[Vulnerability] = []

        try:
            # Run Semgrep if available
            if self.semgrep and self.semgrep.enabled:
                try:
                    semgrep_vulns = await self.semgrep.scan_directory(target_path)
                    vulnerabilities.extend(semgrep_vulns)
                except Exception as e:
                    print(f"[ERROR] Semgrep scan failed: {e}")

            # Run Bandit if available
            if self.bandit and self.bandit.enabled:
                try:
                    bandit_vulns = await self.bandit.scan_directory(target_path)
                    vulnerabilities.extend(bandit_vulns)
                except Exception as e:
                    print(f"[ERROR] Bandit scan failed: {e}")

            self.status = EngineStatus.COMPLETED
            return vulnerabilities

        except Exception as e:
            self.status = EngineStatus.FAILED
            raise RuntimeError(f"SAST analysis failed: {e}") from e

    def is_applicable(
        self,
        file_path: Path,
        file_type: str | None = None,
    ) -> bool:
        """
        Check if SAST engine can analyze the given file.

        SAST tools support multiple languages.
        """
        # Semgrep supports many languages
        if self.semgrep_available:
            return True

        # Bandit only supports Python
        if self.bandit_available and file_type == "python":
            return True

        return False

    def get_supported_languages(self) -> list[str]:
        """
        Get list of supported programming languages.

        Returns:
            List of language identifiers
        """
        languages = []

        if self.semgrep_available:
            # Semgrep supports many languages
            languages.extend(
                [
                    "python",
                    "javascript",
                    "typescript",
                    "java",
                    "go",
                    "ruby",
                    "php",
                    "c",
                    "cpp",
                    "rust",
                ]
            )

        if self.bandit_available and "python" not in languages:
            languages.append("python")

        return list(set(languages))

    def __str__(self) -> str:
        tools = []
        if self.semgrep_available:
            tools.append("Semgrep")
        if self.bandit_available:
            tools.append("Bandit")

        return f"{self.name} ({', '.join(tools) if tools else 'no tools available'})"
