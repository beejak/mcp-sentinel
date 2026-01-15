"""
Main scanner orchestrator for MCP Sentinel.
"""

from datetime import datetime
from pathlib import Path

from mcp_sentinel.core.exceptions import ScanError
from mcp_sentinel.detectors.base import BaseDetector
from mcp_sentinel.detectors.code_injection import CodeInjectionDetector
from mcp_sentinel.detectors.config_security import ConfigSecurityDetector
from mcp_sentinel.detectors.path_traversal import PathTraversalDetector
from mcp_sentinel.detectors.prompt_injection import PromptInjectionDetector
from mcp_sentinel.detectors.secrets import SecretsDetector
from mcp_sentinel.detectors.supply_chain import SupplyChainDetector
from mcp_sentinel.detectors.tool_poisoning import ToolPoisoningDetector
from mcp_sentinel.detectors.xss import XSSDetector
from mcp_sentinel.models.scan_result import ScanResult
from mcp_sentinel.models.vulnerability import Vulnerability


class Scanner:
    """
    Main scanner orchestrator that coordinates all detectors and engines.

    This is the primary entry point for scanning operations.
    """

    def __init__(self, detectors: list[BaseDetector] | None = None):
        """
        Initialize the scanner.

        Args:
            detectors: List of detectors to use. If None, uses default detectors.
        """
        self.detectors = detectors or self._get_default_detectors()

    def _get_default_detectors(self) -> list[BaseDetector]:
        """Get the default set of detectors (all 8 Phase 3 detectors)."""
        return [
            SecretsDetector(),
            CodeInjectionDetector(),
            PromptInjectionDetector(),
            ToolPoisoningDetector(),
            SupplyChainDetector(),
            XSSDetector(),
            ConfigSecurityDetector(),
            PathTraversalDetector(),
        ]

    async def scan_directory(
        self,
        target_path: str | Path,
        file_patterns: list[str] | None = None,
    ) -> ScanResult:
        """
        Scan a directory for vulnerabilities.

        Args:
            target_path: Path to directory to scan
            file_patterns: Optional glob patterns to filter files

        Returns:
            ScanResult with all findings
        """
        target_path = Path(target_path)

        if not target_path.exists():
            raise ScanError(f"Target path does not exist: {target_path}")

        if not target_path.is_dir():
            raise ScanError(f"Target path is not a directory: {target_path}")

        # Initialize scan result
        scan_result = ScanResult(
            target=str(target_path),
            status="running",
        )

        start_time = datetime.utcnow()

        try:
            # Get all files to scan
            files_to_scan = self._discover_files(target_path, file_patterns)
            scan_result.statistics.total_files = len(files_to_scan)

            # Scan each file
            for file_path in files_to_scan:
                try:
                    vulnerabilities = await self.scan_file(file_path)
                    for vuln in vulnerabilities:
                        scan_result.add_vulnerability(vuln)

                    scan_result.statistics.scanned_files += 1

                except Exception as e:
                    # Log error but continue scanning
                    print(f"Error scanning {file_path}: {e}")
                    continue

            # Mark as completed
            scan_result.status = "completed"
            scan_result.completed_at = datetime.utcnow()
            scan_result.statistics.scan_duration_seconds = (
                scan_result.completed_at - start_time
            ).total_seconds()

        except Exception as e:
            scan_result.status = "failed"
            scan_result.error = str(e)
            scan_result.completed_at = datetime.utcnow()
            raise ScanError(f"Scan failed: {e}") from e

        return scan_result

    async def scan_file(self, file_path: Path) -> list[Vulnerability]:
        """
        Scan a single file for vulnerabilities.

        Args:
            file_path: Path to file to scan

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities: list[Vulnerability] = []

        try:
            # Read file content
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Determine file type
            file_type = self._determine_file_type(file_path)

            # Run all applicable detectors
            for detector in self.detectors:
                if not detector.enabled:
                    continue

                if not detector.is_applicable(file_path, file_type):
                    continue

                try:
                    detected = await detector.detect(file_path, content, file_type)
                    vulnerabilities.extend(detected)
                except Exception as e:
                    print(f"Error in detector {detector.name}: {e}")
                    continue

        except Exception as e:
            print(f"Error reading file {file_path}: {e}")

        return vulnerabilities

    def _discover_files(
        self, target_path: Path, file_patterns: list[str] | None = None
    ) -> list[Path]:
        """
        Discover all files to scan in the target directory.

        Args:
            target_path: Root directory to scan
            file_patterns: Optional glob patterns to filter files

        Returns:
            List of file paths to scan
        """
        files: list[Path] = []

        # Default patterns if none provided
        if not file_patterns:
            file_patterns = [
                "**/*.py",
                "**/*.js",
                "**/*.ts",
                "**/*.tsx",
                "**/*.jsx",
                "**/*.go",
                "**/*.java",
                "**/*.yaml",
                "**/*.yml",
                "**/*.json",
                "**/*.toml",
                "**/*.ini",
                "**/*.cfg",
                "**/*.conf",
                "**/*.sh",
                "**/*.bash",
            ]

        # Directories to ignore
        ignore_dirs = {
            ".git",
            ".venv",
            "venv",
            "node_modules",
            "__pycache__",
            ".pytest_cache",
            "dist",
            "build",
            ".tox",
            ".mypy_cache",
        }

        # Find all matching files
        for pattern in file_patterns:
            for file_path in target_path.glob(pattern):
                # Skip if in ignored directory
                if any(ignore_dir in file_path.parts for ignore_dir in ignore_dirs):
                    continue

                if file_path.is_file():
                    files.append(file_path)

        return list(set(files))  # Remove duplicates

    def _determine_file_type(self, file_path: Path) -> str | None:
        """
        Determine the programming language/file type.

        Args:
            file_path: Path to file

        Returns:
            File type string or None
        """
        extension_map = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".go": "go",
            ".java": "java",
            ".yaml": "yaml",
            ".yml": "yaml",
            ".json": "json",
            ".toml": "toml",
            ".sh": "shell",
            ".bash": "shell",
        }

        return extension_map.get(file_path.suffix.lower())
