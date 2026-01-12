"""
Static Analysis Engine for MCP Sentinel.

This engine wraps the 8 pattern-based detectors from Phase 3:
- SecretsDetector
- CodeInjectionDetector
- PromptInjectionDetector
- ToolPoisoningDetector
- SupplyChainDetector
- XSSDetector
- ConfigSecurityDetector
- PathTraversalDetector
"""

from typing import List, Optional
from pathlib import Path

from mcp_sentinel.engines.base import BaseEngine, EngineType, EngineStatus, ScanProgress
from mcp_sentinel.models.vulnerability import Vulnerability
from mcp_sentinel.detectors.base import BaseDetector
from mcp_sentinel.detectors.secrets import SecretsDetector
from mcp_sentinel.detectors.code_injection import CodeInjectionDetector
from mcp_sentinel.detectors.prompt_injection import PromptInjectionDetector
from mcp_sentinel.detectors.tool_poisoning import ToolPoisoningDetector
from mcp_sentinel.detectors.supply_chain import SupplyChainDetector
from mcp_sentinel.detectors.xss import XSSDetector
from mcp_sentinel.detectors.config_security import ConfigSecurityDetector
from mcp_sentinel.detectors.path_traversal import PathTraversalDetector


class StaticAnalysisEngine(BaseEngine):
    """
    Static Analysis Engine using pattern-based detectors.

    This is the primary engine from Phase 3, providing fast pattern matching
    for common security vulnerabilities across multiple languages.
    """

    def __init__(
        self,
        detectors: Optional[List[BaseDetector]] = None,
        enabled: bool = True,
    ):
        """
        Initialize the static analysis engine.

        Args:
            detectors: List of detectors to use. If None, uses all 8 default detectors.
            enabled: Whether engine is enabled
        """
        super().__init__(
            name="Static Analysis Engine",
            engine_type=EngineType.STATIC,
            enabled=enabled,
        )
        self.detectors = detectors or self._get_default_detectors()

    def _get_default_detectors(self) -> List[BaseDetector]:
        """Get all 8 Phase 3 detectors."""
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

    async def scan_file(
        self,
        file_path: Path,
        content: str,
        file_type: Optional[str] = None,
    ) -> List[Vulnerability]:
        """
        Scan a single file using all applicable detectors.

        Args:
            file_path: Path to the file
            content: File content
            file_type: File type (e.g., 'python', 'javascript')

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []

        # Determine file type if not provided
        if file_type is None:
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
                # Log error but continue with other detectors
                print(f"Error in detector {detector.name}: {e}")
                continue

        return vulnerabilities

    async def scan_directory(
        self,
        target_path: Path,
        file_patterns: Optional[List[str]] = None,
    ) -> List[Vulnerability]:
        """
        Scan a directory using all detectors.

        Args:
            target_path: Directory to scan
            file_patterns: Optional glob patterns to filter files

        Returns:
            List of all detected vulnerabilities
        """
        self.status = EngineStatus.RUNNING
        vulnerabilities: List[Vulnerability] = []

        try:
            # Discover files to scan
            files_to_scan = self._discover_files(target_path, file_patterns)
            total_files = len(files_to_scan)

            # Create progress tracker
            progress = ScanProgress(
                engine_type=self.engine_type,
                total_files=total_files,
                scanned_files=0,
                vulnerabilities_found=0,
            )

            # Scan each file
            for idx, file_path in enumerate(files_to_scan):
                progress.current_file = file_path
                progress.scanned_files = idx
                self._report_progress(progress)

                try:
                    # Read file content
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    # Scan file
                    file_vulns = await self.scan_file(file_path, content)
                    vulnerabilities.extend(file_vulns)
                    progress.vulnerabilities_found = len(vulnerabilities)

                except Exception as e:
                    # Log error but continue scanning
                    print(f"Error scanning {file_path}: {e}")
                    continue

            # Final progress update
            progress.scanned_files = total_files
            progress.current_file = None
            self._report_progress(progress)

            self.status = EngineStatus.COMPLETED
            return vulnerabilities

        except Exception as e:
            self.status = EngineStatus.FAILED
            raise RuntimeError(f"Static analysis failed: {e}") from e

    def is_applicable(
        self,
        file_path: Path,
        file_type: Optional[str] = None,
    ) -> bool:
        """
        Check if any detector can analyze this file.

        Args:
            file_path: Path to the file
            file_type: File type

        Returns:
            True if at least one detector can analyze this file
        """
        if file_type is None:
            file_type = self._determine_file_type(file_path)

        return any(
            detector.enabled and detector.is_applicable(file_path, file_type)
            for detector in self.detectors
        )

    def get_supported_languages(self) -> List[str]:
        """
        Get list of all languages supported by detectors.

        Returns:
            List of unique language identifiers
        """
        languages = set()
        for detector in self.detectors:
            if hasattr(detector, "supported_languages"):
                languages.update(detector.supported_languages)

        # Add common languages we know are supported
        languages.update([
            "python",
            "javascript",
            "typescript",
            "go",
            "java",
            "yaml",
            "json",
            "shell",
        ])

        return sorted(languages)

    def _discover_files(
        self,
        target_path: Path,
        file_patterns: Optional[List[str]] = None,
    ) -> List[Path]:
        """
        Discover all files to scan in the target directory.

        Args:
            target_path: Root directory to scan
            file_patterns: Optional glob patterns to filter files

        Returns:
            List of file paths to scan
        """
        files: List[Path] = []

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

    def _determine_file_type(self, file_path: Path) -> Optional[str]:
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