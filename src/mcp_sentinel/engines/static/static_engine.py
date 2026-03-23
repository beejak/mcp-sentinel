"""
Static Analysis Engine for MCP Sentinel.

Pattern-based detectors (v0.2):
- SecretsDetector
- CodeInjectionDetector
- PromptInjectionDetector
- ToolPoisoningDetector  (enhanced: full-schema poisoning, sensitive path targeting)
- ConfigSecurityDetector
- PathTraversalDetector
- SSRFDetector           (new: unvalidated URL args, cloud metadata, redirect params)
- NetworkBindingDetector (new: 0.0.0.0 binding across Python/JS/Go/Java/config)
- MissingAuthDetector    (new: routes/endpoints without auth decorators or middleware)
"""

import asyncio
import concurrent.futures
import logging
from pathlib import Path
from typing import List, Optional

import aiofiles
from mcp_sentinel.core.cache_manager import CacheManager

logger = logging.getLogger(__name__)
from mcp_sentinel.detectors.base import BaseDetector
from mcp_sentinel.detectors.code_injection import CodeInjectionDetector
from mcp_sentinel.detectors.config_security import ConfigSecurityDetector
from mcp_sentinel.detectors.missing_auth import MissingAuthDetector
from mcp_sentinel.detectors.network_binding import NetworkBindingDetector
from mcp_sentinel.detectors.path_traversal import PathTraversalDetector
from mcp_sentinel.detectors.prompt_injection import PromptInjectionDetector
from mcp_sentinel.detectors.secrets import SecretsDetector
from mcp_sentinel.detectors.ssrf import SSRFDetector
from mcp_sentinel.detectors.tool_poisoning import ToolPoisoningDetector
from mcp_sentinel.engines.base import BaseEngine, EngineStatus, EngineType, ScanProgress
from mcp_sentinel.models.vulnerability import Vulnerability


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
            detectors: List of detectors to use. If None, uses all 9 default detectors.
            enabled: Whether engine is enabled
        """
        super().__init__(
            name="Static Analysis Engine",
            engine_type=EngineType.STATIC,
            enabled=enabled,
        )
        self.detectors = detectors or self._get_default_detectors()
        self.process_pool = concurrent.futures.ProcessPoolExecutor()
        self.cache_manager = CacheManager()

    def shutdown(self):
        """Shutdown the process pool."""
        self.process_pool.shutdown()

    def _get_default_detectors(self) -> List[BaseDetector]:
        """Get default detectors."""
        return [
            SecretsDetector(),
            CodeInjectionDetector(),
            PromptInjectionDetector(),
            ToolPoisoningDetector(),
            ConfigSecurityDetector(),
            PathTraversalDetector(),
            SSRFDetector(),
            NetworkBindingDetector(),
            MissingAuthDetector(),
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
        vulnerabilities: list[Vulnerability] = []

        # Determine file type if not provided
        if file_type is None:
            file_type = self._determine_file_type(file_path)

        # Check cache
        content_hash = self.cache_manager.calculate_hash(content)
        cached_results = self.cache_manager.get_cached_results(file_path, content_hash)
        if cached_results is not None:
            return cached_results

        # Run all applicable detectors
        loop = asyncio.get_running_loop()
        
        for detector in self.detectors:
            if not detector.enabled:
                continue

            if not detector.is_applicable(file_path, file_type):
                continue

            try:
                # Run detection in process pool to avoid blocking the event loop
                detected = await loop.run_in_executor(
                    self.process_pool,
                    detector.detect_sync,
                    file_path,
                    content,
                    file_type
                )
                vulnerabilities.extend(detected)
            except Exception as e:
                # Log error but continue with other detectors
                logger.error(f"Error in detector {detector.name}: {e}")
                continue

        # Update cache
        self.cache_manager.update_cache(file_path, content_hash, vulnerabilities)

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
        vulnerabilities: list[Vulnerability] = []

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

            # Create semaphore to limit concurrency
            sem = asyncio.Semaphore(50)  # Reasonable limit for file IO

            async def scan_single_file(file_path: Path) -> list[Vulnerability]:
                async with sem:
                    try:
                        # Read file content asynchronously
                        async with aiofiles.open(file_path, encoding="utf-8", errors="ignore") as f:
                            content = await f.read()

                        # Scan file
                        return await self.scan_file(file_path, content)
                    except Exception as e:
                        # Log error but continue scanning
                        logger.error(f"Error scanning {file_path}: {e}")
                        return []

            # Create tasks
            tasks = [scan_single_file(fp) for fp in files_to_scan]

            # Run tasks and update progress
            for coro in asyncio.as_completed(tasks):
                file_vulns = await coro
                vulnerabilities.extend(file_vulns)

                progress.scanned_files += 1
                progress.vulnerabilities_found = len(vulnerabilities)
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

    def get_supported_languages(self) -> list[str]:
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
        languages.update(
            [
                "python",
                "javascript",
                "typescript",
                "go",
                "java",
                "yaml",
                "json",
                "shell",
            ]
        )

        return sorted(languages)

    def _discover_files(
        self,
        target_path: Path,
        file_patterns: Optional[List[str]] = None,
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
