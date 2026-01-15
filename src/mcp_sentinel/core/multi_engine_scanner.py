"""
Multi-Engine Scanner for MCP Sentinel.

This scanner coordinates multiple analysis engines (Static, Semantic, SAST, AI)
and aggregates their results.
"""

import asyncio
from collections import defaultdict
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from mcp_sentinel.core.exceptions import ScanError
from mcp_sentinel.engines.base import BaseEngine, EngineType, ScanProgress
from mcp_sentinel.engines.sast import SASTEngine
from mcp_sentinel.engines.static import StaticAnalysisEngine
from mcp_sentinel.models.scan_result import ScanResult
from mcp_sentinel.models.vulnerability import Vulnerability


class MultiEngineScanner:
    """
    Multi-engine scanner that coordinates analysis across multiple engines.

    Supports running Static, Semantic, SAST, and AI engines concurrently
    and aggregates their findings.
    """

    def __init__(
        self,
        engines: list[BaseEngine] | None = None,
        enabled_engines: set[EngineType] | None = None,
        progress_callback: Callable[[str, ScanProgress], None] | None = None,
    ):
        """
        Initialize the multi-engine scanner.

        Args:
            engines: List of engines to use. If None, uses Static engine only.
            enabled_engines: Set of engine types to enable. If None, enables all provided engines.
            progress_callback: Optional callback for progress updates (engine_name, progress)
        """
        self.engines = engines or self._get_default_engines()
        self.enabled_engines = enabled_engines or {engine.engine_type for engine in self.engines}
        self.progress_callback = progress_callback

        # Filter engines based on enabled_engines
        self.active_engines = [
            engine
            for engine in self.engines
            if engine.engine_type in self.enabled_engines and engine.enabled
        ]

        # Set up progress callbacks
        for engine in self.active_engines:
            engine.set_progress_callback(self._create_progress_callback(engine))

    def _get_default_engines(self) -> list[BaseEngine]:
        """
        Get default engines.

        Available engines:
        - StaticAnalysisEngine - Pattern-based detection (8 detectors)
        - SASTEngine - Semgrep + Bandit integration (Phase 4.1)

        Coming in future phases:
        - SemanticAnalysisEngine (Phase 4.2)
        - AIAnalysisEngine (Phase 4.3)
        """
        return [
            StaticAnalysisEngine(enabled=True),
            SASTEngine(enabled=True),
        ]

    def _create_progress_callback(self, engine: BaseEngine) -> Callable[[ScanProgress], None]:
        """Create a progress callback for a specific engine."""

        def callback(progress: ScanProgress):
            if self.progress_callback:
                self.progress_callback(engine.name, progress)

        return callback

    async def scan_directory(
        self,
        target_path: str | Path,
        file_patterns: list[str] | None = None,
    ) -> ScanResult:
        """
        Scan a directory using all enabled engines.

        Engines run concurrently for maximum performance.

        Args:
            target_path: Path to directory to scan
            file_patterns: Optional glob patterns to filter files

        Returns:
            ScanResult with aggregated findings from all engines
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
            # Run all engines concurrently
            engine_tasks = [
                engine.scan_directory(target_path, file_patterns) for engine in self.active_engines
            ]

            # Gather results from all engines
            engine_results = await asyncio.gather(*engine_tasks, return_exceptions=True)

            # Process results from each engine
            all_vulnerabilities: list[Vulnerability] = []

            for idx, result in enumerate(engine_results):
                engine = self.active_engines[idx]

                if isinstance(result, Exception):
                    # Log engine failure but continue
                    print(f"Engine {engine.name} failed: {result}")
                    continue

                # Add vulnerabilities from this engine
                all_vulnerabilities.extend(result)

            # Deduplicate vulnerabilities
            deduplicated = self._deduplicate_vulnerabilities(all_vulnerabilities)

            # Add to scan result
            for vuln in deduplicated:
                scan_result.add_vulnerability(vuln)

            # Count files scanned (use max from any engine)
            # This is approximate since different engines may scan different files
            scan_result.statistics.total_files = self._count_files(target_path, file_patterns)
            scan_result.statistics.scanned_files = scan_result.statistics.total_files

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
            raise ScanError(f"Multi-engine scan failed: {e}") from e

        return scan_result

    async def scan_file(
        self,
        file_path: Path,
        content: str | None = None,
        file_type: str | None = None,
    ) -> list[Vulnerability]:
        """
        Scan a single file using all enabled engines.

        Args:
            file_path: Path to file to scan
            content: File content (will be read if not provided)
            file_type: File type (will be detected if not provided)

        Returns:
            Deduplicated list of vulnerabilities from all engines
        """
        # Read content if not provided
        if content is None:
            try:
                with open(file_path, encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                print(f"Error reading {file_path}: {e}")
                return []

        # Determine file type if not provided
        if file_type is None:
            file_type = self._determine_file_type(file_path)

        # Run all engines concurrently on this file
        engine_tasks = [
            engine.scan_file(file_path, content, file_type)
            for engine in self.active_engines
            if engine.is_applicable(file_path, file_type)
        ]

        # Gather results
        engine_results = await asyncio.gather(*engine_tasks, return_exceptions=True)

        # Aggregate vulnerabilities
        all_vulnerabilities: list[Vulnerability] = []
        for result in engine_results:
            if isinstance(result, Exception):
                continue
            all_vulnerabilities.extend(result)

        # Deduplicate and return
        return self._deduplicate_vulnerabilities(all_vulnerabilities)

    def _deduplicate_vulnerabilities(
        self,
        vulnerabilities: list[Vulnerability],
    ) -> list[Vulnerability]:
        """
        Deduplicate vulnerabilities from multiple engines.

        Two vulnerabilities are considered duplicates if they have:
        - Same file path
        - Same line number
        - Same vulnerability type
        - Same title (or very similar)

        When duplicates are found, we keep the one with highest confidence
        and merge the engine information.

        Args:
            vulnerabilities: List of vulnerabilities from all engines

        Returns:
            Deduplicated list of vulnerabilities
        """
        # Group by dedup key
        groups: dict = defaultdict(list)

        for vuln in vulnerabilities:
            # Create deduplication key
            key = (
                vuln.file_path,
                vuln.line_number,
                vuln.type.value,
                vuln.title,
            )
            groups[key].append(vuln)

        # For each group, keep the best vulnerability
        deduplicated: list[Vulnerability] = []

        for _key, group in groups.items():
            if len(group) == 1:
                deduplicated.append(group[0])
            else:
                # Multiple engines found same issue
                # Keep the one with highest confidence
                best = max(
                    group, key=lambda v: v.confidence.value if hasattr(v.confidence, "value") else 0
                )

                # Merge engine information
                engines = {vuln.engine for vuln in group}
                best.engine = ", ".join(sorted(engines))

                deduplicated.append(best)

        return deduplicated

    def _count_files(
        self,
        target_path: Path,
        file_patterns: list[str] | None = None,
    ) -> int:
        """Count files that would be scanned."""
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
                "**/*.sh",
                "**/*.bash",
            ]

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

        files = set()
        for pattern in file_patterns:
            for file_path in target_path.glob(pattern):
                if any(ignore_dir in file_path.parts for ignore_dir in ignore_dirs):
                    continue
                if file_path.is_file():
                    files.add(file_path)

        return len(files)

    def _determine_file_type(self, file_path: Path) -> str | None:
        """Determine the programming language/file type."""
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

    def get_active_engines(self) -> list[str]:
        """Get names of all active engines."""
        return [engine.name for engine in self.active_engines]

    def get_engine_types(self) -> list[EngineType]:
        """Get types of all active engines."""
        return [engine.engine_type for engine in self.active_engines]
