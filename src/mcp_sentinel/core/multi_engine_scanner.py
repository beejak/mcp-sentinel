"""
Multi-Engine Scanner for MCP Sentinel.

Coordinates the static analysis engine and aggregates results.
"""

import asyncio
import hashlib
import logging
from collections import defaultdict
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

import aiofiles  # type: ignore[import-untyped]

from mcp_sentinel.core.cache_manager import CacheManager
from mcp_sentinel.core.exceptions import ScanError
from mcp_sentinel.engines.base import BaseEngine, EngineType, ScanProgress
from mcp_sentinel.engines.static import StaticAnalysisEngine
from mcp_sentinel.models.scan_result import ScanResult
from mcp_sentinel.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


class MultiEngineScanner:
    """
    Scanner that coordinates analysis engines and aggregates findings.
    """

    def __init__(
        self,
        engines: Optional[list[BaseEngine]] = None,
        enabled_engines: Optional[set[EngineType]] = None,
        progress_callback: Optional[Callable[[str, ScanProgress], None]] = None,
    ):
        self.engines = engines or [StaticAnalysisEngine(enabled=True)]
        self.enabled_engines = enabled_engines or {engine.engine_type for engine in self.engines}
        self.progress_callback = progress_callback

        # Filter engines based on enabled_engines
        self.active_engines = [
            engine
            for engine in self.engines
            if engine.engine_type in self.enabled_engines and engine.enabled
        ]

        for engine in self.active_engines:
            engine.set_progress_callback(self._create_progress_callback(engine))

        self.cache_manager = CacheManager()

    def _create_progress_callback(self, engine: BaseEngine) -> Callable[[ScanProgress], None]:
        def callback(progress: ScanProgress) -> None:
            if self.progress_callback:
                self.progress_callback(engine.name, progress)
        return callback

    async def scan(
        self,
        target_path: Union[str, Path],
        file_patterns: Optional[list[str]] = None,
    ) -> ScanResult:
        """
        Scan a directory or file using all enabled engines.

        Args:
            target_path: Path to directory or file to scan
            file_patterns: Optional glob patterns to filter files (directory scan only)

        Returns:
            ScanResult with aggregated findings
        """
        target_path = Path(target_path)

        if not target_path.exists():
            raise ScanError(f"Target path does not exist: {target_path}")

        scan_result = ScanResult(target=str(target_path), status="running")
        start_time = datetime.utcnow()

        try:
            if target_path.is_file():
                async with aiofiles.open(target_path, encoding="utf-8", errors="ignore") as f:
                    content = await f.read()

                content_hash = hashlib.md5(content.encode("utf-8")).hexdigest()
                cached_vulns = self.cache_manager.get_cached_results(target_path, content_hash)

                if cached_vulns is not None:
                    scan_result.vulnerabilities = cached_vulns
                    scan_result.status = "completed"
                    scan_result.completed_at = datetime.utcnow()
                    scan_result.statistics.scan_duration_seconds = (
                        scan_result.completed_at - start_time
                    ).total_seconds()
                    scan_result.statistics.total_files = 1
                    scan_result.statistics.scanned_files = 0
                    return scan_result

                engine_tasks = [
                    engine.scan_file(target_path, content) for engine in self.active_engines
                ]
                total_files = 1
            else:
                engine_tasks = [
                    engine.scan_directory(target_path, file_patterns) for engine in self.active_engines
                ]
                total_files = self._count_files(target_path, file_patterns)

            engine_results = await asyncio.gather(*engine_tasks, return_exceptions=True)

            all_vulnerabilities: list[Vulnerability] = []
            for idx, result in enumerate(engine_results):
                engine = self.active_engines[idx]
                if not isinstance(result, list):
                    logger.error(f"Engine {engine.name} failed: {result}")
                    continue
                all_vulnerabilities.extend(result)

            deduplicated = self._deduplicate_vulnerabilities(all_vulnerabilities)

            if target_path.is_file():
                self.cache_manager.update_cache(target_path, content_hash, deduplicated)

            for vuln in deduplicated:
                scan_result.add_vulnerability(vuln)

            scan_result.statistics.total_files = total_files
            scan_result.statistics.scanned_files = total_files
            scan_result.status = "completed"
            scan_result.completed_at = datetime.utcnow()
            scan_result.statistics.scan_duration_seconds = (
                scan_result.completed_at - start_time
            ).total_seconds()

        except Exception as e:
            scan_result.status = "failed"
            scan_result.error = str(e)
            scan_result.completed_at = datetime.utcnow()
            scan_result.statistics.scan_duration_seconds = (
                scan_result.completed_at - start_time
            ).total_seconds()

        return scan_result

    async def scan_file(
        self,
        file_path: Path,
        content: Optional[str] = None,
        file_type: Optional[str] = None,
    ) -> list[Vulnerability]:
        """Scan a single file using all enabled engines."""
        if content is None:
            try:
                with open(file_path, encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                logger.error(f"Error reading {file_path}: {e}")
                return []

        if file_type is None:
            file_type = self._determine_file_type(file_path)

        engine_tasks = [
            engine.scan_file(file_path, content, file_type)
            for engine in self.active_engines
            if engine.is_applicable(file_path, file_type)
        ]

        engine_results = await asyncio.gather(*engine_tasks, return_exceptions=True)

        all_vulnerabilities: list[Vulnerability] = []
        for result in engine_results:
            if not isinstance(result, list):
                continue
            all_vulnerabilities.extend(result)

        return self._deduplicate_vulnerabilities(all_vulnerabilities)

    def _deduplicate_vulnerabilities(
        self,
        vulnerabilities: list[Vulnerability],
    ) -> list[Vulnerability]:
        """Deduplicate vulnerabilities by (file, line, type, title)."""
        groups: dict[tuple[str, int, str, str], list[Vulnerability]] = defaultdict(list)

        for vuln in vulnerabilities:
            key = (vuln.file_path, vuln.line_number, vuln.type.value, vuln.title)
            groups[key].append(vuln)

        deduplicated: list[Vulnerability] = []
        for _key, group in groups.items():
            if len(group) == 1:
                deduplicated.append(group[0])
            else:
                best = max(
                    group, key=lambda v: v.confidence.value if hasattr(v.confidence, "value") else 0
                )
                engines = {vuln.engine for vuln in group}
                best.engine = ", ".join(sorted(engines))
                deduplicated.append(best)

        return deduplicated

    def _count_files(
        self,
        target_path: Path,
        file_patterns: Optional[list[str]] = None,
    ) -> int:
        """Count files that would be scanned."""
        if not file_patterns:
            file_patterns = [
                "**/*.py", "**/*.js", "**/*.ts", "**/*.tsx", "**/*.jsx",
                "**/*.go", "**/*.java", "**/*.yaml", "**/*.yml",
                "**/*.json", "**/*.toml", "**/*.sh", "**/*.bash",
            ]

        ignore_dirs = {
            ".git", ".venv", "venv", "node_modules", "__pycache__",
            ".pytest_cache", "dist", "build", ".tox", ".mypy_cache",
        }

        files = set()
        for pattern in file_patterns:
            for file_path in target_path.glob(pattern):
                if any(ignore_dir in file_path.parts for ignore_dir in ignore_dirs):
                    continue
                if file_path.is_file():
                    files.add(file_path)

        return len(files)

    def _determine_file_type(self, file_path: Path) -> Optional[str]:
        """Determine the programming language/file type."""
        extension_map = {
            ".py": "python", ".js": "javascript", ".jsx": "javascript",
            ".ts": "typescript", ".tsx": "typescript", ".go": "go",
            ".java": "java", ".yaml": "yaml", ".yml": "yaml",
            ".json": "json", ".toml": "toml", ".sh": "shell", ".bash": "shell",
        }
        return extension_map.get(file_path.suffix.lower())

    def get_active_engines(self) -> list[str]:
        """Get names of all active engines."""
        return [engine.name for engine in self.active_engines]

    def get_engine_types(self) -> list[EngineType]:
        """Get types of all active engines."""
        return [engine.engine_type for engine in self.active_engines]
