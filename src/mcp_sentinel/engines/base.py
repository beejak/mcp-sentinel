"""
Base engine interface for MCP Sentinel analysis engines.

All analysis engines (Static, Semantic, SAST, AI) implement this interface.
"""

from abc import ABC, abstractmethod
from collections.abc import Callable
from enum import Enum
from pathlib import Path

from mcp_sentinel.models.vulnerability import Vulnerability


class EngineType(Enum):
    """Types of analysis engines."""

    STATIC = "static"
    SEMANTIC = "semantic"
    SAST = "sast"
    AI = "ai"


class EngineStatus(Enum):
    """Engine execution status."""

    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanProgress:
    """Progress information for engine scans."""

    def __init__(
        self,
        engine_type: EngineType,
        total_files: int,
        scanned_files: int = 0,
        current_file: Path | None = None,
        vulnerabilities_found: int = 0,
    ):
        self.engine_type = engine_type
        self.total_files = total_files
        self.scanned_files = scanned_files
        self.current_file = current_file
        self.vulnerabilities_found = vulnerabilities_found

    @property
    def progress_percentage(self) -> float:
        """Calculate progress percentage."""
        if self.total_files == 0:
            return 100.0
        return (self.scanned_files / self.total_files) * 100.0

    def __str__(self) -> str:
        return (
            f"{self.engine_type.value}: "
            f"{self.scanned_files}/{self.total_files} files "
            f"({self.progress_percentage:.1f}%) - "
            f"{self.vulnerabilities_found} vulnerabilities"
        )


class BaseEngine(ABC):
    """
    Base class for all analysis engines.

    Each engine (Static, Semantic, SAST, AI) implements this interface
    to provide vulnerability detection capabilities.
    """

    def __init__(
        self,
        name: str,
        engine_type: EngineType,
        enabled: bool = True,
    ):
        """
        Initialize the engine.

        Args:
            name: Human-readable engine name
            engine_type: Type of engine
            enabled: Whether engine is enabled
        """
        self.name = name
        self.engine_type = engine_type
        self.enabled = enabled
        self.status = EngineStatus.IDLE
        self._progress_callback: Callable[[ScanProgress], None] | None = None

    def set_progress_callback(self, callback: Callable[[ScanProgress], None]) -> None:
        """
        Set callback for progress updates.

        Args:
            callback: Function to call with progress updates
        """
        self._progress_callback = callback

    def _report_progress(self, progress: ScanProgress) -> None:
        """Report progress if callback is set."""
        if self._progress_callback:
            self._progress_callback(progress)

    @abstractmethod
    async def scan_file(
        self,
        file_path: Path,
        content: str,
        file_type: str | None = None,
    ) -> list[Vulnerability]:
        """
        Scan a single file for vulnerabilities.

        Args:
            file_path: Path to the file
            content: File content
            file_type: File type (e.g., 'python', 'javascript')

        Returns:
            List of detected vulnerabilities
        """
        pass

    @abstractmethod
    async def scan_directory(
        self,
        target_path: Path,
        file_patterns: list[str] | None = None,
    ) -> list[Vulnerability]:
        """
        Scan a directory for vulnerabilities.

        Args:
            target_path: Directory to scan
            file_patterns: Optional glob patterns to filter files

        Returns:
            List of all detected vulnerabilities
        """
        pass

    @abstractmethod
    def is_applicable(
        self,
        file_path: Path,
        file_type: str | None = None,
    ) -> bool:
        """
        Check if this engine can analyze the given file.

        Args:
            file_path: Path to the file
            file_type: File type

        Returns:
            True if engine can analyze this file
        """
        pass

    @abstractmethod
    def get_supported_languages(self) -> list[str]:
        """
        Get list of supported programming languages.

        Returns:
            List of language identifiers (e.g., ['python', 'javascript'])
        """
        pass

    def __str__(self) -> str:
        return f"{self.name} ({self.engine_type.value})"

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"name='{self.name}' "
            f"type={self.engine_type.value} "
            f"enabled={self.enabled}>"
        )
