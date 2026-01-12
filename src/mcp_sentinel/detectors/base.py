"""
Base detector class for all vulnerability detectors.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from pathlib import Path

from mcp_sentinel.models.vulnerability import Vulnerability


class BaseDetector(ABC):
    """
    Base class for all vulnerability detectors.

    All detectors should inherit from this class and implement the detect method.
    """

    def __init__(self, name: str, enabled: bool = True):
        """
        Initialize the detector.

        Args:
            name: Detector name
            enabled: Whether the detector is enabled
        """
        self.name = name
        self.enabled = enabled

    @abstractmethod
    async def detect(
        self, file_path: Path, content: str, file_type: Optional[str] = None
    ) -> List[Vulnerability]:
        """
        Detect vulnerabilities in a file.

        Args:
            file_path: Path to the file
            content: File content
            file_type: File type (e.g., "python", "javascript")

        Returns:
            List of detected vulnerabilities
        """
        pass

    def is_applicable(self, file_path: Path, file_type: Optional[str] = None) -> bool:
        """
        Check if this detector is applicable to the given file.

        Args:
            file_path: Path to the file
            file_type: File type

        Returns:
            True if detector should run on this file
        """
        return True

    def __repr__(self) -> str:
        """String representation."""
        return f"{self.__class__.__name__}(name={self.name}, enabled={self.enabled})"
