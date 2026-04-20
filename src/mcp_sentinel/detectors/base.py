"""
Base detector class for all vulnerability detectors.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from mcp_sentinel.models.owasp_mapping import annotate
from mcp_sentinel.models.vulnerability import Vulnerability


class BaseDetector(ABC):
    """
    Base class for all vulnerability detectors.

    All detectors should inherit from this class and implement the detect method.
    """

    def __init__(self, name: str, enabled: bool = True) -> None:
        """
        Initialize the detector.

        Args:
            name: Detector name
            enabled: Whether the detector is enabled
        """
        self.name = name
        self.enabled = enabled

    @abstractmethod
    def detect_sync(
        self, file_path: Path, content: str, file_type: Optional[str] = None
    ) -> list[Vulnerability]:
        """
        Synchronous detection method.

        Args:
            file_path: Path to the file
            content: File content
            file_type: File type (e.g., "python", "javascript")

        Returns:
            List of detected vulnerabilities
        """
        pass

    async def detect(
        self, file_path: Path, content: str, file_type: Optional[str] = None
    ) -> list[Vulnerability]:
        """
        Detect vulnerabilities in a file (Async wrapper).

        Annotates every returned finding with its OWASP Agentic AI Top 10
        category (owasp_asi_id / owasp_asi_name) before returning.

        Args:
            file_path: Path to the file
            content: File content
            file_type: File type (e.g., "python", "javascript")

        Returns:
            List of detected vulnerabilities
        """
        vulns = self.detect_sync(file_path, content, file_type)
        for vuln in vulns:
            if vuln.owasp_asi_id is None:
                asi_id, asi_name = annotate(vuln.type)
                vuln.owasp_asi_id = asi_id
                vuln.owasp_asi_name = asi_name
        return vulns

    @staticmethod
    def _is_test_file(file_path: Path) -> bool:
        """Return True if the file lives in a test/fixture directory or is a test module."""
        parts = {p.lower() for p in file_path.parts}
        name = file_path.name.lower()
        return (
            bool(parts & {"tests", "test", "fixtures", "spec", "specs", "__tests__"})
            or name.startswith("test_")
            or name.endswith(("_test.py", ".spec.js", ".spec.ts"))
        )

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
