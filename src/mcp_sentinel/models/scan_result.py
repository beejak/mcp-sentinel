"""
Scan result model for aggregating vulnerability findings.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field

from mcp_sentinel.models.vulnerability import Vulnerability, Severity


class ScanStatistics(BaseModel):
    """Statistics about the scan."""

    total_files: int = 0
    scanned_files: int = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    scan_duration_seconds: float = 0.0
    engines_used: List[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    """
    Result of a security scan.

    Attributes:
        scan_id: Unique scan identifier
        target: Path or URL that was scanned
        vulnerabilities: List of found vulnerabilities
        statistics: Scan statistics
        config: Configuration used for scan
        started_at: Scan start time
        completed_at: Scan completion time
        status: Scan status
        error: Error message if scan failed
    """

    scan_id: str = Field(default_factory=lambda: f"scan-{datetime.utcnow().timestamp()}")
    target: str
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    statistics: ScanStatistics = Field(default_factory=ScanStatistics)
    config: Dict[str, Any] = Field(default_factory=dict)

    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    status: str = "pending"  # pending, running, completed, failed
    error: Optional[str] = None

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        """Add a vulnerability to the result."""
        self.vulnerabilities.append(vuln)
        self.statistics.total_vulnerabilities += 1

        # Update severity counts
        if vuln.severity == Severity.CRITICAL:
            self.statistics.critical_count += 1
        elif vuln.severity == Severity.HIGH:
            self.statistics.high_count += 1
        elif vuln.severity == Severity.MEDIUM:
            self.statistics.medium_count += 1
        elif vuln.severity == Severity.LOW:
            self.statistics.low_count += 1
        else:
            self.statistics.info_count += 1

    def get_by_severity(self, severity: Severity) -> List[Vulnerability]:
        """Get all vulnerabilities of a specific severity."""
        return [v for v in self.vulnerabilities if v.severity == severity]

    def get_by_file(self, file_path: str) -> List[Vulnerability]:
        """Get all vulnerabilities in a specific file."""
        return [v for v in self.vulnerabilities if v.file_path == file_path]

    def has_critical_findings(self) -> bool:
        """Check if scan has critical vulnerabilities."""
        return self.statistics.critical_count > 0

    def has_high_or_critical(self) -> bool:
        """Check if scan has high or critical vulnerabilities."""
        return (self.statistics.critical_count + self.statistics.high_count) > 0

    def risk_score(self) -> float:
        """
        Calculate overall risk score (0-100).

        Weighted average based on severity distribution.
        """
        if self.statistics.total_vulnerabilities == 0:
            return 0.0

        total_score = sum(v.risk_score() for v in self.vulnerabilities)
        return total_score / self.statistics.total_vulnerabilities

    def summary(self) -> str:
        """Generate a text summary of the scan results."""
        return (
            f"Scan {self.scan_id}\n"
            f"Target: {self.target}\n"
            f"Status: {self.status}\n"
            f"Duration: {self.statistics.scan_duration_seconds:.2f}s\n"
            f"Files Scanned: {self.statistics.scanned_files}/{self.statistics.total_files}\n"
            f"Total Vulnerabilities: {self.statistics.total_vulnerabilities}\n"
            f"  Critical: {self.statistics.critical_count}\n"
            f"  High: {self.statistics.high_count}\n"
            f"  Medium: {self.statistics.medium_count}\n"
            f"  Low: {self.statistics.low_count}\n"
            f"  Info: {self.statistics.info_count}\n"
            f"Risk Score: {self.risk_score():.1f}/100"
        )

    class Config:
        json_schema_extra = {
            "example": {
                "scan_id": "scan-1234567890",
                "target": "/path/to/project",
                "vulnerabilities": [],
                "statistics": {
                    "total_files": 100,
                    "scanned_files": 95,
                    "total_vulnerabilities": 15,
                    "critical_count": 2,
                    "high_count": 5,
                    "medium_count": 6,
                    "low_count": 2,
                    "info_count": 0,
                    "scan_duration_seconds": 7.8,
                    "engines_used": ["static", "semantic", "ai"]
                },
                "status": "completed"
            }
        }
