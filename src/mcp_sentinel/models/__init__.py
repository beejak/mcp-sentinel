"""
Data models for MCP Sentinel.
"""

from mcp_sentinel.models.vulnerability import (
    Vulnerability,
    Severity,
    Confidence,
    VulnerabilityType,
)
from mcp_sentinel.models.scan_result import ScanResult, ScanStatistics

__all__ = [
    "Vulnerability",
    "Severity",
    "Confidence",
    "VulnerabilityType",
    "ScanResult",
    "ScanStatistics",
]
