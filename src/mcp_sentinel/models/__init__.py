"""
Data models for MCP Sentinel.
"""

from mcp_sentinel.models.scan_result import ScanResult, ScanStatistics
from mcp_sentinel.models.vulnerability import (
    Confidence,
    Severity,
    Vulnerability,
    VulnerabilityType,
)

__all__ = [
    "Vulnerability",
    "Severity",
    "Confidence",
    "VulnerabilityType",
    "ScanResult",
    "ScanStatistics",
]
