"""
MCP Sentinel - Enterprise Security Scanner for Model Context Protocol Servers

A comprehensive security platform combining static analysis, semantic analysis,
SAST, and AI-powered detection to identify vulnerabilities in MCP implementations.
"""

__version__ = "3.0.0"
__author__ = "MCP Sentinel Team"
__license__ = "MIT"

from mcp_sentinel.core.scanner import Scanner
from mcp_sentinel.models.vulnerability import Vulnerability, Severity
from mcp_sentinel.models.scan_result import ScanResult

__all__ = [
    "Scanner",
    "Vulnerability",
    "Severity",
    "ScanResult",
    "__version__",
]
