"""
MCP Sentinel - Security Scanner for Model Context Protocol Servers

Static analysis tool for detecting vulnerabilities in MCP server code.
"""

__version__ = "4.1.0"
__author__ = "MCP Sentinel Team"
__license__ = "MIT"

from mcp_sentinel.core.scanner import Scanner
from mcp_sentinel.models.scan_result import ScanResult
from mcp_sentinel.models.vulnerability import Severity, Vulnerability

__all__ = [
    "Scanner",
    "Vulnerability",
    "Severity",
    "ScanResult",
    "__version__",
]
