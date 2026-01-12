"""
Custom exceptions for MCP Sentinel.
"""


class MCPSentinelError(Exception):
    """Base exception for MCP Sentinel."""

    pass


class ConfigurationError(MCPSentinelError):
    """Configuration error."""

    pass


class ScanError(MCPSentinelError):
    """Error during scanning."""

    pass


class DetectorError(MCPSentinelError):
    """Error in a detector."""

    pass


class EngineError(MCPSentinelError):
    """Error in an analysis engine."""

    pass


class IntegrationError(MCPSentinelError):
    """Error with an integration."""

    pass


class ReportGenerationError(MCPSentinelError):
    """Error generating a report."""

    pass


class DatabaseError(MCPSentinelError):
    """Database error."""

    pass


class AuthenticationError(MCPSentinelError):
    """Authentication error."""

    pass


class AuthorizationError(MCPSentinelError):
    """Authorization error."""

    pass
