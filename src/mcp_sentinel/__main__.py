"""
Main entry point for running MCP Sentinel as a module.

Allows: python -m mcp_sentinel
"""

from mcp_sentinel.cli.main import cli

if __name__ == "__main__":
    cli()
