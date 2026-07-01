"""
Safe: Path traversal prevented by resolving and bounding the final path.
"""
import os, zipfile
from pathlib import Path
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Safe Server")
WORKSPACE = Path("/app/workspace").resolve()

def _safe_path(filename: str) -> Path:
    """Resolve path and verify it stays within WORKSPACE."""
    resolved = (WORKSPACE / filename).resolve()
    if not str(resolved).startswith(str(WORKSPACE)):
        raise ValueError(f"Path traversal detected: {filename!r}")
    return resolved

@mcp.tool()
def read_file(filename: str) -> str:
    """Read a file — path bounded to WORKSPACE."""
    path = _safe_path(filename)
    return path.read_text()

@mcp.tool()
def extract_archive(zip_path: str) -> str:
    """Extract a zip — Zip Slip prevented by member validation."""
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            dest = (WORKSPACE / member).resolve()
            if not str(dest).startswith(str(WORKSPACE)):
                raise ValueError(f"Zip Slip attempt: {member!r}")
        zf.extractall(WORKSPACE)
    return "extracted safely"
