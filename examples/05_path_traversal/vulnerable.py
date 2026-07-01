"""
Vulnerable: Path traversal — directory escape, zip slip — PATH_TRAVERSAL

Run: mcp-sentinel scan examples/05_path_traversal/vulnerable.py
Expected: HIGH PATH_TRAVERSAL findings
"""
import os, zipfile
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Vulnerable Server")
WORKSPACE = "/app/workspace"

@mcp.tool()
def read_file(filename: str) -> str:
    """Read a file from the workspace — VULNERABLE to path traversal."""
    # Attack: filename = "../../../../etc/passwd"
    # Attack: filename = "../../../../root/.ssh/id_rsa"
    path = os.path.join(WORKSPACE, filename)
    with open(path) as f:
        return f.read()

@mcp.tool()
def extract_archive(zip_path: str) -> str:
    """Extract a zip archive — VULNERABLE to Zip Slip."""
    # Attack: archive contains member "../../etc/cron.d/backdoor"
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(WORKSPACE)  # members can escape WORKSPACE via ../
    return "extracted"

@mcp.tool()
def save_upload(filename: str, content: str) -> str:
    """Save uploaded content — VULNERABLE to path traversal write."""
    # Attack: filename = "../../../etc/crontab"
    dest = os.path.join(WORKSPACE, filename)
    with open(dest, "w") as f:
        f.write(content)
    return f"saved to {dest}"
