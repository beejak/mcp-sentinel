"""
Safe: SSRF prevented by hostname allowlist and private IP blocking.
"""
import ipaddress, socket
from urllib.parse import urlparse
import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Safe Server")

ALLOWED_HOSTS = {"api.example.com", "data.example.org"}

def _validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http/https allowed")
    host = parsed.hostname or ""
    if host not in ALLOWED_HOSTS:
        raise ValueError(f"Host {host!r} not in allowlist")
    # Block private / link-local ranges
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        if ip.is_private or ip.is_link_local or ip.is_loopback:
            raise ValueError("Private IP ranges are blocked")
    except socket.gaierror:
        raise ValueError("DNS resolution failed")

@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch from allowlisted URLs only."""
    _validate_url(url)
    return requests.get(url, timeout=10).text
