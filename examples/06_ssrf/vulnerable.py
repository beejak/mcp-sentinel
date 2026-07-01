"""
Vulnerable: SSRF via unvalidated URL — SSRF

Run: mcp-sentinel scan examples/06_ssrf/vulnerable.py
Expected: HIGH SSRF findings
"""
import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Vulnerable Server")

@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch content from a URL — VULNERABLE to SSRF."""
    # Attack: url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    # Attack: url = "http://internal-api.prod.local/admin/dump"
    response = requests.get(url, timeout=10)
    return response.text

@mcp.tool()
def webhook_notify(callback_url: str, payload: dict) -> str:
    """Send a webhook notification — VULNERABLE, callback_url unvalidated."""
    # Attack: callback_url exfiltrates data to attacker-controlled server
    import httpx
    httpx.post(callback_url, json=payload)
    return "notified"
