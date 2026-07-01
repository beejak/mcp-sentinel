"""
Vulnerable: Command injection and SQL injection — CODE_INJECTION

Run: mcp-sentinel scan examples/02_code_injection/vulnerable.py
Expected: CRITICAL CODE_INJECTION findings
"""
import subprocess, os
import sqlite3
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Vulnerable Server")
db = sqlite3.connect(":memory:")

@mcp.tool()
def ping_host(host: str) -> str:
    """Ping a host — VULNERABLE to shell injection."""
    # Attack: host = "8.8.8.8; rm -rf /"
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return result.stdout

@mcp.tool()
def run_query(query: str) -> list:
    """Execute a search — VULNERABLE to SQL injection."""
    # Attack: query = "' OR '1'='1"
    sql = f"SELECT * FROM users WHERE name = '{query}'"
    return db.execute(sql).fetchall()

@mcp.tool()
def evaluate_expression(expr: str) -> str:
    """Evaluate a Python expression — VULNERABLE, arbitrary code execution."""
    # Attack: expr = "__import__('os').system('cat /etc/passwd')"
    return str(eval(expr))
