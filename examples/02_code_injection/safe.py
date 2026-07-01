"""
Safe: Parameterized queries, execFile with argument list, no eval.
"""
import subprocess
import sqlite3
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Safe Server")
db = sqlite3.connect(":memory:")

@mcp.tool()
def ping_host(host: str) -> str:
    """Ping a host — safe, no shell interpolation."""
    # SAFE: list form — no shell expansion, host is a literal argument
    allowed = {"8.8.8.8", "1.1.1.1", "8.8.4.4"}
    if host not in allowed:
        return "Host not in allowlist"
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
    return result.stdout

@mcp.tool()
def run_query(query: str) -> list:
    """Search users — parameterized query prevents SQL injection."""
    # SAFE: ? placeholder — DB driver handles escaping
    sql = "SELECT * FROM users WHERE name = ?"
    return db.execute(sql, (query,)).fetchall()
