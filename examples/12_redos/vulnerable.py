"""
Vulnerable: ReDoS — catastrophic regex backtracking — REDOS

Run: mcp-sentinel scan examples/12_redos/vulnerable.py
Expected: HIGH REDOS findings
"""
import re
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Vulnerable Server")

@mcp.tool()
def validate_input(user_input: str) -> bool:
    """Validate user input format — VULNERABLE to ReDoS."""
    # Attack: user_input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"
    # This causes exponential backtracking — locks the thread for seconds/minutes
    pattern = re.compile(r"(a+)+$")
    return bool(pattern.match(user_input))

@mcp.tool()
def validate_email(email: str) -> bool:
    """Validate email format — VULNERABLE to ReDoS."""
    # Nested quantifier: (\w+\s*)+ causes catastrophic backtracking
    return bool(re.match(r"^(\w+\s*)+@[\w.]+$", email))

@mcp.tool()
def check_log_format(log_line: str) -> bool:
    """Validate log line format — VULNERABLE to ReDoS."""
    # ([\w\-]+)+ with no end-anchor causes exponential blowup
    pattern = r"^([\w\-]+)+ (ERROR|WARN|INFO)"
    return bool(re.match(pattern, log_line))
