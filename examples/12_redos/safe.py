"""
Safe: Input length limit + linear-time regex alternatives.
"""
import re
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Safe Server")

MAX_INPUT_LEN = 1000

@mcp.tool()
def validate_input(user_input: str) -> bool:
    """Validate input — length-limited, no nested quantifiers."""
    if len(user_input) > MAX_INPUT_LEN:
        return False
    # SAFE: anchored, possessive-style rewrite — no nested quantifiers
    pattern = re.compile(r"^[a-z]+$")
    return bool(pattern.match(user_input))

@mcp.tool()
def validate_email(email: str) -> bool:
    """Validate email — linear-time pattern."""
    if len(email) > 254:  # RFC 5321 max
        return False
    # SAFE: no nested quantifiers
    return bool(re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", email))
