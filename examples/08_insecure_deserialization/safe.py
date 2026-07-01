"""
Safe: JSON only, yaml.safe_load, no pickle from untrusted input.
"""
import json, yaml
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Safe Server")

@mcp.tool()
def restore_session(session_json: str) -> dict:
    """Restore session from JSON — safe, no code execution possible."""
    # SAFE: JSON only supports strings, numbers, arrays, objects — no code
    data = json.loads(session_json)
    # Validate expected shape
    if not isinstance(data, dict) or "user_id" not in data:
        raise ValueError("Invalid session format")
    return {"user_id": str(data["user_id"]), "role": str(data.get("role", "user"))}

@mcp.tool()
def load_config(config_yaml: str) -> dict:
    """Load YAML — SafeLoader prevents arbitrary object instantiation."""
    # SAFE: yaml.safe_load only handles standard YAML types (str, int, list, dict)
    config = yaml.safe_load(config_yaml)
    return config
