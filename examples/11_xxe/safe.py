"""
SAFE: XML parsing with defusedxml — external entities disabled.
"""
import defusedxml.ElementTree as ET  # Replaces stdlib ET; blocks XXE, Billion Laughs, etc.
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("safe-xml-demo")

@mcp.tool()
def parse_document(xml_content: str) -> str:
    """Parse an XML document safely."""
    try:
        root = ET.fromstring(xml_content)  # defusedxml raises on any external entity
    except ET.ParseError as e:
        return f"Invalid XML: {e}"
    except Exception as e:
        return f"XML rejected (possible XXE attempt): {e}"
    return f"Root element: {root.tag}"

@mcp.tool()
def validate_config(config_xml: str) -> str:
    """Validate an XML config file safely."""
    import defusedxml.minidom as minidom
    try:
        doc = minidom.parseString(config_xml.encode())
    except Exception as e:
        return f"Config invalid: {e}"
    return f"Config valid, root: {doc.documentElement.tagName}"
