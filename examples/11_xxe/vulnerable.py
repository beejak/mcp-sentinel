"""
VULNERABLE: XML External Entity (XXE) injection.
Parsing XML from user input without disabling external entity resolution.
"""
import xml.etree.ElementTree as ET  # stdlib: external entities enabled by default (pre-3.8 expat)
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("xxe-demo")

@mcp.tool()
def parse_document(xml_content: str) -> str:
    """Parse an XML document and return its root element's tag."""
    # VULNERABLE: ET.fromstring processes <!ENTITY SYSTEM "file:///etc/passwd">
    # In environments with vulnerable expat, this exfiltrates local files.
    root = ET.fromstring(xml_content)           # CWE-611
    return f"Root element: {root.tag}, text: {root.text}"

@mcp.tool()
def validate_config(config_xml: str) -> str:
    """Validate an XML config file."""
    import xml.dom.minidom as minidom
    # VULNERABLE: minidom also resolves external entities
    doc = minidom.parseString(config_xml.encode())
    return f"Config valid, root: {doc.documentElement.tagName}"
