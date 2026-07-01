"""
Vulnerable: XML External Entity injection — XXE

Run: mcp-sentinel scan examples/11_xxe/vulnerable.py
Expected: HIGH XXE findings
"""
import xml.etree.ElementTree as ET
from xml.dom import minidom
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Vulnerable Server")

@mcp.tool()
def parse_invoice(xml_data: str) -> dict:
    """Parse an XML invoice — VULNERABLE to XXE file read."""
    # Attack payload:
    # <?xml version="1.0"?>
    # <!DOCTYPE invoice [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    # <invoice><amount>&xxe;</amount></invoice>
    #
    # Python's stdlib ET does NOT expand external entities by default,
    # but third-party parsers (lxml without guards) will.
    root = ET.fromstring(xml_data)  # stdlib ET — lower risk but still flagged
    return {
        "amount": root.findtext("amount"),
        "vendor": root.findtext("vendor"),
    }

@mcp.tool()
def parse_config_xml(xml_string: str) -> str:
    """Parse XML config — VULNERABLE with minidom."""
    doc = minidom.parseString(xml_string)
    return doc.toxml()

@mcp.tool()
def parse_with_lxml(xml_data: str) -> str:
    """Parse with lxml — VULNERABLE without resolve_entities=False."""
    from lxml import etree
    # VULNERABLE: default lxml parser resolves external entities
    root = etree.fromstring(xml_data.encode())
    return etree.tostring(root).decode()
