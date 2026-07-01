"""
Safe: XXE prevented by defusedxml and lxml hardened parser.
"""
import defusedxml.ElementTree as ET
import defusedxml.minidom as minidom
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Safe Server")

@mcp.tool()
def parse_invoice(xml_data: str) -> dict:
    """Parse XML invoice — defusedxml blocks XXE, DTD, entity expansion."""
    # SAFE: defusedxml raises DefusedXmlException on any external entity
    root = ET.fromstring(xml_data)
    return {
        "amount": root.findtext("amount"),
        "vendor": root.findtext("vendor"),
    }

@mcp.tool()
def parse_with_lxml(xml_data: str) -> str:
    """Parse with lxml — hardened parser, no external entities."""
    from lxml import etree
    # SAFE: resolve_entities=False, no_network=True
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    root = etree.fromstring(xml_data.encode(), parser=parser)
    return etree.tostring(root).decode()
