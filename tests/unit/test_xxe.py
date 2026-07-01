"""Tests for XXEDetector."""

from pathlib import Path

import pytest

from mcp_sentinel.detectors.xxe import XXEDetector


@pytest.fixture
def detector():
    return XXEDetector()


def test_entity_system_fires(detector):
    code = '<!ENTITY xxe SYSTEM "file:///etc/passwd">'
    results = detector.detect_sync(Path("test.xml"), code)
    assert len(results) >= 1


def test_manual_resolver_fires(detector):
    code = """
const entityRegex = /<!ENTITY\\s+(\\w+)\\s+(?:SYSTEM|PUBLIC)/;
if (match) {
  const data = fs.readFileSync('/etc/passwd');
}
"""
    results = detector.detect_sync(Path("test.ts"), code)
    assert len(results) >= 1


def test_stdlib_elementtree_fires(detector):
    code = """
import xml.etree.ElementTree as ET
tree = ET.parse(data)
"""
    results = detector.detect_sync(Path("test.py"), code)
    assert len(results) >= 1


def test_defusedxml_clean(detector):
    code = """
import defusedxml.ElementTree as ET
tree = ET.parse(data)
"""
    results = detector.detect_sync(Path("test.py"), code)
    et_findings = [
        r for r in results
        if "ElementTree" in r.title or "elementtree" in r.title.lower()
    ]
    assert len(et_findings) == 0


def test_lxml_resolve_entities_false_clean(detector):
    code = """
from lxml import etree
parser = etree.XMLParser(resolve_entities=False)
tree = lxml.etree.parse(xmlfile)
"""
    results = detector.detect_sync(Path("test.py"), code)
    lxml_findings = [r for r in results if "lxml" in r.title.lower()]
    assert len(lxml_findings) == 0
