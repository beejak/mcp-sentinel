"""
Integration tests for report generators.

Tests the end-to-end flow of generating SARIF and HTML reports.
"""

import pytest
import json
from pathlib import Path
import tempfile
import shutil

from mcp_sentinel.core.multi_engine_scanner import MultiEngineScanner
from mcp_sentinel.engines.base import EngineType
from mcp_sentinel.reporting.generators import SARIFGenerator, HTMLGenerator


@pytest.fixture
def temp_project():
    """Create a temporary project directory with test files."""
    temp_dir = Path(tempfile.mkdtemp())

    # Create a Python file with vulnerabilities
    py_file = temp_dir / "app.py"
    py_file.write_text(
        """
import os
import subprocess

# Hardcoded AWS key
AWS_KEY = "AKIA1A2B3C4D5E6F7G8H"

def run_command(user_input):
    # Command injection vulnerability
    subprocess.call(f"cat {user_input}", shell=True)
    os.system(user_input)
"""
    )

    # Create a JavaScript file with XSS vulnerability
    js_file = temp_dir / "app.js"
    js_file.write_text(
        """
const apiKey = "sk-ant-api03-1234567890abcdefghijklmnopqrstuvwxyz";

function displayUser(name) {
    document.getElementById("user").innerHTML = name;  // XSS vulnerability
}
"""
    )

    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.mark.asyncio
async def test_sarif_generator_end_to_end(temp_project):
    """Test SARIF report generation end-to-end."""
    # Run scan
    scanner = MultiEngineScanner(enabled_engines={EngineType.STATIC})
    result = await scanner.scan_directory(temp_project)

    # Verify we found vulnerabilities
    assert result.status == "completed"
    assert len(result.vulnerabilities) >= 3  # AWS key, command injection, XSS

    # Generate SARIF report
    generator = SARIFGenerator()
    sarif_doc = generator.generate(result)

    # Verify SARIF structure
    assert sarif_doc["version"] == "2.1.0"
    assert "$schema" in sarif_doc
    assert "runs" in sarif_doc
    assert len(sarif_doc["runs"]) == 1

    run = sarif_doc["runs"][0]

    # Verify tool information
    assert "tool" in run
    assert run["tool"]["driver"]["name"] == "MCP Sentinel"

    # Verify results
    assert "results" in run
    assert len(run["results"]) >= 3

    # Verify result structure
    for sarif_result in run["results"]:
        assert "ruleId" in sarif_result
        assert "message" in sarif_result
        assert "locations" in sarif_result
        assert len(sarif_result["locations"]) > 0

        location = sarif_result["locations"][0]
        assert "physicalLocation" in location
        assert "artifactLocation" in location["physicalLocation"]
        assert "region" in location["physicalLocation"]

    # Verify rules are defined
    assert "rules" in run["tool"]["driver"]
    assert len(run["tool"]["driver"]["rules"]) > 0

    # Verify we can serialize to JSON
    sarif_json = generator.generate_json(result)
    parsed = json.loads(sarif_json)
    assert parsed["version"] == "2.1.0"


@pytest.mark.asyncio
async def test_sarif_generator_save_to_file(temp_project):
    """Test saving SARIF report to file."""
    # Run scan
    scanner = MultiEngineScanner(enabled_engines={EngineType.STATIC})
    result = await scanner.scan_directory(temp_project)

    # Save to file
    temp_file = Path(tempfile.mktemp(suffix=".sarif"))
    try:
        generator = SARIFGenerator()
        generator.save_to_file(result, temp_file)

        # Verify file exists and is valid JSON
        assert temp_file.exists()
        with open(temp_file) as f:
            sarif_doc = json.load(f)

        assert sarif_doc["version"] == "2.1.0"
        assert len(sarif_doc["runs"]) == 1
        assert len(sarif_doc["runs"][0]["results"]) >= 3

    finally:
        if temp_file.exists():
            temp_file.unlink()


@pytest.mark.asyncio
async def test_html_generator_end_to_end(temp_project):
    """Test HTML report generation end-to-end."""
    # Run scan
    scanner = MultiEngineScanner(enabled_engines={EngineType.STATIC})
    result = await scanner.scan_directory(temp_project)

    # Verify we found vulnerabilities
    assert result.status == "completed"
    assert len(result.vulnerabilities) >= 3

    # Generate HTML report
    generator = HTMLGenerator()
    html_content = generator.generate(result)

    # Verify HTML structure
    assert "<!DOCTYPE html>" in html_content
    assert "<html" in html_content
    assert "</html>" in html_content

    # Verify key sections are present
    assert "MCP Sentinel Security Report" in html_content
    assert "Executive Summary" in html_content
    assert "Risk Score" in html_content
    assert "Vulnerabilities by Severity" in html_content
    assert "Detailed Findings" in html_content

    # Verify statistics are included
    assert "Files Scanned" in html_content
    assert "Total Vulnerabilities" in html_content
    assert "Scan Duration" in html_content

    # Verify CSS is embedded
    assert "<style>" in html_content
    assert "</style>" in html_content

    # Verify JavaScript is embedded
    assert "<script>" in html_content
    assert "</script>" in html_content

    # Verify vulnerability details are included
    for vuln in result.vulnerabilities[:3]:  # Check first 3 vulnerabilities
        assert vuln.title in html_content


@pytest.mark.asyncio
async def test_html_generator_save_to_file(temp_project):
    """Test saving HTML report to file."""
    # Run scan
    scanner = MultiEngineScanner(enabled_engines={EngineType.STATIC})
    result = await scanner.scan_directory(temp_project)

    # Save to file
    temp_file = Path(tempfile.mktemp(suffix=".html"))
    try:
        generator = HTMLGenerator()
        generator.save_to_file(result, temp_file)

        # Verify file exists and contains HTML
        assert temp_file.exists()
        html_content = temp_file.read_text(encoding="utf-8")

        assert "<!DOCTYPE html>" in html_content
        assert "MCP Sentinel Security Report" in html_content
        assert len(html_content) > 1000  # Should be a substantial file

    finally:
        if temp_file.exists():
            temp_file.unlink()


@pytest.mark.asyncio
async def test_html_generator_self_contained(temp_project):
    """Test that HTML reports are self-contained with no external dependencies."""
    # Run scan
    scanner = MultiEngineScanner(enabled_engines={EngineType.STATIC})
    result = await scanner.scan_directory(temp_project)

    # Generate HTML
    generator = HTMLGenerator()
    html_content = generator.generate(result)

    # Verify no external CSS links
    assert "<link" not in html_content or "stylesheet" not in html_content

    # Verify no external script sources
    assert "<script src=" not in html_content

    # Verify CSS is inline
    assert "<style>" in html_content
    assert "body {" in html_content
    assert "background" in html_content

    # Verify JavaScript is inline
    assert "function" in html_content or "const" in html_content


@pytest.mark.asyncio
async def test_report_generators_with_no_vulnerabilities():
    """Test report generators with scan that finds no vulnerabilities."""
    # Create empty temp directory
    temp_dir = Path(tempfile.mkdtemp())
    try:
        # Run scan on empty directory
        scanner = MultiEngineScanner(enabled_engines={EngineType.STATIC})
        result = await scanner.scan_directory(temp_dir)

        assert result.status == "completed"
        assert len(result.vulnerabilities) == 0

        # Test SARIF generation
        sarif_gen = SARIFGenerator()
        sarif_doc = sarif_gen.generate(result)
        assert sarif_doc["version"] == "2.1.0"
        assert len(sarif_doc["runs"][0]["results"]) == 0

        # Test HTML generation
        html_gen = HTMLGenerator()
        html_content = html_gen.generate(result)
        assert "<!DOCTYPE html>" in html_content
        assert "No vulnerabilities found" in html_content or "0" in html_content

    finally:
        shutil.rmtree(temp_dir)


@pytest.mark.asyncio
async def test_report_generators_with_severity_filtering(temp_project):
    """Test that report generators handle severity-filtered results."""
    # Run scan
    scanner = MultiEngineScanner(enabled_engines={EngineType.STATIC})
    result = await scanner.scan_directory(temp_project)

    original_count = len(result.vulnerabilities)
    assert original_count >= 3

    # Filter to only critical vulnerabilities
    result.vulnerabilities = [v for v in result.vulnerabilities if v.severity.value == "critical"]
    result.statistics.total_vulnerabilities = len(result.vulnerabilities)

    # Generate reports with filtered results
    sarif_gen = SARIFGenerator()
    sarif_doc = sarif_gen.generate(result)

    html_gen = HTMLGenerator()
    html_content = html_gen.generate(result)

    # Verify both generators handle filtered results
    assert "version" in sarif_doc
    assert "<!DOCTYPE html>" in html_content

    # The filtered count should be reflected
    assert len(sarif_doc["runs"][0]["results"]) == len(result.vulnerabilities)


@pytest.mark.asyncio
async def test_sarif_github_code_scanning_compatibility(temp_project):
    """Test that SARIF output is compatible with GitHub Code Scanning."""
    # Run scan
    scanner = MultiEngineScanner(enabled_engines={EngineType.STATIC})
    result = await scanner.scan_directory(temp_project)

    # Generate SARIF
    generator = SARIFGenerator()
    sarif_doc = generator.generate(result)

    # Verify GitHub Code Scanning requirements
    run = sarif_doc["runs"][0]

    # Must have tool information
    assert "tool" in run
    assert "driver" in run["tool"]
    assert "name" in run["tool"]["driver"]
    assert "version" in run["tool"]["driver"]
    assert "informationUri" in run["tool"]["driver"]

    # Results must have proper structure
    for result_item in run["results"]:
        # Must have rule ID
        assert "ruleId" in result_item

        # Must have message
        assert "message" in result_item
        assert "text" in result_item["message"]

        # Must have location
        assert "locations" in result_item
        assert len(result_item["locations"]) > 0

        location = result_item["locations"][0]
        assert "physicalLocation" in location

        # URI must be relative
        uri = location["physicalLocation"]["artifactLocation"]["uri"]
        assert not uri.startswith("/")  # Must be relative for GitHub
        assert not uri.startswith("C:")  # No absolute Windows paths

        # Must have region with line number
        assert "region" in location["physicalLocation"]
        assert "startLine" in location["physicalLocation"]["region"]


@pytest.mark.asyncio
async def test_html_report_executive_dashboard(temp_project):
    """Test that HTML reports include executive dashboard elements."""
    # Run scan
    scanner = MultiEngineScanner(enabled_engines={EngineType.STATIC})
    result = await scanner.scan_directory(temp_project)

    # Generate HTML
    generator = HTMLGenerator()
    html_content = generator.generate(result)

    # Verify dashboard elements
    assert "Executive Summary" in html_content
    assert "metric-card" in html_content  # Dashboard card class

    # Verify key metrics
    assert "Files Scanned" in html_content
    assert "Total Vulnerabilities" in html_content
    assert "Risk Score" in html_content
    assert "Scan Duration" in html_content

    # Verify severity breakdown
    assert "Vulnerabilities by Severity" in html_content
    assert "severity-bar" in html_content or "chart" in html_content.lower()

    # Verify detailed findings section
    assert "Detailed Findings" in html_content
    assert "finding-card" in html_content or "vulnerability" in html_content.lower()
