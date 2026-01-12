"""
Integration tests for Scanner.
"""

import pytest
from pathlib import Path

from mcp_sentinel.core.scanner import Scanner
from mcp_sentinel.models.vulnerability import Severity


@pytest.mark.asyncio
async def test_scan_directory(temp_dir, sample_python_file):
    """Test scanning a directory."""
    scanner = Scanner()

    result = await scanner.scan_directory(temp_dir)

    assert result.status == "completed"
    assert result.statistics.scanned_files > 0
    assert result.statistics.total_vulnerabilities > 0


@pytest.mark.asyncio
async def test_scan_finds_secrets(temp_dir, sample_python_file):
    """Test that scanner finds hardcoded secrets."""
    scanner = Scanner()

    result = await scanner.scan_directory(temp_dir)

    # Should find AWS keys, database URL, etc.
    assert len(result.vulnerabilities) >= 2

    # Should have critical findings (AWS keys)
    assert result.has_critical_findings()


@pytest.mark.asyncio
async def test_scan_empty_directory(temp_dir):
    """Test scanning an empty directory."""
    scanner = Scanner()

    result = await scanner.scan_directory(temp_dir)

    assert result.status == "completed"
    assert result.statistics.total_vulnerabilities == 0
    assert not result.has_critical_findings()


@pytest.mark.asyncio
async def test_scan_file(temp_dir, sample_python_file):
    """Test scanning a single file."""
    scanner = Scanner()

    vulns = await scanner.scan_file(sample_python_file)

    assert len(vulns) > 0
    assert all(v.file_path == str(sample_python_file) for v in vulns)


@pytest.mark.asyncio
async def test_scan_statistics(temp_dir, sample_python_file):
    """Test that scan statistics are correct."""
    scanner = Scanner()

    result = await scanner.scan_directory(temp_dir)

    assert result.statistics.total_files >= 1
    assert result.statistics.scanned_files >= 1
    assert result.statistics.scan_duration_seconds > 0


@pytest.mark.asyncio
async def test_risk_score_calculation(temp_dir, sample_python_file):
    """Test risk score calculation."""
    scanner = Scanner()

    result = await scanner.scan_directory(temp_dir)

    risk_score = result.risk_score()

    # Should have a risk score > 0 since we have vulnerabilities
    assert risk_score > 0
    assert risk_score <= 100


@pytest.mark.asyncio
async def test_get_by_severity(temp_dir, sample_python_file):
    """Test filtering vulnerabilities by severity."""
    scanner = Scanner()

    result = await scanner.scan_directory(temp_dir)

    critical_vulns = result.get_by_severity(Severity.CRITICAL)

    assert len(critical_vulns) > 0
    assert all(v.severity == Severity.CRITICAL for v in critical_vulns)
