"""
Unit tests for Multi-Engine Scanner.
"""

import pytest
from pathlib import Path
import tempfile
import shutil

from mcp_sentinel.core.multi_engine_scanner import MultiEngineScanner
from mcp_sentinel.engines.base import EngineType
from mcp_sentinel.engines.static import StaticAnalysisEngine


@pytest.fixture
def temp_project():
    """Create a temporary project directory with test files."""
    temp_dir = Path(tempfile.mkdtemp())

    # Create a Python file with multiple vulnerabilities
    py_file = temp_dir / "app.py"
    py_file.write_text('''
import os
import subprocess

# Hardcoded credentials
AWS_ACCESS_KEY = "AKIA1A2B3C4D5E6F7G8H"
API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"

def run_command(user_input):
    # Command injection
    subprocess.call(f"cat {user_input}", shell=True)
    os.system(user_input)
''')

    # Create a JavaScript file
    js_file = temp_dir / "app.js"
    js_file.write_text('''
const apiKey = "sk-ant-api03-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuv";

function displayName(name) {
    document.getElementById("user").innerHTML = name;
}
''')

    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.mark.asyncio
async def test_multi_engine_scanner_initialization():
    """Test multi-engine scanner initializes correctly."""
    scanner = MultiEngineScanner()

    assert len(scanner.engines) >= 1
    assert len(scanner.active_engines) >= 1
    assert EngineType.STATIC in scanner.get_engine_types()


@pytest.mark.asyncio
async def test_multi_engine_scanner_with_specific_engines():
    """Test scanner with specific engine selection."""
    # Create scanner with only static engine
    static_engine = StaticAnalysisEngine()
    scanner = MultiEngineScanner(
        engines=[static_engine],
        enabled_engines={EngineType.STATIC},
    )

    assert len(scanner.active_engines) == 1
    assert scanner.active_engines[0].engine_type == EngineType.STATIC


@pytest.mark.asyncio
async def test_multi_engine_scan_directory(temp_project):
    """Test scanning a directory with multiple engines."""
    scanner = MultiEngineScanner()

    result = await scanner.scan_directory(temp_project)

    # Should find vulnerabilities
    assert result.status == "completed"
    assert len(result.vulnerabilities) >= 3

    # Check statistics
    assert result.statistics.total_files >= 2
    assert result.statistics.scanned_files >= 2
    assert result.statistics.scan_duration_seconds > 0


@pytest.mark.asyncio
async def test_multi_engine_scan_file(temp_project):
    """Test scanning a single file with multiple engines."""
    scanner = MultiEngineScanner()

    py_file = temp_project / "app.py"
    vulns = await scanner.scan_file(py_file)

    # Should find at least AWS key and command injection
    assert len(vulns) >= 2
    assert all(hasattr(v, 'engine') for v in vulns)


@pytest.mark.asyncio
async def test_multi_engine_progress_callback(temp_project):
    """Test progress callback is called during scanning."""
    progress_updates = []

    def progress_callback(engine_name, progress):
        progress_updates.append((engine_name, progress))

    scanner = MultiEngineScanner(progress_callback=progress_callback)
    await scanner.scan_directory(temp_project)

    # Should have received progress updates
    assert len(progress_updates) > 0

    # Check progress data
    for engine_name, progress in progress_updates:
        assert isinstance(engine_name, str)
        assert progress.engine_type == EngineType.STATIC
        assert progress.total_files >= 0
        assert progress.scanned_files >= 0


@pytest.mark.asyncio
async def test_multi_engine_deduplication(temp_project):
    """Test that duplicate findings from multiple engines are deduplicated."""
    # Create two identical static engines
    engine1 = StaticAnalysisEngine()
    engine2 = StaticAnalysisEngine()

    scanner = MultiEngineScanner(engines=[engine1, engine2])

    result = await scanner.scan_directory(temp_project)

    # Even though we have 2 identical engines, vulnerabilities should be deduplicated
    # Each vulnerability should appear only once
    vuln_keys = set()
    for vuln in result.vulnerabilities:
        key = (vuln.file_path, vuln.line_number, vuln.type.value, vuln.title)
        assert key not in vuln_keys, f"Duplicate vulnerability found: {vuln.title} at {vuln.file_path}:{vuln.line_number}"
        vuln_keys.add(key)


@pytest.mark.asyncio
async def test_multi_engine_get_active_engines():
    """Test getting active engine names."""
    scanner = MultiEngineScanner()

    engine_names = scanner.get_active_engines()

    assert isinstance(engine_names, list)
    assert len(engine_names) >= 1
    assert "Static Analysis Engine" in engine_names


@pytest.mark.asyncio
async def test_multi_engine_get_engine_types():
    """Test getting active engine types."""
    scanner = MultiEngineScanner()

    engine_types = scanner.get_engine_types()

    assert isinstance(engine_types, list)
    assert len(engine_types) >= 1
    assert EngineType.STATIC in engine_types


@pytest.mark.asyncio
async def test_multi_engine_empty_directory():
    """Test scanning an empty directory."""
    temp_dir = Path(tempfile.mkdtemp())

    try:
        scanner = MultiEngineScanner()
        result = await scanner.scan_directory(temp_dir)

        assert result.status == "completed"
        assert len(result.vulnerabilities) == 0
        assert result.statistics.total_files == 0

    finally:
        shutil.rmtree(temp_dir)


@pytest.mark.asyncio
async def test_multi_engine_nonexistent_directory():
    """Test scanning a non-existent directory raises error."""
    scanner = MultiEngineScanner()

    with pytest.raises(Exception):  # Should raise ScanError
        await scanner.scan_directory(Path("/nonexistent/directory"))


@pytest.mark.asyncio
async def test_multi_engine_file_with_content():
    """Test scanning file with provided content."""
    scanner = MultiEngineScanner()

    content = '''
AWS_KEY = "AKIA1A2B3C4D5E6F7G8H"
'''

    vulns = await scanner.scan_file(
        Path("test.py"),
        content=content,
        file_type="python"
    )

    # Should find AWS key
    assert len(vulns) >= 1
    assert any("AWS" in v.title or "Access Key" in v.title for v in vulns)