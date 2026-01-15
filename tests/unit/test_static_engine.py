"""
Unit tests for Static Analysis Engine.
"""

import pytest
from pathlib import Path
import tempfile
import shutil

from mcp_sentinel.engines.static.static_engine import StaticAnalysisEngine
from mcp_sentinel.engines.base import EngineType, EngineStatus


@pytest.fixture
def temp_project():
    """Create a temporary project directory with test files."""
    temp_dir = Path(tempfile.mkdtemp())

    # Create a Python file with vulnerabilities
    py_file = temp_dir / "app.py"
    py_file.write_text(
        """
import os

# Hardcoded credentials
AWS_ACCESS_KEY = "AKIA1A2B3C4D5E6F7G8H"
db_password = "super_secret_password"

def run_command(user_input):
    # Command injection vulnerability
    os.system(f"cat {user_input}")
"""
    )

    # Create a JS file
    js_file = temp_dir / "script.js"
    js_file.write_text(
        """
const apiKey = "sk-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJ";

function displayUser(name) {
    // XSS vulnerability
    document.getElementById("user").innerHTML = name;
}
"""
    )

    yield temp_dir

    # Cleanup
    shutil.rmtree(temp_dir)


@pytest.mark.asyncio
async def test_static_engine_initialization():
    """Test engine initializes correctly."""
    engine = StaticAnalysisEngine()

    assert engine.name == "Static Analysis Engine"
    assert engine.engine_type == EngineType.STATIC
    assert engine.enabled is True
    assert engine.status == EngineStatus.IDLE
    assert len(engine.detectors) == 8


@pytest.mark.asyncio
async def test_static_engine_scan_file(temp_project):
    """Test scanning a single file."""
    engine = StaticAnalysisEngine()

    py_file = temp_project / "app.py"
    content = py_file.read_text()

    vulns = await engine.scan_file(py_file, content, "python")

    # Should find at least the hardcoded AWS key and command injection
    assert len(vulns) >= 2
    assert all(v.engine == "static" for v in vulns)


@pytest.mark.asyncio
async def test_static_engine_scan_directory(temp_project):
    """Test scanning a directory."""
    engine = StaticAnalysisEngine()

    vulns = await engine.scan_directory(temp_project)

    # Should find vulnerabilities in both Python and JS files
    assert len(vulns) >= 3
    assert engine.status == EngineStatus.COMPLETED

    # Check files are from our test project
    file_paths = {v.file_path for v in vulns}
    assert any("app.py" in fp for fp in file_paths)


@pytest.mark.asyncio
async def test_static_engine_progress_callback(temp_project):
    """Test progress callback is called."""
    engine = StaticAnalysisEngine()

    progress_updates = []

    def progress_callback(progress):
        progress_updates.append(progress)

    engine.set_progress_callback(progress_callback)

    await engine.scan_directory(temp_project)

    # Should have received progress updates
    assert len(progress_updates) > 0

    # Check progress data
    for progress in progress_updates:
        assert progress.engine_type == EngineType.STATIC
        assert progress.total_files >= 0
        assert progress.scanned_files >= 0
        assert progress.vulnerabilities_found >= 0


@pytest.mark.asyncio
async def test_static_engine_is_applicable():
    """Test file applicability checking."""
    engine = StaticAnalysisEngine()

    # Python file should be applicable
    assert engine.is_applicable(Path("test.py"), "python")

    # JavaScript file should be applicable
    assert engine.is_applicable(Path("test.js"), "javascript")

    # Unknown file types might not be applicable to all detectors
    # but should still return a boolean
    result = engine.is_applicable(Path("test.xyz"), "unknown")
    assert isinstance(result, bool)


@pytest.mark.asyncio
async def test_static_engine_supported_languages():
    """Test getting supported languages."""
    engine = StaticAnalysisEngine()

    languages = engine.get_supported_languages()

    assert isinstance(languages, list)
    assert "python" in languages
    assert "javascript" in languages
    assert "go" in languages
    assert len(languages) >= 5
