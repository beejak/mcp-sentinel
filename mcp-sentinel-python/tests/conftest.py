"""
Pytest configuration and fixtures.
"""

import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest


def pytest_ignore_collect(path: Path | str, config=None) -> bool | None:  # noqa: ARG002
    """Opt-in fork smoke tests (see tests/integration/test_external_fork_smoke.py)."""
    try:
        name = Path(path).name
    except Exception:
        name = str(path).replace("\\", "/").split("/")[-1]
    if name != "test_external_fork_smoke.py":
        return None
    flag = os.environ.get("MCP_SENTINEL_RUN_FORK_TESTS", "").strip().lower()
    if flag in ("1", "true", "yes"):
        return None
    return True

# Add src directory to Python path for imports
src_path = Path(__file__).parent.parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    temp_path = Path(tempfile.mkdtemp())
    yield temp_path
    shutil.rmtree(temp_path)


@pytest.fixture
def sample_python_file(temp_dir):
    """Create a sample Python file with a hardcoded secret."""
    file_path = temp_dir / "test.py"
    content = """
import os

# This is a test file with hardcoded credentials (FAKE - for testing only!)
AWS_ACCESS_KEY = "AKIA1A2B3C4D5E6F7G8H"  # Fake AWS access key for testing
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYA1B2C3D4E5F6"  # Fake AWS secret key

def get_database_url():
    return "postgres://user:password123@localhost:5432/mydb"

# OpenAI API Key
OPENAI_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
"""
    file_path.write_text(content)
    return file_path


@pytest.fixture
def sample_javascript_file(temp_dir):
    """Create a sample JavaScript file."""
    file_path = temp_dir / "test.js"
    content = """
const API_KEY = "sk-ant-api03-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuv";

function main() {
    console.log("Hello World");
}
"""
    file_path.write_text(content)
    return file_path
