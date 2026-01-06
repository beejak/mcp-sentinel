"""
Pytest configuration and fixtures.
"""

import pytest
from pathlib import Path
import tempfile
import shutil


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
    content = '''
import os

# This is a test file with a hardcoded AWS key
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def get_database_url():
    return "postgres://user:password123@localhost:5432/mydb"

# OpenAI API Key
OPENAI_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
'''
    file_path.write_text(content)
    return file_path


@pytest.fixture
def sample_javascript_file(temp_dir):
    """Create a sample JavaScript file."""
    file_path = temp_dir / "test.js"
    content = '''
const API_KEY = "sk-ant-api03-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuv";

function main() {
    console.log("Hello World");
}
'''
    file_path.write_text(content)
    return file_path
