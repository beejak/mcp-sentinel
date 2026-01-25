"""
Tests for DiffBuilder.
"""

from mcp_sentinel.remediation.models import CodeChange
from mcp_sentinel.remediation.diff_builder import DiffBuilder


def test_generate_diff_simple():
    """Test generating a simple one-line diff."""
    original = 'print("hello")'
    new = 'print("hello world")'
    
    cc = CodeChange(
        file_path="test.py",
        original_code=original,
        new_code=new,
        start_line=1,
        end_line=1
    )
    
    diff = DiffBuilder.generate_diff(cc)
    
    assert "--- a/test.py" in diff
    assert "+++ b/test.py" in diff
    assert '-print("hello")' in diff
    assert '+print("hello world")' in diff


def test_generate_diff_multiline():
    """Test generating a multiline diff."""
    original = """def foo():
    return 1"""
    new = """def foo():
    return 2"""
    
    cc = CodeChange(
        file_path="test.py",
        original_code=original,
        new_code=new,
        start_line=1,
        end_line=2
    )
    
    diff = DiffBuilder.generate_diff(cc)
    
    assert "--- a/test.py" in diff
    assert "+++ b/test.py" in diff
    assert "-    return 1" in diff
    assert "+    return 2" in diff


def test_generate_diff_identical():
    """Test generating diff for identical code."""
    original = 'print("hello")'
    
    cc = CodeChange(
        file_path="test.py",
        original_code=original,
        new_code=original,
        start_line=1,
        end_line=1
    )
    
    diff = DiffBuilder.generate_diff(cc)
    assert diff == ""
