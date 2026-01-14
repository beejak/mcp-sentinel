"""
Unit tests for PathTraversalDetector.

Tests all 5 path traversal pattern categories.
"""

import pytest
from pathlib import Path

from mcp_sentinel.detectors.path_traversal import PathTraversalDetector
from mcp_sentinel.models.vulnerability import (
    Vulnerability,
    VulnerabilityType,
    Severity,
    Confidence,
)


@pytest.fixture
def detector():
    """Create a PathTraversalDetector instance for testing."""
    return PathTraversalDetector()


# ============================================================================
# Pattern 1: Path Manipulation Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_open_with_request_param(detector):
    """Test detection of open() with request parameter."""
    content = """
def read_file(request):
    filename = request.args.get('file')
    with open(filename) as f:
        return f.read()
"""
    vulns = await detector.detect(Path("views.py"), content, "python")

    assert len(vulns) >= 1
    path_vulns = [v for v in vulns if "Path Manipulation" in v.title]
    assert len(path_vulns) >= 1
    assert path_vulns[0].type == VulnerabilityType.PATH_TRAVERSAL
    assert path_vulns[0].severity == Severity.CRITICAL
    assert path_vulns[0].cwe_id == "CWE-22"
    assert path_vulns[0].cvss_score == 9.1
    assert "T1083" in path_vulns[0].mitre_attack_ids


@pytest.mark.asyncio
async def test_detect_readfile_with_params(detector):
    """Test detection of readFile() with params."""
    content = """
app.get('/file', (req, res) => {
    const content = fs.readFile(req.query.filename);
    res.send(content);
});
"""
    vulns = await detector.detect(Path("server.js"), content, "javascript")

    assert len(vulns) >= 1


@pytest.mark.asyncio
async def test_detect_writefile_with_user_input(detector):
    """Test detection of writeFile() with user input."""
    content = """
function saveFile(userInput) {
    fs.writeFile(userInput.path, data);
}
"""
    vulns = await detector.detect(Path("utils.js"), content, "javascript")

    assert len(vulns) >= 1


# ============================================================================
# Pattern 2: Unsafe File Operations Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_open_with_concatenation(detector):
    """Test detection of open() with string concatenation."""
    content = """
def read_log(filename):
    with open('/var/log/' + filename) as f:
        return f.read()
"""
    vulns = await detector.detect(Path("logs.py"), content, "python")

    assert len(vulns) >= 1
    unsafe_vulns = [v for v in vulns if "Unsafe File Operation" in v.title]
    assert len(unsafe_vulns) >= 1
    assert unsafe_vulns[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_detect_php_file_get_contents(detector):
    """Test detection of PHP file_get_contents with $_GET."""
    content = """
<?php
$content = file_get_contents($_GET['file']);
echo $content;
?>
"""
    vulns = await detector.detect(Path("index.php"), content, "php")

    assert len(vulns) >= 1


@pytest.mark.asyncio
async def test_detect_php_fopen(detector):
    """Test detection of PHP fopen with $_POST."""
    content = """
<?php
$handle = fopen($_POST['filename'], 'r');
?>
"""
    vulns = await detector.detect(Path("upload.php"), content, "php")

    assert len(vulns) >= 1


# ============================================================================
# Pattern 3: Traversal Sequences Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_dot_dot_slash(detector):
    """Test detection of '../' sequence."""
    content = """
path = "../../../etc/passwd"
"""
    vulns = await detector.detect(Path("exploit.py"), content, "python")

    assert len(vulns) >= 1
    trav_vulns = [v for v in vulns if "Traversal Sequence" in v.title]
    assert len(trav_vulns) >= 1
    assert trav_vulns[0].severity == Severity.HIGH
    assert trav_vulns[0].cwe_id == "CWE-23"


@pytest.mark.asyncio
async def test_detect_dot_dot_backslash(detector):
    """Test detection of '..\' sequence."""
    content = """
file_path = "..\\..\\windows\\system32\\config\\sam"
"""
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) >= 1


@pytest.mark.asyncio
async def test_detect_url_encoded_traversal(detector):
    """Test detection of URL-encoded traversal."""
    content = """
path = "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
"""
    vulns = await detector.detect(Path("bypass.py"), content, "python")

    assert len(vulns) >= 1


# ============================================================================
# Pattern 4: Zip Slip Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_zipfile_extract(detector):
    """Test detection of unsafe zipfile.extract()."""
    content = """
import zipfile

def extract_archive(zip_path):
    with zipfile.ZipFile(zip_path) as zf:
        zf.extract('file.txt')
"""
    vulns = await detector.detect(Path("archive.py"), content, "python")

    assert len(vulns) >= 1
    zip_vulns = [v for v in vulns if "Zip Slip" in v.title]
    assert len(zip_vulns) >= 1
    assert zip_vulns[0].severity == Severity.CRITICAL
    assert zip_vulns[0].cvss_score == 9.8


@pytest.mark.asyncio
async def test_detect_zipfile_extractall(detector):
    """Test detection of unsafe zipfile.extractall()."""
    content = """
import zipfile

with zipfile.ZipFile('archive.zip') as zf:
    zf.extractall('/tmp/extracted')
"""
    vulns = await detector.detect(Path("unzip.py"), content, "python")

    assert len(vulns) >= 1


@pytest.mark.asyncio
async def test_detect_tarfile_extract(detector):
    """Test detection of unsafe tarfile.extract()."""
    content = """
import tarfile

tar = tarfile.open('archive.tar.gz')
tar.extractall()
"""
    vulns = await detector.detect(Path("untar.py"), content, "python")

    assert len(vulns) >= 1


# ============================================================================
# Pattern 5: Unsafe Path Join Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_os_path_join_with_request(detector):
    """Test detection of os.path.join with request data."""
    content = """
def get_file_path(request):
    filename = request.args.get('file')
    return os.path.join('/var/www/uploads', filename)
"""
    vulns = await detector.detect(Path("utils.py"), content, "python")

    assert len(vulns) >= 1
    join_vulns = [v for v in vulns if "Unsafe Path Joining" in v.title]
    assert len(join_vulns) >= 1
    assert join_vulns[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_detect_nodejs_path_join(detector):
    """Test detection of path.join with request params."""
    content = """
const filePath = path.join(__dirname, req.params.filename);
"""
    vulns = await detector.detect(Path("server.js"), content, "javascript")

    assert len(vulns) >= 1


@pytest.mark.asyncio
@pytest.mark.xfail(reason="Requires semantic analysis: taint tracking across lines (Phase 4.2)")
async def test_detect_java_file_constructor(detector):
    """Test detection of Java File() with request data."""
    content = """
String filename = request.getParameter("file");
File file = new File("/uploads", filename);
"""
    vulns = await detector.detect(Path("FileHandler.java"), content, "java")

    assert len(vulns) >= 1


@pytest.mark.asyncio
async def test_detect_java_paths_get(detector):
    """Test detection of Java Paths.get() with params."""
    content = """
Path filePath = Paths.get(baseDir, request.getParameter("file"));
"""
    vulns = await detector.detect(Path("FileService.java"), content, "java")

    assert len(vulns) >= 1


# ============================================================================
# File Type Applicability Tests
# ============================================================================


def test_is_applicable_python(detector):
    """Test that detector applies to Python files."""
    assert detector.is_applicable(Path("utils.py"), "python") is True
    assert detector.is_applicable(Path("views.py")) is True


def test_is_applicable_javascript(detector):
    """Test that detector applies to JavaScript files."""
    assert detector.is_applicable(Path("server.js"), "javascript") is True
    assert detector.is_applicable(Path("app.ts"), "typescript") is True
    assert detector.is_applicable(Path("component.jsx")) is True


def test_is_applicable_java(detector):
    """Test that detector applies to Java files."""
    assert detector.is_applicable(Path("FileHandler.java"), "java") is True


def test_is_applicable_php(detector):
    """Test that detector applies to PHP files."""
    assert detector.is_applicable(Path("upload.php"), "php") is True


def test_is_applicable_other_languages(detector):
    """Test that detector applies to other code files."""
    assert detector.is_applicable(Path("utils.rb"), "ruby") is True
    assert detector.is_applicable(Path("server.go"), "go") is True
    assert detector.is_applicable(Path("handler.rs"), "rust") is True


def test_is_applicable_non_code_files(detector):
    """Test that detector does not apply to non-code files."""
    assert detector.is_applicable(Path("README.md")) is False
    assert detector.is_applicable(Path("config.json")) is False
    assert detector.is_applicable(Path("data.txt")) is False


# ============================================================================
# Comment Filtering Tests
# ============================================================================


@pytest.mark.asyncio
async def test_ignore_python_comments(detector):
    """Test that Python comments are ignored."""
    content = """
# Dangerous: open(request.args.get('file'))
# This is just documentation
def safe_function():
    pass
"""
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_ignore_javascript_comments(detector):
    """Test that JavaScript comments are ignored."""
    content = """
// fs.readFile(req.query.filename)
// Example of vulnerable code
function safe() {
    return true;
}
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 0


# ============================================================================
# False Positive Prevention Tests
# ============================================================================


@pytest.mark.asyncio
async def test_safe_with_realpath(detector):
    """Test that paths with realpath() are not flagged."""
    content = """
def read_file(filename):
    safe_path = os.path.realpath(filename)
    with open(safe_path) as f:
        return f.read()
"""
    vulns = await detector.detect(Path("safe.py"), content, "python")

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_safe_with_normpath(detector):
    """Test that paths with normpath() are not flagged."""
    content = """
path = os.path.normpath(user_input)
with open(path) as f:
    return f.read()
"""
    vulns = await detector.detect(Path("safe.py"), content, "python")

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_safe_with_resolve(detector):
    """Test that paths with resolve() are not flagged."""
    content = """
const safePath = path.resolve(userInput);
fs.readFile(safePath);
"""
    vulns = await detector.detect(Path("safe.js"), content, "javascript")

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_safe_zip_extraction_with_validation(detector):
    """Test that validated zip extraction is not flagged."""
    content = """
for member in zf.members:
    if member.startswith('/') or '..' in member:
        continue
    zf.extract(member)
"""
    vulns = await detector.detect(Path("safe_unzip.py"), content, "python")

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_ignore_test_files(detector):
    """Test that test examples are ignored."""
    content = """
# Test case for path traversal
test_path = "../../../etc/passwd"
"""
    vulns = await detector.detect(Path("test_security.py"), content, "python")

    assert len(vulns) == 0


# ============================================================================
# Multiple Vulnerabilities Tests
# ============================================================================


@pytest.mark.asyncio
async def test_multiple_path_traversal_issues(detector):
    """Test detection of multiple path traversal vulnerabilities."""
    content = """
def vulnerable_function(request):
    # Issue 1: Direct path manipulation
    file1 = open(request.args.get('file'))

    # Issue 2: Unsafe path join
    path = os.path.join('/tmp', request.args.get('name'))

    # Issue 3: Traversal sequence
    evil = "../../../etc/passwd"
"""
    vulns = await detector.detect(Path("vuln.py"), content, "python")

    assert len(vulns) >= 3
    assert all(v.type == VulnerabilityType.PATH_TRAVERSAL for v in vulns)


# ============================================================================
# Edge Case Tests
# ============================================================================


@pytest.mark.asyncio
async def test_empty_file(detector):
    """Test that empty files don't cause errors."""
    vulns = await detector.detect(Path("empty.py"), "", "python")
    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_whitespace_only(detector):
    """Test that whitespace-only files don't cause errors."""
    content = "   \n\n   \t\t\n   "
    vulns = await detector.detect(Path("whitespace.py"), content, "python")
    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_line_number_accuracy(detector):
    """Test that line numbers are reported accurately."""
    content = """line 1
line 2
open(request.args.get('file'))  # line 3
line 4
"""
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) >= 1
    assert vulns[0].line_number == 3


@pytest.mark.asyncio
async def test_code_snippet_captured(detector):
    """Test that code snippets are captured correctly."""
    content = """
open(request.args.get('file'))
"""
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) >= 1
    assert "open" in vulns[0].code_snippet
    assert "request" in vulns[0].code_snippet


# ============================================================================
# Metadata Tests
# ============================================================================


def test_detector_name(detector):
    """Test that detector has correct name."""
    assert detector.name == "PathTraversalDetector"


def test_detector_enabled_by_default(detector):
    """Test that detector is enabled by default."""
    assert detector.enabled is True


@pytest.mark.asyncio
async def test_vulnerability_metadata_path_manipulation(detector):
    """Test that path manipulation vulnerabilities have complete metadata."""
    content = "open(request.args.get('file'))"
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) >= 1
    vuln = vulns[0]

    # Check all required fields
    assert vuln.type == VulnerabilityType.PATH_TRAVERSAL
    assert vuln.title is not None
    assert "Path Manipulation" in vuln.title or "Path Traversal" in vuln.title
    assert vuln.description is not None
    assert len(vuln.description) > 100
    assert vuln.severity in [Severity.CRITICAL, Severity.HIGH]
    assert vuln.confidence == Confidence.HIGH
    assert vuln.cwe_id in ["CWE-22", "CWE-23"]
    assert vuln.cvss_score >= 7.0
    assert vuln.remediation is not None
    assert len(vuln.remediation) > 100
    assert len(vuln.references) >= 3
    assert vuln.detector == "PathTraversalDetector"
    assert vuln.engine == "static"
    assert len(vuln.mitre_attack_ids) > 0


@pytest.mark.asyncio
async def test_vulnerability_metadata_zip_slip(detector):
    """Test that Zip Slip vulnerabilities have CRITICAL severity."""
    content = "zf.extractall()"
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) >= 1
    zip_vulns = [v for v in vulns if "Zip Slip" in v.title]
    if zip_vulns:
        assert zip_vulns[0].severity == Severity.CRITICAL
        assert zip_vulns[0].cvss_score == 9.8


@pytest.mark.asyncio
async def test_vulnerability_remediation_content(detector):
    """Test that remediation guidance is comprehensive."""
    content = "open(request.args.get('file'))"
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) >= 1
    remediation = vulns[0].remediation

    # Check for key remediation steps
    assert "validate" in remediation.lower() or "Validate" in remediation
    assert "sanitize" in remediation.lower() or "allowlist" in remediation.lower()


@pytest.mark.asyncio
async def test_vulnerability_references(detector):
    """Test that vulnerabilities include proper references."""
    content = "open(request.args.get('file'))"
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) >= 1
    references = vulns[0].references

    assert len(references) >= 3
    # Check for OWASP reference
    assert any("owasp.org" in ref for ref in references)
    # Check for CWE reference
    assert any("cwe.mitre.org" in ref for ref in references)


# ============================================================================
# Integration Tests
# ============================================================================


@pytest.mark.asyncio
async def test_comprehensive_path_traversal_detection(detector):
    """Test detection of all pattern types in a realistic file."""
    content = """
import os
import zipfile

def process_file(request):
    # Path manipulation
    filename = request.args.get('file')
    with open(filename) as f:
        data = f.read()

    # Unsafe path join
    path = os.path.join('/uploads', request.args.get('name'))

    # Traversal sequence
    config_path = "../../../etc/app.conf"

    # Zip extraction
    with zipfile.ZipFile('archive.zip') as zf:
        zf.extractall()

    return data
"""
    vulns = await detector.detect(Path("handler.py"), content, "python")

    # Should detect multiple issues
    assert len(vulns) >= 4
    assert all(v.type == VulnerabilityType.PATH_TRAVERSAL for v in vulns)

    # Check variety of severity levels
    severities = {v.severity for v in vulns}
    assert Severity.CRITICAL in severities or Severity.HIGH in severities


@pytest.mark.asyncio
@pytest.mark.xfail(reason="Requires semantic analysis: taint tracking across lines (Phase 4.2)")
async def test_nodejs_file_handler(detector):
    """Test detection in Node.js file handler."""
    content = """
const fs = require('fs');
const path = require('path');

app.get('/download', (req, res) => {
    const filename = req.query.file;
    const filePath = path.join(__dirname, 'uploads', filename);
    const content = fs.readFile(filePath);
    res.send(content);
});
"""
    vulns = await detector.detect(Path("routes.js"), content, "javascript")

    assert len(vulns) >= 2
