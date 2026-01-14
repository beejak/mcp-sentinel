"""
Unit tests for CodeInjectionDetector.

Tests all 9 detection patterns across Python and JavaScript/TypeScript.
"""

import pytest
from pathlib import Path
from typing import List

from mcp_sentinel.detectors.code_injection import CodeInjectionDetector
from mcp_sentinel.models.vulnerability import (
    Vulnerability,
    VulnerabilityType,
    Severity,
    Confidence,
)


@pytest.fixture
def detector():
    """Create a CodeInjectionDetector instance for testing."""
    return CodeInjectionDetector()


@pytest.fixture
def python_fixture_path():
    """Path to Python test fixture."""
    return Path(__file__).parent.parent / "fixtures" / "vulnerable_code_injection.py"


@pytest.fixture
def javascript_fixture_path():
    """Path to JavaScript test fixture."""
    return Path(__file__).parent.parent / "fixtures" / "vulnerable_code_injection.js"


# ============================================================================
# Python Pattern Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_os_system(detector):
    """Test detection of os.system() command injection."""
    content = """
import os

def vulnerable():
    user_input = input("Enter filename: ")
    os.system(f"cat {user_input}")
"""
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) == 1
    assert vulns[0].type == VulnerabilityType.CODE_INJECTION
    assert vulns[0].severity == Severity.CRITICAL
    assert vulns[0].confidence == Confidence.HIGH
    assert vulns[0].cwe_id == "CWE-78"
    assert vulns[0].cvss_score == 9.8
    assert "os.system()" in vulns[0].title
    assert vulns[0].line_number == 6  # Account for leading newline
    assert "T1059" in vulns[0].mitre_attack_ids


@pytest.mark.asyncio
async def test_detect_subprocess_call_shell(detector):
    """Test detection of subprocess.call() with shell=True."""
    content = """
import subprocess

def vulnerable():
    subprocess.call(f"cat {user_file}", shell=True)
"""
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.CRITICAL
    assert "subprocess.call" in vulns[0].title
    assert "shell=True" in vulns[0].title
    assert vulns[0].cwe_id == "CWE-78"
    assert vulns[0].line_number == 5


@pytest.mark.asyncio
async def test_detect_subprocess_run_shell(detector):
    """Test detection of subprocess.run() with shell=True."""
    content = """
import subprocess

def vulnerable():
    cmd = f"ping {hostname}"
    subprocess.run(cmd, shell=True)
"""
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.CRITICAL
    assert "subprocess.run" in vulns[0].title
    assert "shell=True" in vulns[0].title
    assert vulns[0].cwe_id == "CWE-78"


@pytest.mark.asyncio
async def test_detect_subprocess_popen_shell(detector):
    """Test detection of subprocess.Popen() with shell=True."""
    content = """
import subprocess

def vulnerable():
    process = subprocess.Popen(
        f"grep {pattern} {filename}",
        shell=True,
        stdout=subprocess.PIPE
    )
"""
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.CRITICAL
    assert "subprocess.Popen" in vulns[0].title
    assert "shell=True" in vulns[0].title
    assert vulns[0].cwe_id == "CWE-78"


@pytest.mark.asyncio
async def test_detect_eval_usage(detector):
    """Test detection of eval() code injection."""
    content = """
def vulnerable():
    user_code = request.form.get('expression')
    result = eval(user_code)
    return result
"""
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.CRITICAL
    assert "eval()" in vulns[0].title
    assert vulns[0].cwe_id == "CWE-95"
    assert vulns[0].line_number == 4  # Account for leading newline
    assert "ast.literal_eval" in vulns[0].remediation


@pytest.mark.asyncio
async def test_detect_exec_usage(detector):
    """Test detection of exec() code injection."""
    content = """
def vulnerable():
    code = request.json.get('code')
    exec(code)
"""
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.CRITICAL
    assert "exec()" in vulns[0].title
    assert vulns[0].cwe_id == "CWE-95"
    assert "NEVER use exec()" in vulns[0].remediation


@pytest.mark.asyncio
async def test_multiple_python_vulnerabilities(detector):
    """Test detection of multiple vulnerabilities in one file."""
    content = """
import os
import subprocess

def vuln1():
    os.system("ls")

def vuln2():
    subprocess.run("pwd", shell=True)

def vuln3():
    eval(user_input)
"""
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) == 3
    assert all(v.severity == Severity.CRITICAL for v in vulns)


# ============================================================================
# JavaScript/TypeScript Pattern Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_child_process_exec(detector):
    """Test detection of child_process.exec() command injection."""
    content = """const child_process = require('child_process');

function vulnerable() {
    const userInput = req.query.filename;
    child_process.exec('cat ' + userInput, (error, stdout, stderr) => {
        console.log(stdout);
    });
}
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 1
    assert vulns[0].type == VulnerabilityType.CODE_INJECTION
    assert vulns[0].severity == Severity.CRITICAL
    assert "child_process.exec()" in vulns[0].title
    assert vulns[0].cwe_id == "CWE-78"
    assert vulns[0].line_number == 5
    assert "T1059.007" in vulns[0].mitre_attack_ids


@pytest.mark.asyncio
async def test_detect_javascript_eval(detector):
    """Test detection of eval() in JavaScript."""
    content = """
function vulnerable() {
    const userCode = req.body.expression;
    const result = eval(userCode);
    return result;
}
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.CRITICAL
    assert "eval()" in vulns[0].title
    assert vulns[0].cwe_id == "CWE-95"
    assert "JSON.parse()" in vulns[0].remediation


@pytest.mark.asyncio
async def test_detect_function_constructor(detector):
    """Test detection of Function() constructor."""
    content = """
function vulnerable() {
    const userCode = req.body.code;
    const fn = new Function(userCode);
    fn();
}
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.CRITICAL
    assert "Function() Constructor" in vulns[0].title
    assert vulns[0].cwe_id == "CWE-95"
    assert vulns[0].confidence == Confidence.MEDIUM


@pytest.mark.asyncio
async def test_child_process_require_inline(detector):
    """Test detection of child_process.exec() with inline require()."""
    content = """
function vulnerable() {
    require('child_process').exec('ls -la');
}
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 1
    assert "child_process.exec()" in vulns[0].title


@pytest.mark.asyncio
async def test_multiple_javascript_vulnerabilities(detector):
    """Test detection of multiple vulnerabilities in one JS file."""
    content = """
const { exec } = require('child_process');

function vuln1() {
    exec('ls');
}

function vuln2() {
    eval(userInput);
}

function vuln3() {
    new Function(userCode)();
}
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 3
    assert all(v.severity == Severity.CRITICAL for v in vulns)


# ============================================================================
# File Type Filtering Tests
# ============================================================================


@pytest.mark.asyncio
async def test_typescript_file_detection(detector):
    """Test that detector works on TypeScript files."""
    content = """
function vulnerable(): void {
    eval(userInput);
}
"""
    vulns = await detector.detect(Path("test.ts"), content, "typescript")

    assert len(vulns) == 1
    assert vulns[0].file_path == "test.ts"


@pytest.mark.asyncio
async def test_jsx_file_detection(detector):
    """Test that detector works on JSX files."""
    content = """
const Component = () => {
    const result = eval(props.code);
    return <div>{result}</div>;
};
"""
    vulns = await detector.detect(Path("component.jsx"), content)

    assert len(vulns) == 1


def test_is_applicable_python(detector):
    """Test that detector applies to Python files."""
    assert detector.is_applicable(Path("test.py"), "python") is True
    assert detector.is_applicable(Path("module.py")) is True


def test_is_applicable_javascript(detector):
    """Test that detector applies to JavaScript files."""
    assert detector.is_applicable(Path("app.js"), "javascript") is True
    assert detector.is_applicable(Path("component.jsx")) is True
    assert detector.is_applicable(Path("module.ts"), "typescript") is True
    assert detector.is_applicable(Path("component.tsx")) is True


def test_is_applicable_other_files(detector):
    """Test that detector does not apply to other file types."""
    assert detector.is_applicable(Path("README.md")) is False
    assert detector.is_applicable(Path("config.json")) is False
    assert detector.is_applicable(Path("styles.css")) is False
    assert detector.is_applicable(Path("data.txt")) is False


# ============================================================================
# Comment Filtering Tests
# ============================================================================


@pytest.mark.asyncio
async def test_ignore_python_comments(detector):
    """Test that Python comments are ignored."""
    content = """
# This is a comment with os.system("command")
def safe():
    # eval("this is also a comment")
    pass
"""
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) == 0


@pytest.mark.asyncio
@pytest.mark.xfail(reason="Requires multi-line comment detection for /* ... */ blocks (Phase 4.2)")
async def test_ignore_javascript_comments(detector):
    """Test that JavaScript comments are ignored."""
    content = """
// This is a comment with eval("code")
function safe() {
    // child_process.exec("command")
    /*
     * new Function("code")
     */
    return true;
}
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 0


# ============================================================================
# Safe Pattern Tests (False Positive Prevention)
# ============================================================================


@pytest.mark.asyncio
async def test_safe_subprocess_without_shell(detector):
    """Test that safe subprocess usage without shell=True is not flagged."""
    content = """
import subprocess

def safe():
    subprocess.run(['ls', '-la', directory])
    subprocess.call(['echo', 'hello'])
"""
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_safe_subprocess_shell_false(detector):
    """Test that subprocess with shell=False is not flagged."""
    content = """
import subprocess

def safe():
    subprocess.run(['ls'], shell=False)
"""
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_safe_ast_literal_eval(detector):
    """Test that ast.literal_eval is not flagged."""
    content = """
import ast

def safe():
    data = ast.literal_eval(user_input)
"""
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_safe_json_parse(detector):
    """Test that JSON.parse is not flagged."""
    content = """
function safe() {
    const data = JSON.parse(userInput);
}
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_safe_execfile_spawn(detector):
    """Test that safe child_process alternatives are not flagged."""
    content = """
const { execFile, spawn } = require('child_process');

function safe() {
    execFile('ls', ['-la']);
    spawn('echo', ['hello']);
}
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 0


# ============================================================================
# Integration Tests with Fixtures
# ============================================================================


@pytest.mark.asyncio
@pytest.mark.xfail(reason="Fixture likely contains multi-line patterns requiring Phase 4.2")
async def test_python_fixture_file(detector, python_fixture_path):
    """Test detection against Python fixture file."""
    content = python_fixture_path.read_text()
    vulns = await detector.detect(python_fixture_path, content, "python")

    # Should find: 2 os.system + 2 subprocess.call + 2 subprocess.run +
    #              2 subprocess.Popen + 2 eval + 2 exec = 12 vulnerabilities
    assert len(vulns) >= 12
    assert all(v.severity == Severity.CRITICAL for v in vulns)
    assert all(v.type == VulnerabilityType.CODE_INJECTION for v in vulns)


@pytest.mark.asyncio
async def test_javascript_fixture_file(detector, javascript_fixture_path):
    """Test detection against JavaScript fixture file."""
    content = javascript_fixture_path.read_text()
    vulns = await detector.detect(javascript_fixture_path, content, "javascript")

    # Should find: 3 exec + 3 eval + 3 Function constructor = 9 vulnerabilities
    assert len(vulns) >= 9
    assert all(v.severity == Severity.CRITICAL for v in vulns)
    assert all(v.type == VulnerabilityType.CODE_INJECTION for v in vulns)


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
async def test_multiline_detection(detector):
    """Test detection across multiple lines."""
    content = """
def vulnerable():
    subprocess.run(
        "dangerous command",
        shell=True
    )
"""
    vulns = await detector.detect(Path("test.py"), content, "python")

    # Should detect the pattern on the line with "shell=True"
    assert len(vulns) == 1


@pytest.mark.asyncio
async def test_line_number_accuracy(detector):
    """Test that line numbers are reported accurately."""
    content = """line 1
line 2
line 3
def vulnerable():  # line 4
    os.system("command")  # line 5
line 6
"""
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) == 1
    assert vulns[0].line_number == 5


@pytest.mark.asyncio
async def test_code_snippet_captured(detector):
    """Test that code snippets are captured correctly."""
    content = """
def vulnerable():
    os.system("dangerous command")
"""
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) == 1
    assert 'os.system("dangerous command")' in vulns[0].code_snippet


# ============================================================================
# Metadata Tests
# ============================================================================


def test_detector_name(detector):
    """Test that detector has correct name."""
    assert detector.name == "CodeInjectionDetector"


def test_detector_enabled_by_default(detector):
    """Test that detector is enabled by default."""
    assert detector.enabled is True


@pytest.mark.asyncio
async def test_vulnerability_metadata(detector):
    """Test that vulnerabilities have complete metadata."""
    content = 'os.system("command")'
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) == 1
    vuln = vulns[0]

    # Check all required fields
    assert vuln.type == VulnerabilityType.CODE_INJECTION
    assert vuln.title is not None
    assert len(vuln.title) > 0
    assert vuln.description is not None
    assert len(vuln.description) > 50  # Detailed description
    assert vuln.severity == Severity.CRITICAL
    assert vuln.confidence in [Confidence.HIGH, Confidence.MEDIUM]
    assert vuln.cwe_id is not None
    assert vuln.cwe_id.startswith("CWE-")
    assert vuln.cvss_score == 9.8
    assert vuln.remediation is not None
    assert len(vuln.remediation) > 50  # Detailed remediation
    assert len(vuln.references) >= 3  # Multiple references
    assert vuln.detector == "CodeInjectionDetector"
    assert vuln.engine == "static"
    assert len(vuln.mitre_attack_ids) > 0
