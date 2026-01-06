"""
Unit tests for XSSDetector.

Tests all 6 XSS detection pattern categories across multiple languages:
- DOM-based XSS (innerHTML, outerHTML)
- Event handler injection (onclick, onerror)
- JavaScript protocol injection (javascript:, data:)
- Dangerous HTML insertion (React, Vue, Angular)
- Template XSS (Jinja2, Django, template literals)
- jQuery XSS (.html(), .append())
"""

import pytest
from pathlib import Path
from typing import List

from mcp_sentinel.detectors.xss import XSSDetector
from mcp_sentinel.models.vulnerability import (
    Vulnerability,
    VulnerabilityType,
    Severity,
    Confidence,
)


@pytest.fixture
def detector():
    """Create an XSSDetector instance for testing."""
    return XSSDetector()


@pytest.fixture
def html_fixture_path():
    """Path to HTML test fixture."""
    return Path(__file__).parent.parent / "fixtures" / "vulnerable_xss.html"


@pytest.fixture
def javascript_fixture_path():
    """Path to JavaScript test fixture."""
    return Path(__file__).parent.parent / "fixtures" / "vulnerable_xss.js"


# ============================================================================
# Pattern 1: DOM-based XSS Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_innerhtml_assignment(detector):
    """Test detection of innerHTML assignment."""
    content = """
function displayUser(name) {
    document.getElementById('username').innerHTML = name;
}
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 1
    assert vulns[0].type == VulnerabilityType.XSS
    assert vulns[0].severity == Severity.HIGH
    assert vulns[0].confidence == Confidence.HIGH
    assert vulns[0].cwe_id == "CWE-79"
    assert vulns[0].cvss_score == 7.4
    assert "DOM-Based" in vulns[0].title
    assert "innerHTML" in vulns[0].title
    assert vulns[0].line_number == 3
    assert "T1189" in vulns[0].mitre_attack_ids


@pytest.mark.asyncio
async def test_detect_outerhtml_assignment(detector):
    """Test detection of outerHTML assignment."""
    content = """
element.outerHTML = userContent;
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.HIGH
    assert "outerHTML" in vulns[0].code_snippet


@pytest.mark.asyncio
async def test_detect_insertadjacenthtml(detector):
    """Test detection of insertAdjacentHTML."""
    content = """
div.insertAdjacentHTML('beforeend', userInput);
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.HIGH
    assert "insertAdjacentHTML" in vulns[0].code_snippet


@pytest.mark.asyncio
async def test_detect_document_write_concatenation(detector):
    """Test detection of document.write with concatenation."""
    content = """
document.write("<div>" + userName + "</div>");
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_detect_document_writeln(detector):
    """Test detection of document.writeln with concatenation."""
    content = """
document.writeln("Hello " + user);
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 1


# ============================================================================
# Pattern 2: Event Handler Injection Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_onclick_attribute(detector):
    """Test detection of onclick event handler."""
    content = """
<button onclick="handleClick()">Click me</button>
"""
    vulns = await detector.detect(Path("test.html"), content, "html")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.HIGH
    assert vulns[0].confidence == Confidence.MEDIUM
    assert "Event Handler" in vulns[0].title
    assert "onclick" in vulns[0].code_snippet


@pytest.mark.asyncio
async def test_detect_onerror_attribute(detector):
    """Test detection of onerror event handler."""
    content = """
<img src="invalid.jpg" onerror="alert('XSS')">
"""
    vulns = await detector.detect(Path("test.html"), content, "html")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_detect_onload_attribute(detector):
    """Test detection of onload event handler."""
    content = """
<body onload="loadData()">
"""
    vulns = await detector.detect(Path("test.html"), content, "html")

    assert len(vulns) == 1


@pytest.mark.asyncio
async def test_detect_setattribute_event(detector):
    """Test detection of setAttribute with event handler."""
    content = """
element.setAttribute('onclick', 'maliciousCode()');
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.HIGH
    assert "setAttribute" in vulns[0].code_snippet


@pytest.mark.asyncio
async def test_detect_multiple_event_handlers(detector):
    """Test detection of multiple event handlers in HTML."""
    content = """
<div onclick="handler1()" onmouseover="handler2()">
    <img onerror="handler3()">
</div>
"""
    vulns = await detector.detect(Path("test.html"), content, "html")

    assert len(vulns) >= 3


# ============================================================================
# Pattern 3: JavaScript Protocol Injection Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_javascript_protocol(detector):
    """Test detection of javascript: protocol."""
    content = """
<a href="javascript:alert('XSS')">Click</a>
"""
    vulns = await detector.detect(Path("test.html"), content, "html")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.CRITICAL
    assert vulns[0].confidence == Confidence.HIGH
    assert vulns[0].cvss_score == 8.2
    assert "JavaScript Protocol" in vulns[0].title
    assert "javascript:" in vulns[0].code_snippet


@pytest.mark.asyncio
async def test_detect_javascript_protocol_uppercase(detector):
    """Test detection of JAVASCRIPT: protocol (case insensitive)."""
    content = """
location.href = "JAVASCRIPT:void(0)";
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_detect_data_text_html(detector):
    """Test detection of data:text/html protocol."""
    content = """
<iframe src="data:text/html,<script>alert('XSS')</script>"></iframe>
"""
    vulns = await detector.detect(Path("test.html"), content, "html")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.CRITICAL
    assert "data:text/html" in vulns[0].code_snippet


@pytest.mark.asyncio
async def test_detect_vbscript_protocol(detector):
    """Test detection of vbscript: protocol."""
    content = """
<a href="vbscript:msgbox('XSS')">Click</a>
"""
    vulns = await detector.detect(Path("test.html"), content, "html")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.CRITICAL


# ============================================================================
# Pattern 4: Dangerous HTML Insertion Tests (React/Vue/Angular)
# ============================================================================


@pytest.mark.asyncio
async def test_detect_react_dangerously_set_innerhtml(detector):
    """Test detection of React's dangerouslySetInnerHTML."""
    content = """
const MyComponent = () => {
    return <div dangerouslySetInnerHTML={{__html: userContent}} />;
};
"""
    vulns = await detector.detect(Path("component.jsx"), content, "jsx")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.HIGH
    assert vulns[0].confidence == Confidence.HIGH
    assert vulns[0].cvss_score == 7.8
    assert "React/Vue/Angular" in vulns[0].title
    assert "dangerouslySetInnerHTML" in vulns[0].code_snippet


@pytest.mark.asyncio
async def test_detect_vue_v_html(detector):
    """Test detection of Vue's v-html directive."""
    content = """
<template>
    <div v-html="userContent"></div>
</template>
"""
    vulns = await detector.detect(Path("component.vue"), content, "vue")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.HIGH
    assert "v-html" in vulns[0].code_snippet


@pytest.mark.asyncio
async def test_detect_angular_innerhtml_binding(detector):
    """Test detection of Angular's [innerHTML] binding."""
    content = """
<div [innerHTML]="userContent"></div>
"""
    vulns = await detector.detect(Path("component.html"), content, "html")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.HIGH
    assert "[innerHTML]" in vulns[0].code_snippet


# ============================================================================
# Pattern 5: Template XSS Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_jinja2_safe_filter(detector):
    """Test detection of Jinja2 |safe filter."""
    content = """
<div>{{ user_content | safe }}</div>
"""
    vulns = await detector.detect(Path("template.html"), content, "html")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.MEDIUM
    assert vulns[0].confidence == Confidence.MEDIUM
    assert vulns[0].cvss_score == 6.1
    assert "Template Rendering" in vulns[0].title
    assert "safe" in vulns[0].code_snippet


@pytest.mark.asyncio
async def test_detect_django_mark_safe(detector):
    """Test detection of Django's mark_safe filter."""
    content = """
<p>{{ content | mark_safe }}</p>
"""
    vulns = await detector.detect(Path("template.html"), content, "html")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_detect_python_safe_function(detector):
    """Test detection of Python safe() function."""
    content = """
def render():
    return safe(user_input)
"""
    vulns = await detector.detect(Path("views.py"), content, "python")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_detect_template_literal_with_user_input(detector):
    """Test detection of template literals with user input variables."""
    content = """
const html = `<div>${params.username}</div>`;
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_detect_template_literal_with_query(detector):
    """Test detection of template literals with query parameters."""
    content = """
const message = `Hello ${query.name}`;
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 1


# ============================================================================
# Pattern 6: jQuery XSS Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_jquery_html_method(detector):
    """Test detection of jQuery .html() method."""
    content = """
$('#content').html(userData);
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.HIGH
    assert vulns[0].confidence == Confidence.MEDIUM
    assert vulns[0].cvss_score == 7.2
    assert "jQuery" in vulns[0].title
    assert ".html()" in vulns[0].code_snippet


@pytest.mark.asyncio
async def test_detect_jquery_append_concatenation(detector):
    """Test detection of jQuery .append() with concatenation."""
    content = """
$('#list').append('<li>' + userName + '</li>');
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.HIGH
    assert ".append(" in vulns[0].code_snippet


@pytest.mark.asyncio
async def test_detect_jquery_prepend_concatenation(detector):
    """Test detection of jQuery .prepend() with concatenation."""
    content = """
$('#header').prepend('<h1>' + title + '</h1>');
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.HIGH


# ============================================================================
# File Type Filtering Tests
# ============================================================================


@pytest.mark.asyncio
async def test_typescript_file_detection(detector):
    """Test that detector works on TypeScript files."""
    content = """
element.innerHTML = userInput;
"""
    vulns = await detector.detect(Path("test.ts"), content, "typescript")

    assert len(vulns) == 1


@pytest.mark.asyncio
async def test_jsx_file_detection(detector):
    """Test that detector works on JSX files."""
    content = """
const Component = () => <div dangerouslySetInnerHTML={{__html: data}} />;
"""
    vulns = await detector.detect(Path("component.jsx"), content, "jsx")

    assert len(vulns) == 1


@pytest.mark.asyncio
async def test_tsx_file_detection(detector):
    """Test that detector works on TSX files."""
    content = """
const Component: React.FC = () => <div dangerouslySetInnerHTML={{__html: data}} />;
"""
    vulns = await detector.detect(Path("component.tsx"), content, "tsx")

    assert len(vulns) == 1


@pytest.mark.asyncio
async def test_vue_file_detection(detector):
    """Test that detector works on Vue files."""
    content = """
<div v-html="content"></div>
"""
    vulns = await detector.detect(Path("component.vue"), content, "vue")

    assert len(vulns) == 1


@pytest.mark.asyncio
async def test_python_template_detection(detector):
    """Test that detector works on Python template files."""
    content = """
{{ content | safe }}
"""
    vulns = await detector.detect(Path("template.jinja2"), content)

    assert len(vulns) == 1


def test_is_applicable_html(detector):
    """Test that detector applies to HTML files."""
    assert detector.is_applicable(Path("index.html"), "html") is True
    assert detector.is_applicable(Path("page.htm")) is True
    assert detector.is_applicable(Path("template.xhtml")) is True


def test_is_applicable_javascript(detector):
    """Test that detector applies to JavaScript files."""
    assert detector.is_applicable(Path("app.js"), "javascript") is True
    assert detector.is_applicable(Path("component.jsx")) is True
    assert detector.is_applicable(Path("module.ts"), "typescript") is True
    assert detector.is_applicable(Path("component.tsx")) is True


def test_is_applicable_python(detector):
    """Test that detector applies to Python template files."""
    assert detector.is_applicable(Path("views.py"), "python") is True
    assert detector.is_applicable(Path("template.jinja")) is True
    assert detector.is_applicable(Path("template.jinja2")) is True
    assert detector.is_applicable(Path("template.j2")) is True


def test_is_applicable_frameworks(detector):
    """Test that detector applies to modern framework files."""
    assert detector.is_applicable(Path("component.vue"), "vue") is True
    assert detector.is_applicable(Path("component.svelte"), "svelte") is True


def test_is_applicable_server_side(detector):
    """Test that detector applies to server-side template files."""
    assert detector.is_applicable(Path("page.php")) is True
    assert detector.is_applicable(Path("page.asp")) is True
    assert detector.is_applicable(Path("page.aspx")) is True
    assert detector.is_applicable(Path("page.jsp")) is True


def test_is_applicable_other_files(detector):
    """Test that detector does not apply to non-web files."""
    assert detector.is_applicable(Path("README.md")) is False
    assert detector.is_applicable(Path("config.json")) is False
    assert detector.is_applicable(Path("styles.css")) is False
    assert detector.is_applicable(Path("data.txt")) is False
    assert detector.is_applicable(Path("script.sh")) is False


# ============================================================================
# Comment Filtering Tests
# ============================================================================


@pytest.mark.asyncio
async def test_ignore_python_comments(detector):
    """Test that Python comments are ignored."""
    content = """
# This is a comment with innerHTML = userInput
def safe():
    # element.outerHTML = data
    pass
"""
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_ignore_javascript_comments(detector):
    """Test that JavaScript comments are ignored."""
    content = """
// This is a comment with innerHTML = userInput
function safe() {
    // element.innerHTML = userData
    /*
     * dangerouslySetInnerHTML={{__html: data}}
     */
    return true;
}
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_ignore_html_comments(detector):
    """Test that HTML comments are ignored."""
    content = """
<!-- <div onclick="malicious()"></div> -->
<!-- <script>javascript:alert('XSS')</script> -->
<div>Safe content</div>
"""
    vulns = await detector.detect(Path("test.html"), content, "html")

    assert len(vulns) == 0


# ============================================================================
# Safe Pattern Tests (False Positive Prevention)
# ============================================================================


@pytest.mark.asyncio
async def test_safe_innerhtml_static_string(detector):
    """Test that innerHTML with static string is not flagged."""
    content = """
element.innerHTML = "This is a static string";
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_safe_innerhtml_with_sanitization(detector):
    """Test that sanitized innerHTML is not flagged."""
    content = """
element.innerHTML = DOMPurify.sanitize(userInput);
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_safe_with_escape_function(detector):
    """Test that escaped content is CORRECTLY flagged (escape() is not safe for XSS)."""
    content = """
element.innerHTML = escape(userContent);
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    # Note: JavaScript's escape() is deprecated and does NOT prevent XSS
    # This should correctly be flagged as vulnerable
    assert len(vulns) == 1


@pytest.mark.asyncio
async def test_safe_with_htmlspecialchars(detector):
    """Test that htmlspecialchars is not flagged."""
    content = """
echo '<div>' . htmlspecialchars($userInput) . '</div>';
"""
    vulns = await detector.detect(Path("test.php"), content, "php")

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_safe_with_xss_filter(detector):
    """Test that XSS filtering is recognized."""
    content = """
element.innerHTML = xssFilter.clean(userInput);
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_safe_template_in_test_file(detector):
    """Test that |safe in test files is not flagged."""
    content = """
# Test example
test_html = "{{ content | safe }}"
"""
    vulns = await detector.detect(Path("test_views.py"), content, "python")

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_safe_onclick_null(detector):
    """Test that onclick=null is not flagged."""
    content = """
<button onclick="null">Click</button>
"""
    vulns = await detector.detect(Path("test.html"), content, "html")

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_safe_onclick_false(detector):
    """Test that onclick=false is not flagged."""
    content = """
<button onclick="false">Click</button>
"""
    vulns = await detector.detect(Path("test.html"), content, "html")

    assert len(vulns) == 0


# ============================================================================
# Multiple Vulnerabilities Tests
# ============================================================================


@pytest.mark.asyncio
async def test_multiple_xss_vulnerabilities(detector):
    """Test detection of multiple XSS vulnerabilities in one file."""
    content = """
function display(userData) {
    element.innerHTML = userData;
    document.write("<div>" + userData + "</div>");
    $('#output').html(userData);
}

function clickHandler() {
    element.setAttribute('onclick', 'malicious()');
}

const link = '<a href="javascript:alert()">Click</a>';
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) >= 5
    assert all(v.type == VulnerabilityType.XSS for v in vulns)


@pytest.mark.asyncio
async def test_mixed_severity_vulnerabilities(detector):
    """Test that different patterns have appropriate severity levels."""
    content = """
// CRITICAL: javascript: protocol
location.href = "javascript:alert()";

// HIGH: innerHTML
element.innerHTML = userInput;

// MEDIUM: template safe filter
{{ content | safe }}
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) >= 2
    severities = [v.severity for v in vulns]
    assert Severity.CRITICAL in severities or Severity.HIGH in severities


# ============================================================================
# Edge Case Tests
# ============================================================================


@pytest.mark.asyncio
async def test_empty_file(detector):
    """Test that empty files don't cause errors."""
    vulns = await detector.detect(Path("empty.html"), "", "html")
    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_whitespace_only(detector):
    """Test that whitespace-only files don't cause errors."""
    content = "   \n\n   \t\t\n   "
    vulns = await detector.detect(Path("whitespace.html"), content, "html")
    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_line_number_accuracy(detector):
    """Test that line numbers are reported accurately."""
    content = """line 1
line 2
line 3
element.innerHTML = userData;  // line 4
line 5
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 1
    assert vulns[0].line_number == 4


@pytest.mark.asyncio
async def test_code_snippet_captured(detector):
    """Test that code snippets are captured correctly."""
    content = """
element.innerHTML = dangerousContent;
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 1
    assert "innerHTML" in vulns[0].code_snippet
    assert "dangerousContent" in vulns[0].code_snippet


@pytest.mark.asyncio
async def test_case_insensitive_detection(detector):
    """Test that detection is case insensitive where appropriate."""
    content = """
element.INNERHTML = userInput;
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 1


@pytest.mark.asyncio
async def test_multiline_html_tag(detector):
    """Test detection across multiline HTML tags."""
    content = """
<button
    onclick="handleClick()"
    class="btn">
    Click me
</button>
"""
    vulns = await detector.detect(Path("test.html"), content, "html")

    # Should detect onclick on line 2
    assert len(vulns) == 1
    assert vulns[0].line_number == 2


# ============================================================================
# Metadata Tests
# ============================================================================


def test_detector_name(detector):
    """Test that detector has correct name."""
    assert detector.name == "XSSDetector"


def test_detector_enabled_by_default(detector):
    """Test that detector is enabled by default."""
    assert detector.enabled is True


@pytest.mark.asyncio
async def test_vulnerability_metadata_dom_xss(detector):
    """Test that DOM XSS vulnerabilities have complete metadata."""
    content = "element.innerHTML = userInput;"
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 1
    vuln = vulns[0]

    # Check all required fields
    assert vuln.type == VulnerabilityType.XSS
    assert vuln.title is not None
    assert "DOM-Based" in vuln.title
    assert vuln.description is not None
    assert len(vuln.description) > 100  # Detailed description
    assert vuln.severity == Severity.HIGH
    assert vuln.confidence == Confidence.HIGH
    assert vuln.cwe_id == "CWE-79"
    assert vuln.cvss_score == 7.4
    assert vuln.remediation is not None
    assert len(vuln.remediation) > 100  # Detailed remediation
    assert len(vuln.references) >= 3  # Multiple references
    assert vuln.detector == "XSSDetector"
    assert vuln.engine == "static"
    assert len(vuln.mitre_attack_ids) > 0
    assert "T1189" in vuln.mitre_attack_ids


@pytest.mark.asyncio
async def test_vulnerability_metadata_javascript_protocol(detector):
    """Test that JavaScript protocol vulnerabilities have CRITICAL severity."""
    content = '<a href="javascript:alert()">Link</a>'
    vulns = await detector.detect(Path("test.html"), content, "html")

    assert len(vulns) == 1
    vuln = vulns[0]

    assert vuln.severity == Severity.CRITICAL
    assert vuln.cvss_score == 8.2
    assert "JavaScript Protocol" in vuln.title


@pytest.mark.asyncio
async def test_vulnerability_remediation_content(detector):
    """Test that remediation guidance is comprehensive."""
    content = "element.innerHTML = userInput;"
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 1
    remediation = vulns[0].remediation

    # Check for key remediation steps
    assert "sanitize" in remediation.lower()
    assert "validate" in remediation.lower()
    assert "CSP" in remediation or "Content Security Policy" in remediation
    assert "DOMPurify" in remediation
    assert "textContent" in remediation or "innerText" in remediation


@pytest.mark.asyncio
async def test_vulnerability_references(detector):
    """Test that vulnerabilities include proper references."""
    content = "element.innerHTML = userInput;"
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 1
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
async def test_comprehensive_xss_detection(detector):
    """Test detection of all pattern types in a realistic file."""
    content = """
<!DOCTYPE html>
<html>
<head>
    <script>
        // DOM XSS
        function displayName(name) {
            document.getElementById('user').innerHTML = name;
        }

        // jQuery XSS
        function showMessage(msg) {
            $('#message').html(msg);
        }

        // JavaScript protocol
        function redirect() {
            location.href = "javascript:void(0)";
        }
    </script>
</head>
<body onload="init()">
    <!-- Event handler XSS -->
    <button onclick="handleClick()">Click</button>

    <!-- Template XSS -->
    {{ user_content | safe }}
</body>
</html>
"""
    vulns = await detector.detect(Path("page.html"), content, "html")

    # Should detect: innerHTML, .html(), javascript:, onload, onclick, |safe
    assert len(vulns) >= 5
    assert all(v.type == VulnerabilityType.XSS for v in vulns)

    # Check variety of severity levels
    severities = {v.severity for v in vulns}
    assert len(severities) >= 2  # Should have HIGH and CRITICAL or MEDIUM


@pytest.mark.asyncio
async def test_react_component_xss(detector):
    """Test XSS detection in React components."""
    content = """
import React from 'react';

const UserProfile = ({ user }) => {
    return (
        <div>
            <h1>{user.name}</h1>
            <div dangerouslySetInnerHTML={{__html: user.bio}} />
        </div>
    );
};
"""
    vulns = await detector.detect(Path("UserProfile.jsx"), content, "jsx")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.HIGH
    assert "React" in vulns[0].title


@pytest.mark.asyncio
async def test_vue_component_xss(detector):
    """Test XSS detection in Vue components."""
    content = """
<template>
    <div>
        <h1>{{ user.name }}</h1>
        <div v-html="user.bio"></div>
    </div>
</template>
"""
    vulns = await detector.detect(Path("UserProfile.vue"), content, "vue")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.HIGH
    assert "Vue" in vulns[0].title


@pytest.mark.asyncio
async def test_python_template_xss(detector):
    """Test XSS detection in Python templates."""
    content = """
{% extends "base.html" %}

{% block content %}
    <h1>{{ user.username }}</h1>
    <div>{{ user.bio | safe }}</div>
{% endblock %}
"""
    vulns = await detector.detect(Path("profile.html"), content, "html")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.MEDIUM
    assert "Template" in vulns[0].title
