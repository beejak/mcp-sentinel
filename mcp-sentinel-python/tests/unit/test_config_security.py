"""
Unit tests for ConfigSecurityDetector.

Tests all 8 configuration security pattern categories.
"""

import pytest
from pathlib import Path
from typing import List

from mcp_sentinel.detectors.config_security import ConfigSecurityDetector
from mcp_sentinel.models.vulnerability import (
    Vulnerability,
    VulnerabilityType,
    Severity,
    Confidence,
)


@pytest.fixture
def detector():
    """Create a ConfigSecurityDetector instance for testing."""
    return ConfigSecurityDetector()


# ============================================================================
# Pattern 1: Debug Mode Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_debug_true_python(detector):
    """Test detection of DEBUG = True in Python."""
    content = """
DEBUG = True
SECRET_KEY = 'my-secret'
"""
    vulns = await detector.detect(Path("settings.py"), content, "python")

    assert len(vulns) >= 1
    debug_vulns = [v for v in vulns if "Debug Mode" in v.title]
    assert len(debug_vulns) == 1
    assert debug_vulns[0].type == VulnerabilityType.CONFIG_SECURITY
    assert debug_vulns[0].severity == Severity.HIGH
    assert debug_vulns[0].confidence == Confidence.HIGH
    assert debug_vulns[0].cwe_id == "CWE-489"
    assert debug_vulns[0].cvss_score == 7.5
    assert "T1082" in debug_vulns[0].mitre_attack_ids


@pytest.mark.asyncio
async def test_detect_debug_yaml(detector):
    """Test detection of debug: true in YAML."""
    content = """
app:
  debug: true
  port: 3000
"""
    vulns = await detector.detect(Path("config.yaml"), content, "yaml")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.HIGH
    assert "debug: true" in vulns[0].code_snippet.lower()


@pytest.mark.asyncio
async def test_detect_node_env_development(detector):
    """Test detection of NODE_ENV=development."""
    content = """
NODE_ENV = "development"
PORT = 3000
"""
    vulns = await detector.detect(Path(".env"), content)

    assert len(vulns) == 1


@pytest.mark.asyncio
async def test_detect_flask_debug(detector):
    """Test detection of app.debug = True."""
    content = """
from flask import Flask
app = Flask(__name__)
app.debug = True
"""
    vulns = await detector.detect(Path("app.py"), content, "python")

    # May match multiple patterns
    assert len(vulns) >= 1
    assert any("Debug" in v.title for v in vulns)


# ============================================================================
# Pattern 2: Weak Authentication Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_auth_disabled(detector):
    """Test detection of auth = False."""
    content = """
config = {
    'auth': False,
    'port': 8080
}
"""
    vulns = await detector.detect(Path("config.py"), content, "python")

    assert len(vulns) >= 1
    auth_vulns = [v for v in vulns if "Authentication" in v.title]
    assert len(auth_vulns) == 1
    assert auth_vulns[0].severity == Severity.CRITICAL
    assert auth_vulns[0].cwe_id == "CWE-306"
    assert auth_vulns[0].cvss_score == 9.8


@pytest.mark.asyncio
async def test_detect_weak_password(detector):
    """Test detection of weak default password."""
    content = """
database:
  password: "admin"
  host: localhost
"""
    vulns = await detector.detect(Path("config.yaml"), content, "yaml")

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_detect_allow_anonymous(detector):
    """Test detection of ALLOW_ANONYMOUS = True."""
    content = """
ALLOW_ANONYMOUS = True
REQUIRE_AUTH = False
"""
    vulns = await detector.detect(Path("settings.py"), content, "python")

    assert len(vulns) >= 1


# ============================================================================
# Pattern 3: Insecure CORS Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_cors_wildcard_header(detector):
    """Test detection of Access-Control-Allow-Origin: *."""
    content = """
headers = {
    'Access-Control-Allow-Origin': '*',
    'Content-Type': 'application/json'
}
"""
    vulns = await detector.detect(Path("server.py"), content, "python")

    assert len(vulns) >= 1
    cors_vulns = [v for v in vulns if "CORS" in v.title]
    assert len(cors_vulns) == 1
    assert cors_vulns[0].severity == Severity.HIGH
    assert cors_vulns[0].cwe_id == "CWE-942"
    assert cors_vulns[0].cvss_score == 7.4


@pytest.mark.asyncio
async def test_detect_cors_origins_wildcard(detector):
    """Test detection of CORS_ORIGINS = ['*']."""
    content = """
CORS_ORIGINS = ['*']
ALLOWED_METHODS = ['GET', 'POST']
"""
    vulns = await detector.detect(Path("config.py"), content, "python")

    assert len(vulns) == 1


@pytest.mark.asyncio
async def test_detect_cors_function_wildcard(detector):
    """Test detection of cors(*)."""
    content = """
app.use(cors(*))
"""
    vulns = await detector.detect(Path("server.js"), content, "javascript")

    assert len(vulns) == 1


# ============================================================================
# Pattern 4: Security Headers Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_xframe_options_allow(detector):
    """Test detection of weak X-Frame-Options."""
    content = """
headers = {
    'X-Frame-Options': 'ALLOWALL'
}
"""
    vulns = await detector.detect(Path("config.py"), content, "python")

    assert len(vulns) >= 1
    header_vulns = [v for v in vulns if "Security Headers" in v.title]
    assert len(header_vulns) == 1
    assert header_vulns[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_detect_hsts_disabled(detector):
    """Test detection of HSTS = False."""
    content = """
HSTS = False
USE_HTTPS = True
"""
    vulns = await detector.detect(Path("settings.py"), content, "python")

    assert len(vulns) == 1


@pytest.mark.asyncio
async def test_detect_unsafe_csp(detector):
    """Test detection of unsafe CSP."""
    content = """
Content-Security-Policy: "unsafe-inline unsafe-eval"
"""
    vulns = await detector.detect(Path("nginx.conf"), content, "config")

    assert len(vulns) == 1


# ============================================================================
# Pattern 5: Weak Secrets Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_weak_secret_key(detector):
    """Test detection of weak SECRET_KEY."""
    content = """
SECRET_KEY = 'secret'
DATABASE_URL = 'postgresql://localhost/db'
"""
    vulns = await detector.detect(Path("settings.py"), content, "python")

    assert len(vulns) >= 1
    secret_vulns = [v for v in vulns if "Secret" in v.title]
    assert len(secret_vulns) == 1
    assert secret_vulns[0].severity == Severity.CRITICAL
    assert secret_vulns[0].cwe_id == "CWE-798"
    assert secret_vulns[0].cvss_score == 9.1


@pytest.mark.asyncio
async def test_detect_insecure_cookie(detector):
    """Test detection of SESSION_COOKIE_SECURE = False."""
    content = """
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False
"""
    vulns = await detector.detect(Path("config.py"), content, "python")

    assert len(vulns) >= 1


@pytest.mark.asyncio
async def test_detect_weak_session_secret(detector):
    """Test detection of weak session secret."""
    content = """
session_secret = "password"
"""
    vulns = await detector.detect(Path("app.js"), content, "javascript")

    assert len(vulns) == 1


# ============================================================================
# Pattern 6: Rate Limiting Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_rate_limit_disabled(detector):
    """Test detection of rate_limit = None."""
    content = """
config = {
    'rate_limit': None,
    'timeout': 30
}
"""
    vulns = await detector.detect(Path("config.py"), content, "python")

    assert len(vulns) >= 1
    rate_vulns = [v for v in vulns if "Rate Limiting" in v.title]
    assert len(rate_vulns) == 1
    assert rate_vulns[0].severity == Severity.MEDIUM
    assert rate_vulns[0].cwe_id == "CWE-770"


@pytest.mark.asyncio
async def test_detect_rate_limit_false(detector):
    """Test detection of RATE_LIMIT = False."""
    content = """
RATE_LIMIT = False
THROTTLE = False
"""
    vulns = await detector.detect(Path("settings.py"), content, "python")

    assert len(vulns) >= 1


@pytest.mark.asyncio
async def test_detect_disabled_rate_limit(detector):
    """Test detection of disable_rate_limit = True."""
    content = """
disable_rate_limit = True
"""
    vulns = await detector.detect(Path("config.py"), content, "python")

    assert len(vulns) == 1


# ============================================================================
# Pattern 7: Insecure SSL/TLS Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_ssl_verify_false(detector):
    """Test detection of SSL_VERIFY = False."""
    content = """
import requests
response = requests.get(url, verify=False)
"""
    vulns = await detector.detect(Path("client.py"), content, "python")

    # Note: This might also match as insecure SSL
    ssl_vulns = [v for v in vulns if "SSL" in v.title or "TLS" in v.title]
    assert len(ssl_vulns) >= 1
    assert ssl_vulns[0].severity == Severity.HIGH
    assert ssl_vulns[0].cwe_id == "CWE-327"


@pytest.mark.asyncio
async def test_detect_weak_tls_version(detector):
    """Test detection of weak TLS version."""
    content = """
TLS_VERSION = "1.0"
"""
    vulns = await detector.detect(Path("config.py"), content, "python")

    assert len(vulns) == 1


@pytest.mark.asyncio
async def test_detect_check_hostname_false(detector):
    """Test detection of check_hostname = False."""
    content = """
ssl_context.check_hostname = False
"""
    vulns = await detector.detect(Path("server.py"), content, "python")

    assert len(vulns) == 1


# ============================================================================
# Pattern 8: Exposed Endpoints Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_debug_endpoint(detector):
    """Test detection of /debug endpoint."""
    content = """
@app.route('/debug')
def debug_view():
    return render_template('debug.html')
"""
    vulns = await detector.detect(Path("views.py"), content, "python")

    assert len(vulns) >= 1
    endpoint_vulns = [v for v in vulns if "Endpoint" in v.title]
    assert len(endpoint_vulns) == 1
    assert endpoint_vulns[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_detect_admin_endpoint(detector):
    """Test detection of /admin endpoint."""
    content = """
router.get('/admin', adminController)
"""
    vulns = await detector.detect(Path("routes.js"), content, "javascript")

    assert len(vulns) == 1


@pytest.mark.asyncio
async def test_detect_allowed_hosts_wildcard(detector):
    """Test detection of ALLOWED_HOSTS = ['*']."""
    content = """
ALLOWED_HOSTS = ['*']
DEBUG = False
"""
    vulns = await detector.detect(Path("settings.py"), content, "python")

    assert len(vulns) >= 1


# ============================================================================
# File Type Filtering Tests
# ============================================================================


def test_is_applicable_python(detector):
    """Test that detector applies to Python files."""
    assert detector.is_applicable(Path("settings.py"), "python") is True
    assert detector.is_applicable(Path("config.py")) is True
    assert detector.is_applicable(Path("app.py")) is True


def test_is_applicable_config_files(detector):
    """Test that detector applies to configuration files."""
    assert detector.is_applicable(Path(".env"), "env") is True
    assert detector.is_applicable(Path("config.yaml"), "yaml") is True
    assert detector.is_applicable(Path("config.json"), "json") is True
    assert detector.is_applicable(Path("app.toml"), "toml") is True


def test_is_applicable_javascript(detector):
    """Test that detector applies to JavaScript files."""
    assert detector.is_applicable(Path("server.js"), "javascript") is True
    assert detector.is_applicable(Path("app.ts"), "typescript") is True


def test_is_applicable_nginx(detector):
    """Test that detector applies to nginx config."""
    assert detector.is_applicable(Path("nginx.conf")) is True


def test_is_applicable_docker(detector):
    """Test that detector applies to docker-compose."""
    assert detector.is_applicable(Path("docker-compose.yml")) is True


def test_is_applicable_other_files(detector):
    """Test that detector does not apply to non-config files."""
    assert detector.is_applicable(Path("README.md")) is False
    assert detector.is_applicable(Path("test.txt")) is False
    assert detector.is_applicable(Path("image.png")) is False


# ============================================================================
# Comment Filtering Tests
# ============================================================================


@pytest.mark.asyncio
async def test_ignore_python_comments(detector):
    """Test that Python comments are ignored."""
    content = """
# DEBUG = True
# This is a comment
def main():
    pass
"""
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_ignore_javascript_comments(detector):
    """Test that JavaScript comments are ignored."""
    content = """
// DEBUG = true
// app.use(cors(*))
function main() {
    return true;
}
"""
    vulns = await detector.detect(Path("test.js"), content, "javascript")

    assert len(vulns) == 0


# ============================================================================
# False Positive Prevention Tests
# ============================================================================


@pytest.mark.asyncio
async def test_ignore_test_files(detector):
    """Test that test examples are ignored."""
    content = """
# Test example
DEBUG = True  # For testing only
"""
    vulns = await detector.detect(Path("test_config.py"), content, "python")

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_ignore_local_dev_config(detector):
    """Test that local/dev configs are not flagged."""
    content = """
DEBUG = True
"""
    vulns = await detector.detect(Path("settings_local.py"), content, "python")

    # Should not flag debug mode in local config
    debug_vulns = [v for v in vulns if "Debug" in v.title]
    assert len(debug_vulns) == 0


@pytest.mark.asyncio
async def test_ignore_env_vars(detector):
    """Test that environment variable usage is not flagged."""
    content = """
import os
SECRET_KEY = os.environ.get('SECRET_KEY')
"""
    vulns = await detector.detect(Path("settings.py"), content, "python")

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_ignore_nodejs_env_vars(detector):
    """Test that Node.js environment variables are not flagged."""
    content = """
const secret = process.env.SECRET_KEY || 'default';
"""
    vulns = await detector.detect(Path("config.js"), content, "javascript")

    assert len(vulns) == 0


# ============================================================================
# Multiple Vulnerabilities Tests
# ============================================================================


@pytest.mark.asyncio
async def test_multiple_config_issues(detector):
    """Test detection of multiple configuration issues."""
    content = """
DEBUG = True
SECRET_KEY = 'secret'
CORS_ORIGINS = ['*']
auth = False
RATE_LIMIT = 0
"""
    vulns = await detector.detect(Path("settings.py"), content, "python")

    assert len(vulns) >= 4
    assert all(v.type == VulnerabilityType.CONFIG_SECURITY for v in vulns)


@pytest.mark.asyncio
async def test_mixed_severity_issues(detector):
    """Test that different patterns have appropriate severity levels."""
    content = """
DEBUG = True  # HIGH
auth = False  # CRITICAL
HSTS = False  # MEDIUM
"""
    vulns = await detector.detect(Path("config.py"), content, "python")

    assert len(vulns) >= 3
    severities = {v.severity for v in vulns}
    assert Severity.CRITICAL in severities
    assert Severity.HIGH in severities


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
DEBUG = True  # line 3
line 4
"""
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) == 1
    assert vulns[0].line_number == 3


@pytest.mark.asyncio
async def test_code_snippet_captured(detector):
    """Test that code snippets are captured correctly."""
    content = """
DEBUG = True
"""
    vulns = await detector.detect(Path("test.py"), content, "python")

    assert len(vulns) == 1
    assert "DEBUG" in vulns[0].code_snippet


# ============================================================================
# Metadata Tests
# ============================================================================


def test_detector_name(detector):
    """Test that detector has correct name."""
    assert detector.name == "ConfigSecurityDetector"


def test_detector_enabled_by_default(detector):
    """Test that detector is enabled by default."""
    assert detector.enabled is True


@pytest.mark.asyncio
async def test_vulnerability_metadata_debug(detector):
    """Test that debug mode vulnerabilities have complete metadata."""
    content = "DEBUG = True"
    vulns = await detector.detect(Path("settings.py"), content, "python")

    assert len(vulns) == 1
    vuln = vulns[0]

    # Check all required fields
    assert vuln.type == VulnerabilityType.CONFIG_SECURITY
    assert vuln.title is not None
    assert "Debug Mode" in vuln.title
    assert vuln.description is not None
    assert len(vuln.description) > 100
    assert vuln.severity == Severity.HIGH
    assert vuln.confidence == Confidence.HIGH
    assert vuln.cwe_id == "CWE-489"
    assert vuln.cvss_score == 7.5
    assert vuln.remediation is not None
    assert len(vuln.remediation) > 100
    assert len(vuln.references) >= 3
    assert vuln.detector == "ConfigSecurityDetector"
    assert vuln.engine == "static"
    assert len(vuln.mitre_attack_ids) > 0
    assert "T1082" in vuln.mitre_attack_ids


@pytest.mark.asyncio
async def test_vulnerability_metadata_weak_auth(detector):
    """Test that weak auth vulnerabilities have CRITICAL severity."""
    content = "auth = False"
    vulns = await detector.detect(Path("config.py"), content, "python")

    assert len(vulns) == 1
    vuln = vulns[0]

    assert vuln.severity == Severity.CRITICAL
    assert vuln.cvss_score == 9.8
    assert "Authentication" in vuln.title


@pytest.mark.asyncio
async def test_vulnerability_remediation_content(detector):
    """Test that remediation guidance is comprehensive."""
    content = "DEBUG = True"
    vulns = await detector.detect(Path("settings.py"), content, "python")

    assert len(vulns) == 1
    remediation = vulns[0].remediation

    # Check for key remediation steps
    assert "debug" in remediation.lower() or "Debug" in remediation
    assert "production" in remediation.lower()
    assert "environment" in remediation.lower()


@pytest.mark.asyncio
async def test_vulnerability_references(detector):
    """Test that vulnerabilities include proper references."""
    content = "DEBUG = True"
    vulns = await detector.detect(Path("settings.py"), content, "python")

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
async def test_comprehensive_config_detection(detector):
    """Test detection of all pattern types in a realistic config file."""
    content = """
# Django settings for production
DEBUG = True
SECRET_KEY = 'changeme'

# Database
DATABASE_PASSWORD = 'admin'

# Security
auth = False
CORS_ORIGINS = ['*']
SESSION_COOKIE_SECURE = False
HSTS = False
RATE_LIMIT = None
SSL_VERIFY = False

# Routes
ALLOWED_HOSTS = ['*']
"""
    vulns = await detector.detect(Path("settings.py"), content, "python")

    # Should detect multiple issues
    assert len(vulns) >= 7
    assert all(v.type == VulnerabilityType.CONFIG_SECURITY for v in vulns)

    # Check variety of severity levels
    severities = {v.severity for v in vulns}
    assert len(severities) >= 2


@pytest.mark.asyncio
async def test_nodejs_config_detection(detector):
    """Test detection in Node.js configuration."""
    content = """
module.exports = {
  debug: true,
  cors: cors(*),
  rateLimit: false,
  session: {
    secret: 'secret',
    cookie: {
      secure: false
    }
  }
};
"""
    vulns = await detector.detect(Path("config.js"), content, "javascript")

    assert len(vulns) >= 4
