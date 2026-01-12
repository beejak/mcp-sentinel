"""
Tests for SecretsDetector.
"""

import pytest
from pathlib import Path

from mcp_sentinel.detectors.secrets import SecretsDetector
from mcp_sentinel.models.vulnerability import Severity, VulnerabilityType


@pytest.mark.asyncio
async def test_detect_aws_access_key():
    """Test detection of AWS access keys."""
    detector = SecretsDetector()

    content = 'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"'
    file_path = Path("test.py")

    vulns = await detector.detect(file_path, content)

    assert len(vulns) == 1
    assert vulns[0].type == VulnerabilityType.SECRET_EXPOSURE
    assert vulns[0].severity == Severity.CRITICAL
    assert "AWS Access Key" in vulns[0].title


@pytest.mark.asyncio
async def test_detect_openai_api_key():
    """Test detection of OpenAI API keys."""
    detector = SecretsDetector()

    content = 'OPENAI_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"'
    file_path = Path("config.py")

    vulns = await detector.detect(file_path, content)

    assert len(vulns) >= 1
    assert any("OpenAI" in v.title for v in vulns)


@pytest.mark.asyncio
async def test_detect_anthropic_api_key():
    """Test detection of Anthropic Claude API keys."""
    detector = SecretsDetector()

    content = '''
API_KEY = "sk-ant-api03-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuv"
'''
    file_path = Path("config.py")

    vulns = await detector.detect(file_path, content)

    assert len(vulns) >= 1
    assert any("Anthropic" in v.title for v in vulns)


@pytest.mark.asyncio
async def test_detect_private_key():
    """Test detection of private keys."""
    detector = SecretsDetector()

    content = '''
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890...
-----END RSA PRIVATE KEY-----
'''
    file_path = Path("key.pem")

    vulns = await detector.detect(file_path, content)

    assert len(vulns) >= 1
    assert any("Private Key" in v.title for v in vulns)
    assert vulns[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_detect_database_url():
    """Test detection of database URLs with credentials."""
    detector = SecretsDetector()

    content = 'DATABASE_URL = "postgres://user:password123@localhost:5432/mydb"'
    file_path = Path("settings.py")

    vulns = await detector.detect(file_path, content)

    assert len(vulns) >= 1
    assert any("PostgreSQL" in v.title or "connection" in v.title.lower() for v in vulns)


@pytest.mark.asyncio
async def test_ignore_placeholders():
    """Test that placeholder values are ignored."""
    detector = SecretsDetector()

    content = '''
API_KEY = "your_api_key_here"
SECRET = "placeholder_secret"
TOKEN = "example_token"
'''
    file_path = Path("example.py")

    vulns = await detector.detect(file_path, content)

    # Should not detect placeholders
    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_line_number_tracking():
    """Test that line numbers are correctly tracked."""
    detector = SecretsDetector()

    content = '''line 1
line 2
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
line 4
'''
    file_path = Path("test.py")

    vulns = await detector.detect(file_path, content)

    assert len(vulns) == 1
    assert vulns[0].line_number == 3


@pytest.mark.asyncio
async def test_multiple_secrets_in_file():
    """Test detection of multiple secrets in one file."""
    detector = SecretsDetector()

    content = '''
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
OPENAI_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
'''
    file_path = Path("secrets.py")

    vulns = await detector.detect(file_path, content)

    # Should detect all three secrets
    assert len(vulns) >= 3
