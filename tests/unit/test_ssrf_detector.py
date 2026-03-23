"""Tests for SSRFDetector."""
import pytest
from pathlib import Path

from mcp_sentinel.detectors.ssrf import SSRFDetector
from mcp_sentinel.models.vulnerability import Severity, VulnerabilityType


@pytest.fixture
def detector():
    return SSRFDetector()


# ---------------------------------------------------------------------------
# Python HTTP clients
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detect_requests_get_variable(detector):
    content = 'response = requests.get(url, timeout=30)'
    vulns = await detector.detect(Path("tool.py"), content)
    assert any(v.type == VulnerabilityType.SSRF for v in vulns)


@pytest.mark.asyncio
async def test_detect_requests_post_variable(detector):
    content = 'resp = requests.post(target_url, json=data)'
    vulns = await detector.detect(Path("tool.py"), content)
    assert any(v.type == VulnerabilityType.SSRF for v in vulns)


@pytest.mark.asyncio
async def test_detect_httpx_get_variable(detector):
    content = 'result = httpx.get(endpoint)'
    vulns = await detector.detect(Path("tool.py"), content)
    assert any(v.type == VulnerabilityType.SSRF for v in vulns)


@pytest.mark.asyncio
async def test_detect_urllib_urlopen_variable(detector):
    content = 'response = urllib.request.urlopen(user_url)'
    vulns = await detector.detect(Path("tool.py"), content)
    assert any(v.type == VulnerabilityType.SSRF for v in vulns)


@pytest.mark.asyncio
async def test_detect_aiohttp_get_variable(detector):
    content = 'async with aiohttp.ClientSession() as session:\n    resp = await session.get(url)'
    vulns = await detector.detect(Path("tool.py"), content)
    assert any(v.type == VulnerabilityType.SSRF for v in vulns)


# ---------------------------------------------------------------------------
# JavaScript/TypeScript
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detect_fetch_variable(detector):
    content = 'const response = await fetch(userUrl);'
    vulns = await detector.detect(Path("tool.js"), content)
    assert any(v.type == VulnerabilityType.SSRF for v in vulns)


@pytest.mark.asyncio
async def test_detect_axios_get_variable(detector):
    content = 'const data = await axios.get(targetUrl);'
    vulns = await detector.detect(Path("tool.ts"), content)
    assert any(v.type == VulnerabilityType.SSRF for v in vulns)


# ---------------------------------------------------------------------------
# Cloud metadata endpoints
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detect_aws_imds(detector):
    content = 'url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"'
    vulns = await detector.detect(Path("cloud.py"), content)
    assert any(v.type == VulnerabilityType.SSRF and v.severity == Severity.CRITICAL for v in vulns)


@pytest.mark.asyncio
async def test_detect_gcp_metadata(detector):
    content = 'endpoint = "http://metadata.google.internal/computeMetadata/v1/instance/"'
    vulns = await detector.detect(Path("cloud.py"), content)
    assert any(v.type == VulnerabilityType.SSRF and v.severity == Severity.CRITICAL for v in vulns)


@pytest.mark.asyncio
async def test_detect_ecs_metadata(detector):
    content = 'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI = "http://169.254.170.2/v2/credentials"'
    vulns = await detector.detect(Path("cloud.py"), content)
    assert any(v.type == VulnerabilityType.SSRF for v in vulns)


# ---------------------------------------------------------------------------
# Redirect/callback params
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detect_redirect_uri_param(detector):
    content = 'redirect_uri = request.args.get("redirect_uri")'
    vulns = await detector.detect(Path("auth.py"), content)
    assert any(v.type == VulnerabilityType.SSRF for v in vulns)


@pytest.mark.asyncio
async def test_detect_webhook_url_param(detector):
    content = '"webhook_url": {"type": "string", "description": "URL to send notifications"}'
    vulns = await detector.detect(Path("schema.json"), content)
    assert any(v.type == VulnerabilityType.SSRF for v in vulns)


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detect_go_http_get_variable(detector):
    content = 'resp, err := http.Get(targetURL)'
    vulns = await detector.detect(Path("tool.go"), content)
    assert any(v.type == VulnerabilityType.SSRF for v in vulns)


@pytest.mark.asyncio
async def test_detect_go_http_new_request(detector):
    content = 'req, _ := http.NewRequest("GET", userURL, nil)'
    vulns = await detector.detect(Path("tool.go"), content)
    assert any(v.type == VulnerabilityType.SSRF for v in vulns)


# ---------------------------------------------------------------------------
# Java
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detect_java_url_open(detector):
    content = 'URLConnection conn = new URL(userInput).openConnection();'
    vulns = await detector.detect(Path("Tool.java"), content)
    assert any(v.type == VulnerabilityType.SSRF for v in vulns)


# ---------------------------------------------------------------------------
# False positive suppression
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_false_positive_literal_url(detector):
    content = 'response = requests.get("https://api.example.com/data")'
    vulns = await detector.detect(Path("tool.py"), content)
    ssrf = [v for v in vulns if v.type == VulnerabilityType.SSRF]
    assert len(ssrf) == 0


@pytest.mark.asyncio
async def test_no_false_positive_comment(detector):
    content = '# requests.get(url) should be validated first'
    vulns = await detector.detect(Path("tool.py"), content)
    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_no_false_positive_fetch_literal(detector):
    content = 'const data = await fetch("https://api.example.com/users");'
    vulns = await detector.detect(Path("tool.js"), content)
    ssrf = [v for v in vulns if v.type == VulnerabilityType.SSRF]
    assert len(ssrf) == 0


# ---------------------------------------------------------------------------
# is_applicable
# ---------------------------------------------------------------------------

def test_applicable_python(detector):
    assert detector.is_applicable(Path("tool.py")) is True

def test_applicable_javascript(detector):
    assert detector.is_applicable(Path("tool.js")) is True

def test_applicable_typescript(detector):
    assert detector.is_applicable(Path("tool.ts")) is True

def test_applicable_go(detector):
    assert detector.is_applicable(Path("tool.go")) is True

def test_applicable_java(detector):
    assert detector.is_applicable(Path("Tool.java")) is True

def test_not_applicable_yaml(detector):
    assert detector.is_applicable(Path("config.yaml")) is False

def test_not_applicable_markdown(detector):
    assert detector.is_applicable(Path("README.md")) is False
