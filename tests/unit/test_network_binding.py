"""Tests for NetworkBindingDetector."""
import pytest
from pathlib import Path

from mcp_sentinel.detectors.network_binding import NetworkBindingDetector
from mcp_sentinel.models.vulnerability import VulnerabilityType


@pytest.fixture
def detector():
    return NetworkBindingDetector()


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detect_flask_app_run_wildcard(detector):
    content = 'app.run(host="0.0.0.0", port=8080, debug=False)'
    vulns = await detector.detect(Path("server.py"), content)
    assert any(v.type == VulnerabilityType.NETWORK_BINDING for v in vulns)


@pytest.mark.asyncio
async def test_detect_uvicorn_run_wildcard(detector):
    content = 'uvicorn.run(app, host="0.0.0.0", port=8000)'
    vulns = await detector.detect(Path("main.py"), content)
    assert any(v.type == VulnerabilityType.NETWORK_BINDING for v in vulns)


@pytest.mark.asyncio
async def test_detect_host_kwarg_wildcard(detector):
    content = 'server = Server(host="0.0.0.0", port=9000)'
    vulns = await detector.detect(Path("server.py"), content)
    assert any(v.type == VulnerabilityType.NETWORK_BINDING for v in vulns)


# ---------------------------------------------------------------------------
# JavaScript / TypeScript
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detect_express_listen_wildcard(detector):
    content = 'server.listen(3000, "0.0.0.0", () => console.log("running"));'
    vulns = await detector.detect(Path("server.js"), content)
    assert any(v.type == VulnerabilityType.NETWORK_BINDING for v in vulns)


@pytest.mark.asyncio
async def test_detect_hostname_wildcard(detector):
    content = 'const hostname = "0.0.0.0";'
    vulns = await detector.detect(Path("server.ts"), content)
    assert any(v.type == VulnerabilityType.NETWORK_BINDING for v in vulns)


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detect_go_net_listen_explicit_wildcard(detector):
    content = 'ln, err := net.Listen("tcp", "0.0.0.0:8080")'
    vulns = await detector.detect(Path("server.go"), content)
    assert any(v.type == VulnerabilityType.NETWORK_BINDING for v in vulns)


@pytest.mark.asyncio
async def test_detect_go_net_listen_shorthand(detector):
    # ":8080" in Go binds to 0.0.0.0
    content = 'ln, err := net.Listen("tcp", ":8080")'
    vulns = await detector.detect(Path("server.go"), content)
    assert any(v.type == VulnerabilityType.NETWORK_BINDING for v in vulns)


@pytest.mark.asyncio
async def test_detect_go_listen_and_serve_shorthand(detector):
    content = 'log.Fatal(http.ListenAndServe(":8080", mux))'
    vulns = await detector.detect(Path("server.go"), content)
    assert any(v.type == VulnerabilityType.NETWORK_BINDING for v in vulns)


@pytest.mark.asyncio
async def test_go_shorthand_note_in_description(detector):
    content = 'ln, err := net.Listen("tcp", ":9000")'
    vulns = await detector.detect(Path("server.go"), content)
    binding_vulns = [v for v in vulns if v.type == VulnerabilityType.NETWORK_BINDING]
    assert len(binding_vulns) > 0
    assert "0.0.0.0" in binding_vulns[0].description or "all interface" in binding_vulns[0].description


# ---------------------------------------------------------------------------
# Config files
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detect_env_bind_host(detector):
    content = 'BIND_HOST=0.0.0.0\nPORT=8080'
    vulns = await detector.detect(Path(".env"), content)
    assert any(v.type == VulnerabilityType.NETWORK_BINDING for v in vulns)


@pytest.mark.asyncio
async def test_detect_env_host(detector):
    content = 'HOST=0.0.0.0'
    vulns = await detector.detect(Path(".env"), content)
    assert any(v.type == VulnerabilityType.NETWORK_BINDING for v in vulns)


@pytest.mark.asyncio
async def test_detect_yaml_bind_address(detector):
    content = 'bind-address: 0.0.0.0\nport: 8080'
    vulns = await detector.detect(Path("config.yaml"), content)
    assert any(v.type == VulnerabilityType.NETWORK_BINDING for v in vulns)


# ---------------------------------------------------------------------------
# False positive suppression
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_false_positive_localhost(detector):
    content = 'app.run(host="127.0.0.1", port=8080)'
    vulns = await detector.detect(Path("server.py"), content)
    binding = [v for v in vulns if v.type == VulnerabilityType.NETWORK_BINDING]
    assert len(binding) == 0


@pytest.mark.asyncio
async def test_no_false_positive_specific_ip(detector):
    content = 'app.run(host="10.0.1.5", port=8080)'
    vulns = await detector.detect(Path("server.py"), content)
    binding = [v for v in vulns if v.type == VulnerabilityType.NETWORK_BINDING]
    assert len(binding) == 0


@pytest.mark.asyncio
async def test_no_false_positive_comment(detector):
    content = '# app.run(host="0.0.0.0")  # for docker use'
    vulns = await detector.detect(Path("server.py"), content)
    binding = [v for v in vulns if v.type == VulnerabilityType.NETWORK_BINDING]
    assert len(binding) == 0


# ---------------------------------------------------------------------------
# Remediation content
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_remediation_mentions_localhost(detector):
    content = 'app.run(host="0.0.0.0", port=5000)'
    vulns = await detector.detect(Path("server.py"), content)
    binding = [v for v in vulns if v.type == VulnerabilityType.NETWORK_BINDING]
    assert len(binding) > 0
    assert "127.0.0.1" in binding[0].remediation


# ---------------------------------------------------------------------------
# is_applicable
# ---------------------------------------------------------------------------

def test_applicable_python(detector):
    assert detector.is_applicable(Path("server.py")) is True

def test_applicable_go(detector):
    assert detector.is_applicable(Path("server.go")) is True

def test_applicable_env(detector):
    assert detector.is_applicable(Path(".env")) is True

def test_applicable_yaml(detector):
    assert detector.is_applicable(Path("config.yaml")) is True

def test_applicable_javascript(detector):
    assert detector.is_applicable(Path("server.js")) is True

def test_not_applicable_markdown(detector):
    assert detector.is_applicable(Path("README.md")) is False
