"""Tests for MCPSamplingDetector."""

import pytest
from pathlib import Path

from mcp_sentinel.detectors.mcp_sampling import MCPSamplingDetector
from mcp_sentinel.models.vulnerability import Severity, VulnerabilityType


@pytest.fixture
def detector():
    return MCPSamplingDetector()


# ---------------------------------------------------------------------------
# Basic sampling call detection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_detect_create_message_python(detector):
    content = "result = await session.create_message(messages=messages)"
    vulns = await detector.detect(Path("server.py"), content, "python")
    assert len(vulns) >= 1
    assert any(v.type == VulnerabilityType.MCP_SAMPLING for v in vulns)


@pytest.mark.asyncio
async def test_detect_create_message_js(detector):
    content = "const resp = await client.createMessage({ messages });"
    vulns = await detector.detect(Path("server.ts"), content, "typescript")
    assert len(vulns) >= 1
    assert any(v.type == VulnerabilityType.MCP_SAMPLING for v in vulns)


@pytest.mark.asyncio
async def test_detect_sampling_json_rpc(detector):
    content = 'method = "sampling/createMessage"'
    vulns = await detector.detect(Path("handler.py"), content, "python")
    assert len(vulns) >= 1


# ---------------------------------------------------------------------------
# Prompt injection via sampling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_detect_prompt_injection_fstring(detector):
    content = (
        'await session.create_message(messages=[{"role": "user", "content": f"Answer: {user_input}"}])'
    )
    vulns = await detector.detect(Path("tools.py"), content, "python")
    assert len(vulns) >= 1
    pi_vulns = [v for v in vulns if "Prompt Injection" in v.title]
    assert len(pi_vulns) >= 1
    assert pi_vulns[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_detect_prompt_injection_concat(detector):
    content = 'create_message(messages=[{"role": "user", "content": "Query: " + user_input}])'
    vulns = await detector.detect(Path("tools.py"), content, "python")
    assert len(vulns) >= 1
    pi_vulns = [v for v in vulns if "Prompt Injection" in v.title]
    assert len(pi_vulns) >= 1


# ---------------------------------------------------------------------------
# Sensitive data in sampling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_detect_password_in_sampling(detector):
    content = 'await session.create_message(messages=[{"content": password}])'
    vulns = await detector.detect(Path("auth.py"), content, "python")
    assert len(vulns) >= 1
    sensitive_vulns = [v for v in vulns if "Sensitive Data" in v.title]
    assert len(sensitive_vulns) >= 1
    assert sensitive_vulns[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_detect_token_in_sampling(detector):
    content = 'await session.create_message(messages=[{"content": api_key}])'
    vulns = await detector.detect(Path("integration.py"), content, "python")
    assert len(vulns) >= 1
    sensitive_vulns = [v for v in vulns if "Sensitive Data" in v.title]
    assert len(sensitive_vulns) >= 1


@pytest.mark.asyncio
async def test_detect_env_secret_in_sampling(detector):
    content = 'create_message(messages=[{"content": os.environ["SECRET"]}])'
    vulns = await detector.detect(Path("server.py"), content, "python")
    assert len(vulns) >= 1
    sensitive_vulns = [v for v in vulns if "Sensitive Data" in v.title]
    assert len(sensitive_vulns) >= 1


@pytest.mark.asyncio
async def test_detect_process_env_in_sampling_js(detector):
    content = 'client.createMessage({ messages: [{ content: process.env.SECRET }] });'
    vulns = await detector.detect(Path("server.js"), content, "javascript")
    assert len(vulns) >= 1
    sensitive_vulns = [v for v in vulns if "Sensitive Data" in v.title]
    assert len(sensitive_vulns) >= 1


# ---------------------------------------------------------------------------
# Unconstrained sampling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_detect_very_high_max_tokens(detector):
    content = "max_tokens = 500000"
    vulns = await detector.detect(Path("config.py"), content, "python")
    assert len(vulns) >= 1
    unconstrained = [v for v in vulns if "Unconstrained" in v.title]
    assert len(unconstrained) >= 1
    assert unconstrained[0].severity == Severity.LOW


@pytest.mark.asyncio
async def test_detect_very_high_max_tokens_js(detector):
    content = "const opts = { maxTokens: 200000 };"
    vulns = await detector.detect(Path("server.js"), content, "javascript")
    assert len(vulns) >= 1
    unconstrained = [v for v in vulns if "Unconstrained" in v.title]
    assert len(unconstrained) >= 1


# ---------------------------------------------------------------------------
# OWASP ASI annotation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_owasp_annotation(detector):
    content = "result = await session.create_message(messages=messages)"
    vulns = await detector.detect(Path("server.py"), content, "python")
    assert len(vulns) >= 1
    assert vulns[0].owasp_asi_id == "ASI10"
    assert vulns[0].owasp_asi_name == "Inadequate Audit and Monitoring"


# ---------------------------------------------------------------------------
# Non-applicable files
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_not_applicable_yaml(detector):
    assert not detector.is_applicable(Path("config.yaml"), "yaml")


@pytest.mark.asyncio
async def test_not_applicable_go(detector):
    assert not detector.is_applicable(Path("main.go"), "go")


@pytest.mark.asyncio
async def test_applicable_python(detector):
    assert detector.is_applicable(Path("server.py"), "python")


@pytest.mark.asyncio
async def test_applicable_javascript(detector):
    assert detector.is_applicable(Path("index.js"), "javascript")


# ---------------------------------------------------------------------------
# No false positives
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_fp_safe_sampling_reference(detector):
    """A comment mentioning createMessage should not trigger."""
    content = "# See create_message() docs for proper usage"
    vulns = await detector.detect(Path("docs.py"), content, "python")
    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_no_fp_unrelated_message(detector):
    content = "logger.info('Processing message')"
    vulns = await detector.detect(Path("server.py"), content, "python")
    assert len(vulns) == 0
