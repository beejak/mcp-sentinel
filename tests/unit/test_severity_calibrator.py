"""
Tests for SeverityCalibrator and MCPContext detection.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_sentinel.engines.static.context_detector import MCPContext, detect_mcp_context
from mcp_sentinel.engines.static.severity_calibrator import SeverityCalibrator
from mcp_sentinel.models.vulnerability import Confidence, Severity, VulnerabilityType


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_vuln(vuln_type: VulnerabilityType, severity: Severity):
    """Create a minimal Vulnerability for testing."""
    from mcp_sentinel.models.vulnerability import Vulnerability

    return Vulnerability(
        type=vuln_type,
        title="Test",
        description="Test vulnerability",
        severity=severity,
        confidence=Confidence.HIGH,
        file_path="test.py",
        line_number=1,
        detector="TestDetector",
        engine="static",
    )


@pytest.fixture
def calibrator():
    return SeverityCalibrator()


@pytest.fixture
def no_context():
    return MCPContext()


@pytest.fixture
def fs_context():
    return MCPContext(has_filesystem_access=True)


@pytest.fixture
def net_context():
    return MCPContext(has_network_access=True)


@pytest.fixture
def stdio_context():
    return MCPContext(is_stdio_transport=True)


@pytest.fixture
def full_context():
    return MCPContext(
        has_filesystem_access=True,
        has_network_access=True,
        is_stdio_transport=True,
        sensitive_tool_names=["delete_file"],
    )


# ---------------------------------------------------------------------------
# No-context: calibrator is a no-op
# ---------------------------------------------------------------------------


def test_no_context_returns_identical(calibrator, no_context):
    vuln = _make_vuln(VulnerabilityType.PATH_TRAVERSAL, Severity.HIGH)
    result = calibrator.calibrate([vuln], no_context)
    assert len(result) == 1
    assert result[0].severity == Severity.HIGH


def test_empty_list_returns_empty(calibrator, no_context):
    assert calibrator.calibrate([], no_context) == []


# ---------------------------------------------------------------------------
# Filesystem access elevation
# ---------------------------------------------------------------------------


def test_fs_access_elevates_path_traversal(calibrator, fs_context):
    vuln = _make_vuln(VulnerabilityType.PATH_TRAVERSAL, Severity.MEDIUM)
    result = calibrator.calibrate([vuln], fs_context)
    assert result[0].severity == Severity.HIGH


def test_fs_access_elevates_code_injection(calibrator, fs_context):
    vuln = _make_vuln(VulnerabilityType.CODE_INJECTION, Severity.HIGH)
    result = calibrator.calibrate([vuln], fs_context)
    assert result[0].severity == Severity.CRITICAL


def test_fs_access_elevates_ssrf(calibrator, fs_context):
    vuln = _make_vuln(VulnerabilityType.SSRF, Severity.MEDIUM)
    result = calibrator.calibrate([vuln], fs_context)
    assert result[0].severity == Severity.HIGH


def test_fs_access_elevates_mcp_sampling(calibrator, fs_context):
    vuln = _make_vuln(VulnerabilityType.MCP_SAMPLING, Severity.MEDIUM)
    result = calibrator.calibrate([vuln], fs_context)
    assert result[0].severity == Severity.HIGH


def test_fs_access_does_not_elevate_weak_crypto(calibrator, fs_context):
    vuln = _make_vuln(VulnerabilityType.WEAK_CRYPTO, Severity.HIGH)
    result = calibrator.calibrate([vuln], fs_context)
    assert result[0].severity == Severity.HIGH  # unchanged


def test_fs_access_does_not_elevate_secrets(calibrator, fs_context):
    vuln = _make_vuln(VulnerabilityType.SECRET_EXPOSURE, Severity.CRITICAL)
    result = calibrator.calibrate([vuln], fs_context)
    assert result[0].severity == Severity.CRITICAL  # unchanged


def test_critical_stays_critical_after_elevation(calibrator, fs_context):
    vuln = _make_vuln(VulnerabilityType.PATH_TRAVERSAL, Severity.CRITICAL)
    result = calibrator.calibrate([vuln], fs_context)
    assert result[0].severity == Severity.CRITICAL  # capped


# ---------------------------------------------------------------------------
# Network access elevation
# ---------------------------------------------------------------------------


def test_net_access_elevates_ssrf(calibrator, net_context):
    vuln = _make_vuln(VulnerabilityType.SSRF, Severity.HIGH)
    result = calibrator.calibrate([vuln], net_context)
    assert result[0].severity == Severity.CRITICAL


def test_net_access_elevates_mcp_sampling(calibrator, net_context):
    vuln = _make_vuln(VulnerabilityType.MCP_SAMPLING, Severity.LOW)
    result = calibrator.calibrate([vuln], net_context)
    assert result[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# STDIO transport: context note added but severity unchanged
# ---------------------------------------------------------------------------


def test_stdio_adds_context_note_to_all_findings(calibrator, stdio_context):
    vulns = [
        _make_vuln(VulnerabilityType.SECRET_EXPOSURE, Severity.CRITICAL),
        _make_vuln(VulnerabilityType.WEAK_CRYPTO, Severity.MEDIUM),
    ]
    result = calibrator.calibrate(vulns, stdio_context)
    for v in result:
        assert "context_note" in v.metadata
        assert "STDIO" in v.metadata["context_note"]


def test_stdio_does_not_change_severity(calibrator, stdio_context):
    vuln = _make_vuln(VulnerabilityType.WEAK_CRYPTO, Severity.MEDIUM)
    result = calibrator.calibrate([vuln], stdio_context)
    assert result[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Sensitive tool names
# ---------------------------------------------------------------------------


def test_sensitive_tools_elevates_path_traversal(calibrator):
    ctx = MCPContext(sensitive_tool_names=["delete_file"])
    vuln = _make_vuln(VulnerabilityType.PATH_TRAVERSAL, Severity.MEDIUM)
    result = calibrator.calibrate([vuln], ctx)
    assert result[0].severity == Severity.HIGH


def test_sensitive_tools_elevates_code_injection(calibrator):
    ctx = MCPContext(sensitive_tool_names=["execute_shell"])
    vuln = _make_vuln(VulnerabilityType.CODE_INJECTION, Severity.MEDIUM)
    result = calibrator.calibrate([vuln], ctx)
    assert result[0].severity == Severity.HIGH


def test_sensitive_tools_does_not_elevate_ssrf(calibrator):
    ctx = MCPContext(sensitive_tool_names=["delete_file"])
    vuln = _make_vuln(VulnerabilityType.SSRF, Severity.MEDIUM)
    result = calibrator.calibrate([vuln], ctx)
    # SSRF is not in _ELEVATE_FOR_SENSITIVE_TOOLS
    assert result[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Combined context: double elevation
# ---------------------------------------------------------------------------


def test_fs_plus_sensitive_tools_double_elevates_path_traversal(calibrator):
    ctx = MCPContext(has_filesystem_access=True, sensitive_tool_names=["rm"])
    vuln = _make_vuln(VulnerabilityType.PATH_TRAVERSAL, Severity.LOW)
    result = calibrator.calibrate([vuln], ctx)
    # LOW -> MEDIUM (fs) -> HIGH (sensitive tools)
    assert result[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Metadata: elevation_reason is set
# ---------------------------------------------------------------------------


def test_elevation_reason_set_in_metadata(calibrator, fs_context):
    vuln = _make_vuln(VulnerabilityType.PATH_TRAVERSAL, Severity.MEDIUM)
    result = calibrator.calibrate([vuln], fs_context)
    assert "elevation_reason" in result[0].metadata
    assert "filesystem" in result[0].metadata["elevation_reason"].lower()


def test_severity_elevated_flag_set(calibrator, fs_context):
    vuln = _make_vuln(VulnerabilityType.CODE_INJECTION, Severity.HIGH)
    result = calibrator.calibrate([vuln], fs_context)
    assert result[0].metadata.get("severity_elevated") is True


# ---------------------------------------------------------------------------
# Original vuln IDs are preserved
# ---------------------------------------------------------------------------


def test_original_id_preserved(calibrator, fs_context):
    vuln = _make_vuln(VulnerabilityType.PATH_TRAVERSAL, Severity.MEDIUM)
    original_id = vuln.id
    result = calibrator.calibrate([vuln], fs_context)
    assert result[0].id == original_id


# ---------------------------------------------------------------------------
# Context detector — MCPContext dataclass
# ---------------------------------------------------------------------------


def test_mcp_context_defaults():
    ctx = MCPContext()
    assert not ctx.has_filesystem_access
    assert not ctx.has_network_access
    assert not ctx.is_stdio_transport
    assert ctx.sensitive_tool_names == []
    assert ctx.config_files_found == []


def test_detect_no_config_returns_empty_context(tmp_path):
    ctx = detect_mcp_context(tmp_path)
    assert not ctx.has_filesystem_access
    assert not ctx.has_network_access
    assert not ctx.is_stdio_transport


def test_detect_mcp_json_stdio(tmp_path):
    (tmp_path / "mcp.json").write_text('{"transport": "stdio", "tools": []}')
    ctx = detect_mcp_context(tmp_path)
    assert ctx.is_stdio_transport


def test_detect_mcp_json_fs_tool(tmp_path):
    config = '{"tools": [{"name": "read_file", "description": "Read a file from disk"}]}'
    (tmp_path / "mcp.json").write_text(config)
    ctx = detect_mcp_context(tmp_path)
    assert ctx.has_filesystem_access


def test_detect_mcp_json_network_tool(tmp_path):
    config = '{"tools": [{"name": "fetch_url", "description": "HTTP fetch"}]}'
    (tmp_path / "mcp.json").write_text(config)
    ctx = detect_mcp_context(tmp_path)
    assert ctx.has_network_access


def test_detect_mcp_json_sensitive_tool(tmp_path):
    config = '{"tools": [{"name": "run_shell", "description": "Execute shell command"}]}'
    (tmp_path / "mcp.json").write_text(config)
    ctx = detect_mcp_context(tmp_path)
    assert "run_shell" in ctx.sensitive_tool_names


def test_detect_non_mcp_json_ignored(tmp_path):
    # A plain JSON file without MCP keys should not be parsed
    (tmp_path / "config.json").write_text('{"host": "localhost", "port": 8080}')
    ctx = detect_mcp_context(tmp_path)
    assert not ctx.is_stdio_transport
    assert not ctx.has_filesystem_access


def test_detect_invalid_json_does_not_raise(tmp_path):
    (tmp_path / "mcp.json").write_text("not valid json }{")
    ctx = detect_mcp_context(tmp_path)  # should not raise
    assert isinstance(ctx, MCPContext)


def test_detect_mcp_servers_nested_stdio(tmp_path):
    config = '{"mcpServers": {"my-server": {"transport": "stdio"}}}'
    (tmp_path / "mcp.json").write_text(config)
    ctx = detect_mcp_context(tmp_path)
    assert ctx.is_stdio_transport
