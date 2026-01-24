import pytest
from click.testing import CliRunner
from unittest.mock import patch, MagicMock
from pathlib import Path
from mcp_sentinel.cli.main import cli
from mcp_sentinel.models.scan_result import ScanResult, ScanStatistics
from mcp_sentinel.models.vulnerability import Severity

@pytest.fixture
def mock_scan_result():
    result = MagicMock(spec=ScanResult)
    result.target = "/test"
    result.status = "completed"
    result.statistics = ScanStatistics(
        total_files=10,
        scanned_files=10,
        scan_duration_seconds=1.0,
        total_vulnerabilities=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        info_count=0
    )
    result.vulnerabilities = []
    result.risk_score.return_value = 0.0
    result.has_critical_findings.return_value = False
    result.model_dump_json.return_value = "{}"
    return result

def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "MCP Sentinel" in result.output
    assert "--log-level" in result.output

@patch("mcp_sentinel.cli.main.setup_logging")
@patch("mcp_sentinel.cli.main.asyncio.run")
def test_cli_logging_options(mock_run, mock_setup, mock_scan_result):
    mock_run.return_value = mock_scan_result
    runner = CliRunner()
    # We invoke scan command so the group callback (setup_logging) is executed
    result = runner.invoke(cli, ["--log-level", "DEBUG", "--log-file", "test.log", "scan", "."])
    assert result.exit_code == 0
    # Setup logging is called before command execution
    mock_setup.assert_called_once_with(log_level="DEBUG", log_file="test.log")

@patch("mcp_sentinel.cli.main.questionary.path")
@patch("mcp_sentinel.cli.main.Path.exists")
@patch("mcp_sentinel.cli.main.asyncio.run")
def test_scan_interactive(mock_run, mock_exists, mock_questionary, mock_scan_result):
    # Mock questionary
    mock_questionary.return_value.ask.return_value = "/mock/path"
    mock_exists.return_value = True
    
    # Mock scan execution
    mock_run.return_value = mock_scan_result
    
    runner = CliRunner()
    result = runner.invoke(cli, ["scan"])
    
    assert result.exit_code == 0
    mock_questionary.assert_called_once()
    # Check for normalized path string if needed, or just part of the output
    assert "Scanning" in result.output
    assert "/mock/path" in result.output

@patch("mcp_sentinel.cli.main.asyncio.run")
def test_scan_with_target(mock_run, mock_scan_result):
    mock_run.return_value = mock_scan_result
    
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("target_dir").mkdir()
        result = runner.invoke(cli, ["scan", "target_dir"])
        
        assert result.exit_code == 0
        assert "Scanning: target_dir" in result.output
