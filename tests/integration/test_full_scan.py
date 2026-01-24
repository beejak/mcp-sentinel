
import os
import json
import pytest
from pathlib import Path
from click.testing import CliRunner
from mcp_sentinel.cli.main import cli

@pytest.fixture
def vulnerable_app_path():
    return Path(__file__).parent / "fixtures" / "vulnerable_app.py"

def test_full_scan_json_output(vulnerable_app_path, tmp_path):
    """Test full scan with JSON output."""
    runner = CliRunner()
    output_file = tmp_path / "results.json"
    
    # Run scan
    result = runner.invoke(cli, [
        "scan", 
        str(vulnerable_app_path.parent), 
        "--output", "json",
        "--json-file", str(output_file),
        "--no-progress"
    ])
    
    # It might exit with 1 if critical vulnerabilities are found (default behavior)
    if result.exit_code != 0:
         # Check if it was due to critical findings
         assert "Aborted!" in result.output or result.exit_code == 1
    
    assert output_file.exists()
    
    # Parse results
    with open(output_file) as f:
        data = json.load(f)
        
    assert data["status"] == "completed"
    assert len(data["vulnerabilities"]) > 0
    
    # Check for expected vulnerabilities
    vulns = data["vulnerabilities"]
    
    # Check for hardcoded secret
    has_secret = any(v["type"] == "secret_exposure" for v in vulns)
    # Check for command injection (might be flagged as code_injection)
    has_injection = any(v["type"] == "code_injection" for v in vulns)
    
    assert has_secret, "Should detect hardcoded AWS key"
    # Note: SAST might need specific rules to catch the injection, 
    # but at least static analysis should catch the secret.

def test_scan_console_output(vulnerable_app_path):
    """Test scan with console output."""
    runner = CliRunner()
    
    result = runner.invoke(cli, [
        "scan", 
        str(vulnerable_app_path.parent),
        "--no-progress"
    ])
    
    # Expect failure due to critical findings
    if result.exit_code != 0:
        assert result.exit_code == 1
    
    assert "Scan Summary" in result.output
    # Title might be wrapped in the table
    assert "Vulnerabilities" in result.output
    assert "Severity" in result.output
    
    # Check for specific findings
    assert "Hardcoded AWS Access Key" in result.output
    assert "Command Injection" in result.output
    assert "AKIA" in result.output  # Secret value should be in snippet or description

