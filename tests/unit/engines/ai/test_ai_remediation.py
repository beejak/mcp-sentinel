import pytest
from unittest.mock import AsyncMock, MagicMock
from pathlib import Path

from mcp_sentinel.engines.ai.ai_engine import AIEngine
from mcp_sentinel.engines.ai.providers.base import AIResponse
from mcp_sentinel.models.vulnerability import Vulnerability, Severity, Confidence

@pytest.fixture
def mock_provider():
    provider = MagicMock()
    provider.analyze_code = AsyncMock()
    provider.estimate_cost.return_value = 0.01
    provider.is_available.return_value = True
    return provider

@pytest.fixture
def ai_engine(mock_provider):
    engine = AIEngine()
    engine.provider = mock_provider
    engine.enabled = True
    return engine

@pytest.mark.asyncio
async def test_remediation_fields_parsing(ai_engine, mock_provider):
    """Test that fixed_code and remediation_steps are correctly parsed from AI response."""
    
    # Mock AI response with remediation details
    mock_response = AIResponse(
        vulnerabilities=[
            {
                "type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "line": 10,
                "description": "SQL Injection found",
                "remediation": "Use parameterized queries",
                "fixed_code": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
                "remediation_steps": [
                    "Replace string concatenation",
                    "Use parameterized query"
                ],
                "cwe_id": "CWE-89"
            }
        ],
        raw_response="...",
        confidence=0.9,
        tokens_used=100,
        cost_usd=0.01,
        provider="test_provider",
        model="test_model"
    )
    
    mock_provider.analyze_code.return_value = mock_response
    
    # Create a dummy file
    file_path = Path("test_vuln.py")
    content = "query = 'SELECT * FROM users WHERE id = ' + user_id\ncursor.execute(query)"
    
    # Run scan
    vulnerabilities = await ai_engine.scan_file(file_path, content, file_type="python")
    
    # Verify results
    assert len(vulnerabilities) == 1
    vuln = vulnerabilities[0]
    
    assert vuln.remediation == "Use parameterized queries"
    assert vuln.fixed_code == "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
    assert vuln.remediation_steps == [
        "Replace string concatenation",
        "Use parameterized query"
    ]
    assert vuln.cwe_id == "CWE-89"
    assert vuln.severity == Severity.CRITICAL
