import os
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from mcp_sentinel.engines.ai.ai_engine import AIEngine
from mcp_sentinel.engines.ai.providers.base import AIResponse, AIProviderType
from mcp_sentinel.engines.base import EngineStatus

@pytest.fixture
def mock_provider():
    mock = MagicMock()
    mock.analyze_code = AsyncMock()
    mock.is_available.return_value = True
    mock.estimate_cost.return_value = 0.1
    return mock

@patch("mcp_sentinel.engines.ai.ai_engine.AIEngine._create_provider")
@pytest.mark.asyncio
async def test_ai_engine_scan_file(mock_create_provider, mock_provider):
    mock_create_provider.return_value = mock_provider
    
    # Setup mock response
    mock_provider.analyze_code.return_value = AIResponse(
        vulnerabilities=[{
            "type": "SQL_INJECTION",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "line": 1,
            "description": "SQL Injection",
            "remediation": "Fix it",
            "cwe_id": "CWE-89"
        }],
        raw_response="...",
        confidence=0.9,
        tokens_used=100,
        cost_usd=0.01,
        provider="anthropic",
        model="claude"
    )
    
    engine = AIEngine(provider_type=AIProviderType.ANTHROPIC, api_key="test")
    await engine.initialize()
    
    vulnerabilities = await engine.scan_file(
        file_path=Path("test.py"),
        content="query = 'SELECT * FROM users WHERE id = ' + user_id",
        file_type="python"
    )
    
    assert len(vulnerabilities) == 1
    assert vulnerabilities[0].type.value == "code_injection" # Mapped from SQL_INJECTION
    assert vulnerabilities[0].severity.value == "critical"
    
    # Check cost tracking
    assert engine.total_cost == 0.01

@patch("mcp_sentinel.engines.ai.ai_engine.AIEngine._create_provider")
@pytest.mark.asyncio
async def test_ai_engine_cost_limit(mock_create_provider, mock_provider):
    mock_create_provider.return_value = mock_provider
    mock_provider.estimate_cost.return_value = 2.0 # Exceeds default limit of 1.0
    
    engine = AIEngine(provider_type=AIProviderType.ANTHROPIC, api_key="test", max_cost_per_scan=1.0)
    await engine.initialize()
    
    vulnerabilities = await engine.scan_file(
        file_path=Path("test.py"),
        content="some code",
        file_type="python"
    )
    
    assert len(vulnerabilities) == 0
    mock_provider.analyze_code.assert_not_called()

def test_auto_detect_provider():
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test"}):
        with patch("mcp_sentinel.engines.ai.ai_engine.AIEngine._create_provider") as mock_create:
             mock_create.return_value = MagicMock()
             engine = AIEngine()
             mock_create.assert_called_with(AIProviderType.ANTHROPIC, None, None)

@patch("mcp_sentinel.engines.ai.ai_engine.AIEngine._create_provider")
@pytest.mark.asyncio
async def test_scan_directory(mock_create_provider, mock_provider, tmp_path):
    mock_create_provider.return_value = mock_provider
    mock_provider.analyze_code.return_value = AIResponse(
        vulnerabilities=[],
        raw_response="...",
        confidence=0.9,
        tokens_used=0,
        cost_usd=0.0,
        provider="anthropic",
        model="claude"
    )

    # Create dummy file
    test_file = tmp_path / "test.py"
    test_file.write_text("print('hello')")
    
    engine = AIEngine(provider_type=AIProviderType.ANTHROPIC, api_key="test")
    await engine.initialize()
    
    vulns = await engine.scan_directory(tmp_path)
    assert isinstance(vulns, list)
    assert engine.status == EngineStatus.COMPLETED
