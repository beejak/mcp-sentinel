import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from mcp_sentinel.engines.ai.providers.anthropic_provider import AnthropicProvider
from mcp_sentinel.engines.ai.providers.base import AIProviderConfig, AIProviderType

@pytest.fixture
def mock_anthropic_client():
    with patch("mcp_sentinel.engines.ai.providers.anthropic_provider.AsyncAnthropic") as mock:
        yield mock

@pytest.fixture
def provider_config():
    return AIProviderConfig(
        provider_type=AIProviderType.ANTHROPIC,
        api_key="test-key",
        model="claude-3-5-sonnet-20241022"
    )

@pytest.mark.asyncio
async def test_analyze_code_success(mock_anthropic_client, provider_config):
    # Setup mock response
    mock_instance = mock_anthropic_client.return_value
    mock_message = MagicMock()
    
    vulns = [
        {
            "type": "SQL_INJECTION",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "line": 42,
            "description": "SQL Injection found",
            "remediation": "Fix it",
            "cwe_id": "CWE-89"
        }
    ]
    
    mock_message.content = [MagicMock(text=json.dumps(vulns))]
    mock_message.usage.input_tokens = 100
    mock_message.usage.output_tokens = 50
    mock_instance.messages.create = AsyncMock(return_value=mock_message)
    
    provider = AnthropicProvider(provider_config)
    
    code = "def test(): pass"
    response = await provider.analyze_code(code, "test.py", "python")
    
    assert response.provider == "anthropic"
    assert response.model == provider_config.model
    assert response.tokens_used == 150
    assert len(response.vulnerabilities) == 1
    assert response.vulnerabilities[0]["type"] == "SQL_INJECTION"

@pytest.mark.asyncio
async def test_analyze_code_empty(mock_anthropic_client, provider_config):
    # Setup mock response
    mock_instance = mock_anthropic_client.return_value
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text="[]")]
    mock_message.usage.input_tokens = 100
    mock_message.usage.output_tokens = 50
    mock_instance.messages.create = AsyncMock(return_value=mock_message)
    
    provider = AnthropicProvider(provider_config)
    
    code = "def test(): pass"
    response = await provider.analyze_code(code, "test.py", "python")
    
    assert len(response.vulnerabilities) == 0

@pytest.mark.asyncio
async def test_analyze_code_error(mock_anthropic_client, provider_config):
    # Setup mock exception
    mock_instance = mock_anthropic_client.return_value
    mock_instance.messages.create = AsyncMock(side_effect=Exception("API Error"))
    
    provider = AnthropicProvider(provider_config)
    
    code = "def test(): pass"
    response = await provider.analyze_code(code, "test.py", "python")
    
    assert len(response.vulnerabilities) == 0
    assert "Error: API Error" in response.raw_response

def test_estimate_cost(mock_anthropic_client, provider_config):
    provider = AnthropicProvider(provider_config)
    cost = provider.estimate_cost("some code")
    assert cost > 0

def test_is_available(mock_anthropic_client, provider_config):
    provider = AnthropicProvider(provider_config)
    assert provider.is_available() is True

@pytest.mark.asyncio
async def test_generate_fix(mock_anthropic_client, provider_config):
    # Setup mock response
    mock_instance = mock_anthropic_client.return_value
    mock_message = MagicMock()
    
    fix_data = {
        "title": "Use parameterized queries",
        "description": "Replaced string concatenation with parameter binding",
        "explanation": "Prevents SQL injection",
        "code_changes": [{
            "file_path": "db.py",
            "original_code": "sql = '...'",
            "new_code": "sql = '...'",
            "start_line": 10,
            "end_line": 10
        }],
        "confidence": 0.95
    }
    
    mock_message.content = [MagicMock(text=json.dumps(fix_data))]
    mock_instance.messages.create = AsyncMock(return_value=mock_message)
    
    provider = AnthropicProvider(provider_config)
    
    code = "def test(): pass"
    vuln = {"type": "SQL_INJECTION", "title": "SQL Injection", "line_number": 10}
    
    response = await provider.generate_fix(code, vuln, "test.py")
    
    assert response["title"] == "Use parameterized queries"
    assert len(response["code_changes"]) == 1
