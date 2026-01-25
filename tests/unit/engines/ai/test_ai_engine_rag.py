import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from mcp_sentinel.engines.ai.ai_engine import AIEngine
from mcp_sentinel.engines.ai.providers.base import AIResponse, AIProviderType
from mcp_sentinel.rag.vector_store import VectorStore
from mcp_sentinel.rag.retriever import RetrievalResult

@pytest.fixture
def mock_provider():
    mock = MagicMock()
    mock.analyze_code = AsyncMock()
    mock.is_available.return_value = True
    mock.estimate_cost.return_value = 0.1
    return mock

@pytest.fixture
def mock_vector_store():
    return MagicMock(spec=VectorStore)

@patch("mcp_sentinel.engines.ai.ai_engine.Retriever")
@patch("mcp_sentinel.engines.ai.ai_engine.AIEngine._create_provider")
@pytest.mark.asyncio
async def test_ai_engine_rag_integration(mock_create_provider, mock_retriever_cls, mock_provider, mock_vector_store):
    # Setup mocks
    mock_create_provider.return_value = mock_provider
    
    mock_retriever_instance = MagicMock()
    mock_retriever_cls.return_value = mock_retriever_instance
    
    # Setup retrieval results
    mock_retrieval_result = RetrievalResult(
        id="1",
        document="Secure coding practice...",
        metadata={"title": "SQL Injection Prevention"},
        distance=0.1,
        similarity=0.9
    )
    mock_retriever_instance.multi_search.return_value = [mock_retrieval_result]
    mock_retriever_instance.format_results.return_value = "### 1. SQL Injection Prevention\nSecure coding practice...\n"

    # Setup provider response
    mock_provider.analyze_code.return_value = AIResponse(
        vulnerabilities=[],
        raw_response="...",
        confidence=0.9,
        tokens_used=100,
        cost_usd=0.01,
        provider="anthropic",
        model="claude"
    )

    # Initialize Engine with VectorStore
    engine = AIEngine(
        provider_type=AIProviderType.ANTHROPIC, 
        api_key="test",
        vector_store=mock_vector_store
    )
    await engine.initialize()

    # Verify Retriever initialization
    mock_retriever_cls.assert_called_with(mock_vector_store)
    assert engine.retriever == mock_retriever_instance

    # Run scan
    content = "query = 'SELECT * FROM users'"
    file_path = Path("test.py")
    await engine.scan_file(file_path, content, "python")

    # Verify RAG flow
    # 1. multi_search called with content prefix
    mock_retriever_instance.multi_search.assert_called_with(query=content[:1000], top_k=3)
    
    # 2. format_results called
    mock_retriever_instance.format_results.assert_called()
    
    # 3. analyze_code called with context
    expected_context = {"security_knowledge": "### 1. SQL Injection Prevention\nSecure coding practice...\n"}
    mock_provider.analyze_code.assert_called_with(
        code=content,
        file_path=str(file_path),
        language="python",
        context=expected_context
    )

@patch("mcp_sentinel.engines.ai.ai_engine.Retriever")
@patch("mcp_sentinel.engines.ai.ai_engine.AIEngine._create_provider")
@pytest.mark.asyncio
async def test_ai_engine_rag_failure_handling(mock_create_provider, mock_retriever_cls, mock_provider, mock_vector_store):
    # Setup mocks
    mock_create_provider.return_value = mock_provider
    mock_retriever_instance = MagicMock()
    mock_retriever_cls.return_value = mock_retriever_instance
    
    # Simulate retrieval failure
    mock_retriever_instance.multi_search.side_effect = Exception("DB Connection Failed")

    mock_provider.analyze_code.return_value = AIResponse(
        vulnerabilities=[],
        raw_response="...",
        confidence=0.9,
        tokens_used=100,
        cost_usd=0.01,
        provider="anthropic",
        model="claude"
    )

    engine = AIEngine(
        provider_type=AIProviderType.ANTHROPIC, 
        api_key="test",
        vector_store=mock_vector_store
    )
    await engine.initialize()

    # Run scan
    await engine.scan_file(Path("test.py"), "content", "python")

    # Verify analyze_code still called but with context=None
    mock_provider.analyze_code.assert_called_with(
        code="content",
        file_path="test.py",
        language="python",
        context=None
    )
