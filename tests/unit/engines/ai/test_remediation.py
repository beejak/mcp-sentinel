import pytest
from unittest.mock import MagicMock, AsyncMock
from pathlib import Path
from mcp_sentinel.engines.ai.ai_engine import AIEngine
from mcp_sentinel.remediation.diff_builder import DiffBuilder
from mcp_sentinel.models.vulnerability import Vulnerability, VulnerabilityType, Severity, Confidence
from mcp_sentinel.remediation.models import RemediationSuggestion

@pytest.mark.asyncio
async def test_generate_fix():
    """Test generating a fix for a vulnerability."""
    # Setup
    engine = AIEngine(enabled=True)
    engine.provider = MagicMock()
    engine.provider.is_available.return_value = True
    
    # Mock fix response
    fix_response = {
        "title": "Use parameterized queries",
        "description": "Replaced string concatenation with parameter binding",
        "explanation": "Prevents SQL injection",
        "code_changes": [{
            "file_path": "db.py",
            "original_code": "sql = 'SELECT * FROM users WHERE id = ' + user_id",
            "new_code": "sql = 'SELECT * FROM users WHERE id = ?'",
            "start_line": 10,
            "end_line": 10
        }],
        "confidence": 0.95
    }
    engine.provider.generate_fix = AsyncMock(return_value=fix_response)
    
    # Vulnerability
    vuln = Vulnerability(
        type=VulnerabilityType.CODE_INJECTION,
        title="SQL Injection",
        description="SQL injection detected",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file_path="db.py",
        line_number=10,
        code_snippet="sql = 'SELECT * FROM users WHERE id = ' + user_id",
        detector="test_detector",
        engine="test_engine"
    )
    
    # Execute
    try:
        suggestion = await engine.generate_fix(vuln, "full file content")
    except Exception as e:
        print(f"Caught exception: {e}")
        if hasattr(e, 'errors'):
            print(f"Validation errors: {e.errors()}")
        raise
    
    # Verify
    assert suggestion is not None
    assert isinstance(suggestion, RemediationSuggestion)
    assert suggestion.title == "Use parameterized queries"
    assert len(suggestion.code_changes) == 1
    assert suggestion.code_changes[0].new_code == "sql = 'SELECT * FROM users WHERE id = ?'"
    
    # Verify provider call
    engine.provider.generate_fix.assert_called_once()
    call_args = engine.provider.generate_fix.call_args
    assert call_args.kwargs["file_path"] == "db.py"
    assert call_args.kwargs["vulnerability"]["title"] == "SQL Injection"

@pytest.mark.asyncio
async def test_generate_fix_with_rag():
    """Test generating a fix with RAG context."""
    # Setup
    mock_vector_store = MagicMock()
    engine = AIEngine(enabled=True, vector_store=mock_vector_store)
    engine.provider = MagicMock()
    engine.provider.is_available.return_value = True
    
    # Mock RAG retrieval
    mock_result = MagicMock()
    mock_result.document = "Use parameterized queries to prevent SQL injection."
    mock_result.metadata = {"title": "SQL Injection Prevention"}
    mock_result.similarity = 0.9
    
    # Mock Retriever (created inside AIEngine)
    engine.retriever = MagicMock()
    engine.retriever.multi_search.return_value = [mock_result]
    engine.retriever.format_results.return_value = "Context: Use parameterized queries."
    
    # Mock fix response
    fix_response = {
        "title": "Fix",
        "description": "Desc",
        "explanation": "Exp",
        "code_changes": [{
            "file_path": "test.py",
            "original_code": "a",
            "new_code": "b",
            "start_line": 1,
            "end_line": 1
        }],
        "confidence": 0.9
    }
    engine.provider.generate_fix = AsyncMock(return_value=fix_response)
    
    # Vulnerability
    vuln = Vulnerability(
        type=VulnerabilityType.CODE_INJECTION,
        title="SQL Injection",
        description="SQL injection detected",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file_path="test.py",
        line_number=1,
        code_snippet="a",
        detector="test_detector",
        engine="test_engine"
    )
    
    # Execute
    await engine.generate_fix(vuln, "content")
    
    # Verify RAG usage
    engine.retriever.multi_search.assert_called_once()
    
    # Verify context passed to provider
    engine.provider.generate_fix.assert_called_once()
    call_args = engine.provider.generate_fix.call_args
    assert "context" in call_args.kwargs
    assert call_args.kwargs["context"] == {"security_knowledge": "Context: Use parameterized queries."}
