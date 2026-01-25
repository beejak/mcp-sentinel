import pytest
from unittest.mock import MagicMock
from mcp_sentinel.rag.retriever import Retriever, RetrievalResult
from mcp_sentinel.rag.vector_store import VectorStore

@pytest.fixture
def mock_vector_store():
    return MagicMock(spec=VectorStore)

def test_retriever_initialization(mock_vector_store):
    retriever = Retriever(vector_store=mock_vector_store)
    assert retriever.vector_store == mock_vector_store
    assert retriever.min_similarity == 0.3

def test_search(mock_vector_store):
    retriever = Retriever(vector_store=mock_vector_store)
    
    # Mock vector_store.search results (already flattened by VectorStore.search)
    mock_vector_store.search.return_value = {
        "ids": ["1", "2"],
        "documents": ["doc1", "doc2"],
        "metadatas": [{"m": 1}, {"m": 2}],
        "distances": [0.1, 0.8] # 0.1 -> sim 0.9, 0.8 -> sim 0.2
    }
    
    results = retriever.search("query", "test_collection")
    
    mock_vector_store.search.assert_called_with(
        collection_name="test_collection",
        query="query",
        n_results=5,
        where=None
    )
    
    # Check filtering (min_similarity=0.3)
    # distance 0.1 -> similarity 0.9 (keep)
    # distance 0.8 -> similarity 0.2 (filter out)
    assert len(results) == 1
    assert results[0].id == "1"
    assert abs(results[0].similarity - 0.9) < 0.001

def test_augment_prompt(mock_vector_store):
    retriever = Retriever(vector_store=mock_vector_store)
    
    # Mock multi_search results
    mock_result = RetrievalResult(id="1", document="Security Rule 1", metadata={"title": "Test Rule", "category": "Test"}, distance=0.1, similarity=0.9)
    retriever.multi_search = MagicMock(return_value=[mock_result])
    retriever.vector_store.list_collections.return_value = ["cwe_database"]
    
    prompt = retriever.augment_prompt("Analyze code", "print('hello')")
    
    # augment_prompt includes the base_prompt and knowledge context, but not necessarily the code snippet
    # (unless base_prompt contained it).
    assert "Analyze code" in prompt
    assert "Security Rule 1" in prompt
    assert "Test Rule" in prompt
