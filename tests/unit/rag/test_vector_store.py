import pytest
from unittest.mock import MagicMock, patch
from mcp_sentinel.rag.vector_store import VectorStore

# Keeping fixtures for other tests
@pytest.fixture
def mock_chroma_client():
    with patch('mcp_sentinel.rag.vector_store.chromadb.PersistentClient') as mock:
        yield mock

@pytest.fixture
def mock_embedding_function_class():
    with patch('mcp_sentinel.rag.vector_store.embedding_functions.SentenceTransformerEmbeddingFunction') as mock:
        yield mock

def test_vector_store_initialization(mock_chroma_client, mock_embedding_function_class):
    """Test VectorStore initialization."""
    store = VectorStore(persist_dir="./test_db")
    
    mock_chroma_client.assert_called_once()
    assert store.client is not None

def test_get_or_create_collection():
    """Test collection creation with explicit embedding function."""
    with patch('mcp_sentinel.rag.vector_store.chromadb.PersistentClient') as mock_cls:
        mock_ef = MagicMock()
        store = VectorStore(persist_dir="./test_db", embedding_function=mock_ef)
        mock_client_instance = mock_cls.return_value
        
        # Mock successful retrieval
        mock_collection = MagicMock()
        mock_client_instance.get_collection.return_value = mock_collection
        
        collection = store.get_or_create_collection("test_collection")
        
        # Verify call arguments manually to debug issues
        assert mock_client_instance.get_collection.called
        call_args = mock_client_instance.get_collection.call_args
        assert call_args.kwargs["name"] == "test_collection"
        assert call_args.kwargs["embedding_function"] == mock_ef
        assert collection == mock_collection

        # Mock creation if retrieval fails
        mock_client_instance.get_collection.side_effect = Exception("Not found")
        mock_new_collection = MagicMock()
        mock_client_instance.create_collection.return_value = mock_new_collection
        
        collection = store.get_or_create_collection("new_collection")
        
        assert mock_client_instance.create_collection.called
        create_call_args = mock_client_instance.create_collection.call_args
        assert create_call_args.kwargs["name"] == "new_collection"
        assert create_call_args.kwargs["embedding_function"] == mock_ef
        assert collection == mock_new_collection

def test_add_documents(mock_chroma_client):
    """Test adding documents."""
    mock_ef = MagicMock()
    store = VectorStore(persist_dir="./test_db", embedding_function=mock_ef)
    mock_client_instance = mock_chroma_client.return_value
    mock_collection = MagicMock()
    mock_client_instance.get_collection.return_value = mock_collection
    
    store.add_documents(
        collection_name="test_collection",
        documents=["doc1", "doc2"],
        metadatas=[{"m": 1}, {"m": 2}],
        ids=["1", "2"]
    )
    
    mock_collection.add.assert_called_with(
        documents=["doc1", "doc2"],
        metadatas=[{"m": 1}, {"m": 2}],
        ids=["1", "2"]
    )
