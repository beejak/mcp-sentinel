"""
Vector Store implementation using ChromaDB.

Provides persistent storage and retrieval of security knowledge embeddings.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import chromadb
from chromadb.config import Settings
from chromadb.utils import embedding_functions

logger = logging.getLogger(__name__)


class VectorStore:
    """
    ChromaDB-based vector store for security knowledge.

    Features:
    - Persistent storage of vulnerability patterns
    - Semantic search with cosine similarity
    - Collection management (OWASP, CWE, frameworks, CVE)
    - Incremental updates and deletions

    Usage:
        store = VectorStore(persist_dir="./chroma_db")
        store.add_documents(
            collection_name="owasp_top10",
            documents=["SQL injection pattern...", ...],
            metadatas=[{"cwe_id": "CWE-89", ...}, ...],
            ids=["owasp_llm_01", ...]
        )
        results = store.search(
            collection_name="owasp_top10",
            query="How to detect SQL injection?",
            n_results=5
        )
    """

    def __init__(
        self,
        persist_dir: Optional[str] = "./data/chroma_db",
        embedding_function: Optional[Any] = None
    ):
        """
        Initialize ChromaDB vector store.

        Args:
            persist_dir: Directory for persistent storage (or None/":memory:" for in-memory)
            embedding_function: Custom embedding function (default: sentence-transformers)
        """
        self.persist_dir = Path(persist_dir) if persist_dir and persist_dir != ":memory:" else None
        
        # Initialize ChromaDB
        if self.persist_dir:
            self.persist_dir.mkdir(parents=True, exist_ok=True)
            self.client = chromadb.PersistentClient(
                path=str(self.persist_dir),
                settings=Settings(
                    anonymized_telemetry=False,
                    allow_reset=True
                )
            )
        else:
            self.client = chromadb.EphemeralClient(
                settings=Settings(
                    anonymized_telemetry=False,
                    allow_reset=True
                )
            )

        # Use default sentence-transformers embedding if not provided
        self.embedding_function = embedding_function or embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"  # Fast, efficient model (384 dimensions)
        )

        logger.info(f"VectorStore initialized with persist_dir: {self.persist_dir}")

    def get_or_create_collection(self, name: str) -> chromadb.Collection:
        """
        Get existing collection or create new one.

        Args:
            name: Collection name (e.g., "owasp_top10", "cwe_database")

        Returns:
            ChromaDB collection
        """
        try:
            collection = self.client.get_collection(
                name=name,
                embedding_function=self.embedding_function
            )
            logger.debug(f"Retrieved existing collection: {name}")
        except Exception:
            collection = self.client.create_collection(
                name=name,
                embedding_function=self.embedding_function,
                metadata={"hnsw:space": "cosine"}  # Cosine similarity
            )
            logger.info(f"Created new collection: {name}")

        return collection

    def add_documents(
        self,
        collection_name: str,
        documents: List[str],
        metadatas: Optional[List[Dict[str, Any]]] = None,
        ids: Optional[List[str]] = None
    ) -> None:
        """
        Add documents to a collection.

        Args:
            collection_name: Target collection
            documents: List of text documents to embed and store
            metadatas: Optional metadata for each document (e.g., CWE ID, severity)
            ids: Optional unique IDs (auto-generated if not provided)
        """
        collection = self.get_or_create_collection(collection_name)

        # Auto-generate IDs if not provided
        if ids is None:
            existing_count = collection.count()
            ids = [f"{collection_name}_{existing_count + i}" for i in range(len(documents))]

        # Add documents with embeddings
        collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )

        logger.info(f"Added {len(documents)} documents to collection '{collection_name}'")

    def upsert_documents(
        self,
        collection_name: str,
        documents: List[str],
        metadatas: Optional[List[Dict[str, Any]]] = None,
        ids: Optional[List[str]] = None
    ) -> None:
        """
        Update existing documents or insert new ones.

        Args:
            collection_name: Target collection
            documents: List of text documents
            metadatas: Optional metadata
            ids: Document IDs (required for upsert)
        """
        if ids is None:
            raise ValueError("IDs are required for upsert operation")

        collection = self.get_or_create_collection(collection_name)

        collection.upsert(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )

        logger.info(f"Upserted {len(documents)} documents in collection '{collection_name}'")

    def search(
        self,
        collection_name: str,
        query: str,
        n_results: int = 5,
        where: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Semantic search for relevant documents.

        Args:
            collection_name: Collection to search
            query: Search query text
            n_results: Number of results to return
            where: Optional metadata filter (e.g., {"severity": "CRITICAL"})

        Returns:
            Dictionary with 'documents', 'metadatas', 'distances', 'ids'
        """
        collection = self.get_or_create_collection(collection_name)

        results = collection.query(
            query_texts=[query],
            n_results=n_results,
            where=where
        )

        logger.debug(f"Search in '{collection_name}': found {len(results['ids'][0])} results")

        return {
            "documents": results["documents"][0],
            "metadatas": results["metadatas"][0],
            "distances": results["distances"][0],
            "ids": results["ids"][0]
        }

    def delete_documents(
        self,
        collection_name: str,
        ids: Optional[List[str]] = None,
        where: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Delete documents from collection.

        Args:
            collection_name: Target collection
            ids: Specific document IDs to delete
            where: Metadata filter for bulk deletion
        """
        collection = self.get_or_create_collection(collection_name)

        collection.delete(
            ids=ids,
            where=where
        )

        logger.info(f"Deleted documents from collection '{collection_name}'")

    def get_collection_stats(self, collection_name: str) -> Dict[str, Any]:
        """
        Get statistics for a collection.

        Args:
            collection_name: Collection name

        Returns:
            Dictionary with count and metadata
        """
        collection = self.get_or_create_collection(collection_name)

        return {
            "name": collection_name,
            "count": collection.count(),
            "metadata": collection.metadata
        }

    def list_collections(self) -> List[str]:
        """
        List all collections in the vector store.

        Returns:
            List of collection names
        """
        collections = self.client.list_collections()
        return [col.name for col in collections]

    def delete_collection(self, collection_name: str) -> None:
        """
        Delete an entire collection.

        Args:
            collection_name: Collection to delete
        """
        self.client.delete_collection(name=collection_name)
        logger.warning(f"Deleted collection: {collection_name}")

    def reset(self) -> None:
        """
        Delete all collections and reset the database.

        WARNING: This is destructive and cannot be undone!
        """
        self.client.reset()
        logger.warning("VectorStore reset: all collections deleted")
