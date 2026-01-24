"""
Unit tests for RAG (Retrieval-Augmented Generation) system.

Tests the core components:
- VectorStore (ChromaDB integration)
- EmbeddingService (SentenceTransformers)
- KnowledgeBase (knowledge management)
- Retriever (semantic search)
"""

import pytest
import tempfile
from pathlib import Path

from mcp_sentinel.rag import VectorStore, EmbeddingService, KnowledgeBase, Retriever
from mcp_sentinel.rag.knowledge_base import SecurityKnowledge


class TestVectorStore:
    """Test VectorStore component."""

    def test_init_vector_store(self):
        """Test VectorStore initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = VectorStore(persist_dir=tmpdir)
            assert store.persist_dir == Path(tmpdir)
            assert store.client is not None

    def test_create_collection(self):
        """Test collection creation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = VectorStore(persist_dir=tmpdir)
            collection = store.get_or_create_collection("test_collection")
            assert collection.name == "test_collection"

    def test_add_and_search_documents(self):
        """Test adding documents and searching."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = VectorStore(persist_dir=tmpdir)

            # Add documents
            documents = [
                "SQL injection vulnerability in login form",
                "Cross-site scripting (XSS) in user input",
                "Command injection in file upload"
            ]
            metadatas = [
                {"severity": "CRITICAL", "cwe_id": "CWE-89"},
                {"severity": "HIGH", "cwe_id": "CWE-79"},
                {"severity": "CRITICAL", "cwe_id": "CWE-78"}
            ]
            ids = ["vuln_1", "vuln_2", "vuln_3"]

            store.add_documents(
                collection_name="vulnerabilities",
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )

            # Search
            results = store.search(
                collection_name="vulnerabilities",
                query="SQL injection attack",
                n_results=2
            )

            assert len(results["documents"]) == 2
            assert "SQL injection" in results["documents"][0]
            assert results["metadatas"][0]["cwe_id"] == "CWE-89"

    def test_upsert_documents(self):
        """Test upserting (update or insert) documents."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = VectorStore(persist_dir=tmpdir)

            # Add initial document
            store.add_documents(
                collection_name="test",
                documents=["Original document"],
                ids=["doc_1"]
            )

            # Upsert with updated content
            store.upsert_documents(
                collection_name="test",
                documents=["Updated document"],
                ids=["doc_1"]
            )

            # Verify update
            results = store.search(
                collection_name="test",
                query="Updated",
                n_results=1
            )

            assert "Updated document" in results["documents"][0]

    def test_delete_documents(self):
        """Test document deletion."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = VectorStore(persist_dir=tmpdir)

            # Add documents
            store.add_documents(
                collection_name="test",
                documents=["Doc 1", "Doc 2"],
                ids=["doc_1", "doc_2"]
            )

            # Delete one document
            store.delete_documents(
                collection_name="test",
                ids=["doc_1"]
            )

            # Verify deletion
            stats = store.get_collection_stats("test")
            assert stats["count"] == 1

    def test_list_collections(self):
        """Test listing collections."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = VectorStore(persist_dir=tmpdir)

            store.get_or_create_collection("collection_1")
            store.get_or_create_collection("collection_2")

            collections = store.list_collections()
            assert "collection_1" in collections
            assert "collection_2" in collections


class TestEmbeddingService:
    """Test EmbeddingService component."""

    def test_init_embedding_service(self):
        """Test EmbeddingService initialization."""
        service = EmbeddingService()
        assert service.model is not None
        assert service.dimension == 384  # all-MiniLM-L6-v2

    def test_embed_single_text(self):
        """Test embedding a single text."""
        service = EmbeddingService()
        embedding = service.embed_text("SQL injection vulnerability")

        assert isinstance(embedding, list)
        assert len(embedding) == 384
        assert all(isinstance(x, float) for x in embedding)

    def test_embed_multiple_texts(self):
        """Test embedding multiple texts."""
        service = EmbeddingService()
        texts = [
            "SQL injection",
            "XSS vulnerability",
            "Command injection"
        ]

        embeddings = service.embed_texts(texts)

        assert len(embeddings) == 3
        assert all(len(emb) == 384 for emb in embeddings)

    def test_semantic_similarity(self):
        """Test semantic similarity calculation."""
        service = EmbeddingService()

        # Similar texts should have high similarity
        similarity_high = service.semantic_similarity(
            "SQL injection vulnerability",
            "Database injection attack"
        )

        # Different texts should have lower similarity
        similarity_low = service.semantic_similarity(
            "SQL injection vulnerability",
            "React component rendering"
        )

        assert similarity_high > similarity_low
        assert 0.0 <= similarity_high <= 1.0
        assert 0.0 <= similarity_low <= 1.0

    def test_find_most_similar(self):
        """Test finding most similar texts."""
        service = EmbeddingService()

        query = "SQL database injection"
        candidates = [
            "SQL injection vulnerability",
            "Cross-site scripting",
            "Database query attack",
            "React component",
            "Command execution"
        ]

        results = service.find_most_similar(query, candidates, top_k=3)

        assert len(results) == 3
        assert all(isinstance(r, tuple) and len(r) == 2 for r in results)
        # Most similar should be SQL-related
        assert "SQL injection" in results[0][0] or "Database query" in results[0][0]


class TestKnowledgeBase:
    """Test KnowledgeBase component."""

    def test_security_knowledge_to_document(self):
        """Test SecurityKnowledge.to_document()."""
        knowledge = SecurityKnowledge(
            id="test_1",
            title="SQL Injection",
            description="Attacker can inject SQL queries",
            category="Injection",
            severity="CRITICAL",
            cwe_id="CWE-89",
            code_example="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')"
        )

        document = knowledge.to_document()

        assert "SQL Injection" in document
        assert "CWE-89" in document
        assert "cursor.execute" in document

    def test_security_knowledge_to_metadata(self):
        """Test SecurityKnowledge.to_metadata()."""
        knowledge = SecurityKnowledge(
            id="test_1",
            title="SQL Injection",
            description="Test",
            category="Injection",
            severity="CRITICAL",
            cwe_id="CWE-89",
            tags=["sql", "database"]
        )

        metadata = knowledge.to_metadata()

        assert metadata["title"] == "SQL Injection"
        assert metadata["category"] == "Injection"
        assert metadata["severity"] == "CRITICAL"
        assert metadata["cwe_id"] == "CWE-89"
        assert metadata["tags"] == "sql,database"

    def test_add_knowledge(self):
        """Test adding knowledge to KnowledgeBase."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = VectorStore(persist_dir=tmpdir)
            kb = KnowledgeBase(store)

            knowledge_items = [
                SecurityKnowledge(
                    id="sql_inj",
                    title="SQL Injection",
                    description="Database injection vulnerability",
                    category="Injection",
                    cwe_id="CWE-89"
                ),
                SecurityKnowledge(
                    id="xss",
                    title="Cross-Site Scripting",
                    description="XSS vulnerability",
                    category="Injection",
                    cwe_id="CWE-79"
                )
            ]

            kb.add_knowledge("test_collection", knowledge_items)

            stats = store.get_collection_stats("test_collection")
            assert stats["count"] == 2

    def test_get_stats(self):
        """Test getting knowledge base statistics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = VectorStore(persist_dir=tmpdir)
            kb = KnowledgeBase(store)

            # Add some knowledge
            knowledge_items = [
                SecurityKnowledge(
                    id=f"item_{i}",
                    title=f"Vulnerability {i}",
                    description=f"Description {i}",
                    category="Test"
                )
                for i in range(5)
            ]

            kb.add_knowledge("cwe_database", knowledge_items)

            stats = kb.get_stats()

            assert "cwe_database" in stats
            assert stats["cwe_database"]["count"] == 5


class TestRetriever:
    """Test Retriever component."""

    @pytest.fixture
    def setup_retriever(self):
        """Setup retriever with sample data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = VectorStore(persist_dir=tmpdir)
            kb = KnowledgeBase(store)

            # Add sample knowledge
            knowledge_items = [
                SecurityKnowledge(
                    id="sql_inj",
                    title="SQL Injection",
                    description="SQL injection allows attackers to manipulate database queries",
                    category="Injection",
                    severity="CRITICAL",
                    cwe_id="CWE-89"
                ),
                SecurityKnowledge(
                    id="xss",
                    title="Cross-Site Scripting",
                    description="XSS allows injecting malicious scripts into web pages",
                    category="Injection",
                    severity="HIGH",
                    cwe_id="CWE-79"
                ),
                SecurityKnowledge(
                    id="cmd_inj",
                    title="Command Injection",
                    description="Command injection allows executing arbitrary system commands",
                    category="Injection",
                    severity="CRITICAL",
                    cwe_id="CWE-78"
                )
            ]

            kb.add_knowledge("cwe_database", knowledge_items)

            retriever = Retriever(store, min_similarity=0.0)
            yield retriever, store

    def test_search_single_collection(self, setup_retriever):
        """Test searching a single collection."""
        retriever, _ = setup_retriever

        results = retriever.search(
            query="SQL database injection",
            collection_name="cwe_database",
            top_k=2
        )

        assert len(results) > 0
        assert results[0].metadata["cwe_id"] == "CWE-89"
        assert 0.0 <= results[0].similarity <= 1.0

    def test_multi_search(self, setup_retriever):
        """Test searching multiple collections."""
        retriever, store = setup_retriever

        # Add to another collection
        kb = KnowledgeBase(store)
        kb.add_knowledge("owasp_top10_web", [
            SecurityKnowledge(
                id="owasp_a03",
                title="Injection",
                description="OWASP A03:2021 - Injection vulnerabilities",
                category="OWASP",
                owasp_id="A03"
            )
        ])

        results = retriever.multi_search(
            query="SQL injection",
            collections=["cwe_database", "owasp_top10_web"],
            top_k=3
        )

        assert len(results) > 0
        # Results should be from both collections
        sources = {r.metadata.get("cwe_id") or r.metadata.get("owasp_id") for r in results}
        assert len(sources) > 1

    def test_augment_prompt(self, setup_retriever):
        """Test prompt augmentation with relevant knowledge."""
        retriever, _ = setup_retriever

        base_prompt = "Analyze this code for security vulnerabilities"
        code_snippet = "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')"

        augmented_prompt = retriever.augment_prompt(
            base_prompt=base_prompt,
            code_snippet=code_snippet,
            vulnerability_type="SQL injection",
            top_k=3
        )

        assert len(augmented_prompt) > len(base_prompt)
        assert "Security Analysis Task" in augmented_prompt
        assert "Relevant Security Knowledge" in augmented_prompt
        assert "SQL Injection" in augmented_prompt or "CWE-89" in augmented_prompt

    def test_get_similar_vulnerabilities(self, setup_retriever):
        """Test finding similar vulnerabilities."""
        retriever, _ = setup_retriever

        results = retriever.get_similar_vulnerabilities(
            vulnerability_description="Database query manipulation attack",
            top_k=5
        )

        assert len(results) > 0
        # Should find SQL injection as most similar
        assert results[0].metadata["cwe_id"] == "CWE-89"

    def test_minimum_similarity_threshold(self, setup_retriever):
        """Test that minimum similarity threshold filters results."""
        retriever, _ = setup_retriever
        retriever.min_similarity = 0.8  # Very high threshold

        results = retriever.search(
            query="Completely unrelated topic like cooking recipes",
            collection_name="cwe_database",
            top_k=10
        )

        # Should return few or no results due to high threshold
        assert len(results) < 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
