"""
RAG (Retrieval-Augmented Generation) System for MCP Sentinel.

This module provides a comprehensive RAG system that enhances AI-powered
vulnerability detection by retrieving relevant security knowledge from a
vector database (ChromaDB).

Components:
- VectorStore: ChromaDB client for storing and querying embeddings
- EmbeddingService: SentenceTransformer wrapper for text embeddings
- KnowledgeBase: Management of security knowledge (OWASP, CWE, CVE, etc.)
- Retriever: Semantic search for relevant security patterns

Phase 4.4 - Week 1: RAG System Foundation
"""

from mcp_sentinel.rag.embeddings import EmbeddingService
from mcp_sentinel.rag.knowledge_base import KnowledgeBase
from mcp_sentinel.rag.retriever import Retriever
from mcp_sentinel.rag.vector_store import VectorStore

__all__ = [
    "VectorStore",
    "EmbeddingService",
    "KnowledgeBase",
    "Retriever",
]
