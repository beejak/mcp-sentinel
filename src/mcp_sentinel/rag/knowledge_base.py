"""
Security knowledge base management.

Manages the collection, storage, and updating of security knowledge from various sources.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp_sentinel.rag.vector_store import VectorStore

logger = logging.getLogger(__name__)


class SecurityKnowledge:
    """Represents a single piece of security knowledge."""

    def __init__(
        self,
        id: str,
        title: str,
        description: str,
        category: str,
        severity: Optional[str] = None,
        cwe_id: Optional[str] = None,
        owasp_id: Optional[str] = None,
        framework: Optional[str] = None,
        code_example: Optional[str] = None,
        remediation: Optional[str] = None,
        references: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        source: Optional[str] = None,
        created_at: Optional[str] = None
    ):
        self.id = id
        self.title = title
        self.description = description
        self.category = category
        self.severity = severity
        self.cwe_id = cwe_id
        self.owasp_id = owasp_id
        self.framework = framework
        self.code_example = code_example
        self.remediation = remediation
        self.references = references or []
        self.tags = tags or []
        self.source = source
        self.created_at = created_at or datetime.utcnow().isoformat()

    def to_document(self) -> str:
        """Convert to text document for embedding."""
        parts = [
            f"Title: {self.title}",
            f"Category: {self.category}",
            f"Description: {self.description}"
        ]

        if self.cwe_id:
            parts.append(f"CWE: {self.cwe_id}")
        if self.owasp_id:
            parts.append(f"OWASP: {self.owasp_id}")
        if self.framework:
            parts.append(f"Framework: {self.framework}")
        if self.code_example:
            parts.append(f"Code Example:\n{self.code_example}")
        if self.remediation:
            parts.append(f"Remediation:\n{self.remediation}")

        return "\n\n".join(parts)

    def to_metadata(self) -> Dict[str, Any]:
        """Convert to metadata dictionary."""
        metadata = {
            "title": self.title,
            "category": self.category,
            "source": self.source or "unknown",
            "created_at": self.created_at
        }

        if self.severity:
            metadata["severity"] = self.severity
        if self.cwe_id:
            metadata["cwe_id"] = self.cwe_id
        if self.owasp_id:
            metadata["owasp_id"] = self.owasp_id
        if self.framework:
            metadata["framework"] = self.framework
        if self.tags:
            metadata["tags"] = ",".join(self.tags)

        return metadata

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityKnowledge":
        """Create from dictionary."""
        return cls(**data)


class KnowledgeBase:
    """
    Security knowledge base manager.

    Manages security knowledge from multiple sources:
    - Tier 1: OWASP Top 10 (LLM, Web, API)
    - Tier 1: CWE Database (Top 100 most common)
    - Tier 1: SANS Top 25
    - Tier 2: Framework-specific (Django, FastAPI, Express, Flask, React)
    - Continuous: CVE database
    - Continuous: GitHub Security Advisories
    - Continuous: Research Agent discoveries

    Collections:
    - owasp_top10_llm: OWASP Top 10 for LLMs
    - owasp_top10_web: OWASP Top 10 for Web
    - owasp_top10_api: OWASP Top 10 for APIs
    - cwe_database: CWE vulnerability patterns
    - sans_top25: SANS Top 25 weaknesses
    - framework_django: Django security patterns
    - framework_fastapi: FastAPI security patterns
    - framework_express: Express.js security patterns
    - framework_flask: Flask security patterns
    - framework_react: React security patterns
    - cve_database: CVE vulnerabilities
    - github_advisories: GitHub Security Advisories
    - research_agent: Research Agent discoveries
    """

    COLLECTIONS = {
        # Tier 1: Core Standards
        "owasp_top10_llm": "OWASP Top 10 for LLM Applications",
        "owasp_top10_web": "OWASP Top 10 for Web Applications",
        "owasp_top10_api": "OWASP API Security Top 10",
        "cwe_database": "CWE Vulnerability Database",
        "sans_top25": "SANS Top 25 Most Dangerous Weaknesses",

        # Tier 2: Framework-Specific
        "framework_django": "Django Security Patterns",
        "framework_fastapi": "FastAPI Security Patterns",
        "framework_express": "Express.js Security Patterns",
        "framework_flask": "Flask Security Patterns",
        "framework_react": "React Security Patterns",

        # Continuous Updates
        "cve_database": "CVE Vulnerability Database",
        "github_advisories": "GitHub Security Advisories",
        "research_agent": "Research Agent Discoveries"
    }

    def __init__(self, vector_store: VectorStore):
        """
        Initialize knowledge base.

        Args:
            vector_store: VectorStore instance
        """
        self.vector_store = vector_store
        logger.info("KnowledgeBase initialized")

    def add_knowledge(
        self,
        collection_name: str,
        knowledge_items: List[SecurityKnowledge]
    ) -> None:
        """
        Add security knowledge to a collection.

        Args:
            collection_name: Target collection
            knowledge_items: List of SecurityKnowledge items
        """
        if not knowledge_items:
            logger.warning(f"No knowledge items to add to {collection_name}")
            return

        documents = [item.to_document() for item in knowledge_items]
        metadatas = [item.to_metadata() for item in knowledge_items]
        ids = [item.id for item in knowledge_items]

        self.vector_store.add_documents(
            collection_name=collection_name,
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )

        logger.info(f"Added {len(knowledge_items)} knowledge items to '{collection_name}'")

    def update_knowledge(
        self,
        collection_name: str,
        knowledge_items: List[SecurityKnowledge]
    ) -> None:
        """
        Update existing knowledge items (upsert).

        Args:
            collection_name: Target collection
            knowledge_items: List of SecurityKnowledge items
        """
        documents = [item.to_document() for item in knowledge_items]
        metadatas = [item.to_metadata() for item in knowledge_items]
        ids = [item.id for item in knowledge_items]

        self.vector_store.upsert_documents(
            collection_name=collection_name,
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )

        logger.info(f"Updated {len(knowledge_items)} knowledge items in '{collection_name}'")

    def load_from_json(
        self,
        collection_name: str,
        json_file: Path
    ) -> int:
        """
        Load knowledge from JSON file.

        Args:
            collection_name: Target collection
            json_file: Path to JSON file

        Returns:
            Number of items loaded
        """
        logger.info(f"Loading knowledge from {json_file}")

        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        knowledge_items = [
            SecurityKnowledge.from_dict(item)
            for item in data
        ]

        self.add_knowledge(collection_name, knowledge_items)

        return len(knowledge_items)

    def export_to_json(
        self,
        collection_name: str,
        output_file: Path
    ) -> int:
        """
        Export collection to JSON file.

        Args:
            collection_name: Source collection
            output_file: Output JSON file path

        Returns:
            Number of items exported
        """
        # Get all documents from collection
        collection = self.vector_store.get_or_create_collection(collection_name)
        results = collection.get()

        # Convert to SecurityKnowledge objects
        items = []
        for i, doc_id in enumerate(results["ids"]):
            metadata = results["metadatas"][i] if results["metadatas"] else {}
            items.append({
                "id": doc_id,
                "title": metadata.get("title", ""),
                "description": results["documents"][i] if results["documents"] else "",
                "category": metadata.get("category", ""),
                "severity": metadata.get("severity"),
                "cwe_id": metadata.get("cwe_id"),
                "owasp_id": metadata.get("owasp_id"),
                "framework": metadata.get("framework"),
                "source": metadata.get("source"),
                "created_at": metadata.get("created_at"),
                "tags": metadata.get("tags", "").split(",") if metadata.get("tags") else []
            })

        # Write to JSON
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(items, f, indent=2, ensure_ascii=False)

        logger.info(f"Exported {len(items)} items to {output_file}")
        return len(items)

    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics for all collections.

        Returns:
            Dictionary with collection statistics
        """
        stats = {}
        for collection_name, description in self.COLLECTIONS.items():
            try:
                collection_stats = self.vector_store.get_collection_stats(collection_name)
                stats[collection_name] = {
                    "description": description,
                    "count": collection_stats["count"]
                }
            except Exception as e:
                logger.debug(f"Collection {collection_name} not found: {e}")
                stats[collection_name] = {
                    "description": description,
                    "count": 0
                }

        total_count = sum(s["count"] for s in stats.values())
        stats["_total"] = {"count": total_count}

        return stats

    def initialize_collections(self) -> None:
        """Initialize all predefined collections."""
        for collection_name, description in self.COLLECTIONS.items():
            self.vector_store.get_or_create_collection(collection_name)
            logger.debug(f"Initialized collection: {collection_name}")

        logger.info(f"Initialized {len(self.COLLECTIONS)} collections")
