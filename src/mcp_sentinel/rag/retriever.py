"""
Semantic retrieval system for security knowledge.

Provides intelligent retrieval of relevant security patterns to enhance AI prompts.
"""

import logging
from typing import Any, Dict, List, Optional, Union

from mcp_sentinel.rag.vector_store import VectorStore

logger = logging.getLogger(__name__)


class RetrievalResult:
    """Represents a single retrieval result."""

    def __init__(
        self,
        id: str,
        document: str,
        metadata: Dict[str, Any],
        distance: float,
        similarity: float
    ):
        self.id = id
        self.document = document
        self.metadata = metadata
        self.distance = distance
        self.similarity = similarity  # 1 - distance (for cosine)

    def __repr__(self) -> str:
        return f"RetrievalResult(id={self.id}, similarity={self.similarity:.3f})"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "document": self.document,
            "metadata": self.metadata,
            "distance": self.distance,
            "similarity": self.similarity
        }


class Retriever:
    """
    Semantic retrieval system for security knowledge.

    Features:
    - Multi-collection search
    - Relevance filtering (minimum similarity threshold)
    - Metadata-based filtering
    - Context augmentation for AI prompts
    - Hybrid search (semantic + keyword)

    Usage:
        retriever = Retriever(vector_store)

        # Search single collection
        results = retriever.search(
            query="How to detect SQL injection in Python?",
            collection_name="cwe_database",
            top_k=5
        )

        # Search multiple collections
        results = retriever.multi_search(
            query="XSS vulnerability in React",
            collections=["owasp_top10_web", "framework_react"],
            top_k=3
        )

        # Augment AI prompt with relevant knowledge
        augmented_prompt = retriever.augment_prompt(
            base_prompt="Analyze this code for vulnerabilities",
            code_snippet="...",
            top_k=5
        )
    """

    def __init__(
        self,
        vector_store: VectorStore,
        min_similarity: float = 0.3
    ):
        """
        Initialize retriever.

        Args:
            vector_store: VectorStore instance
            min_similarity: Minimum similarity threshold (0.0 to 1.0)
        """
        self.vector_store = vector_store
        self.min_similarity = min_similarity
        logger.info(f"Retriever initialized (min_similarity={min_similarity})")

    def search(
        self,
        query: str,
        collection_name: str,
        top_k: int = 5,
        where: Optional[Dict[str, Any]] = None,
        min_similarity: Optional[float] = None
    ) -> List[RetrievalResult]:
        """
        Search a single collection.

        Args:
            query: Search query
            collection_name: Collection to search
            top_k: Number of results to return
            where: Metadata filter (e.g., {"severity": "CRITICAL"})
            min_similarity: Override default minimum similarity

        Returns:
            List of RetrievalResult objects
        """
        threshold = min_similarity if min_similarity is not None else self.min_similarity

        raw_results = self.vector_store.search(
            collection_name=collection_name,
            query=query,
            n_results=top_k,
            where=where
        )

        # Convert to RetrievalResult objects
        results = []
        for i in range(len(raw_results["ids"])):
            distance = raw_results["distances"][i]
            similarity = 1.0 - distance  # Cosine distance to similarity

            # Filter by similarity threshold
            if similarity >= threshold:
                results.append(RetrievalResult(
                    id=raw_results["ids"][i],
                    document=raw_results["documents"][i],
                    metadata=raw_results["metadatas"][i],
                    distance=distance,
                    similarity=similarity
                ))

        logger.debug(
            f"Search '{collection_name}': {len(results)}/{len(raw_results['ids'])} "
            f"results above similarity threshold {threshold}"
        )

        return results

    def multi_search(
        self,
        query: str,
        collections: Optional[List[str]] = None,
        top_k: int = 5,
        where: Optional[Dict[str, Any]] = None,
        min_similarity: Optional[float] = None
    ) -> List[RetrievalResult]:
        """
        Search multiple collections and merge results.

        Args:
            query: Search query
            collections: List of collections to search (None = all collections)
            top_k: Total number of results to return
            where: Metadata filter
            min_similarity: Override default minimum similarity

        Returns:
            List of RetrievalResult objects, sorted by similarity
        """
        if collections is None:
            collections = self.vector_store.list_collections()

        all_results = []
        per_collection_k = max(1, top_k // len(collections)) if collections else top_k

        for collection_name in collections:
            try:
                results = self.search(
                    query=query,
                    collection_name=collection_name,
                    top_k=per_collection_k,
                    where=where,
                    min_similarity=min_similarity
                )
                all_results.extend(results)
            except Exception as e:
                logger.warning(f"Error searching collection {collection_name}: {e}")

        # Sort by similarity and take top-k
        all_results.sort(key=lambda x: x.similarity, reverse=True)
        top_results = all_results[:top_k]

        logger.info(
            f"Multi-search across {len(collections)} collections: "
            f"found {len(top_results)} results"
        )

        return top_results

    def augment_prompt(
        self,
        base_prompt: str,
        code_snippet: Optional[str] = None,
        vulnerability_type: Optional[str] = None,
        framework: Optional[str] = None,
        top_k: int = 5,
        min_similarity: float = 0.5
    ) -> str:
        """
        Augment AI prompt with relevant security knowledge.

        Args:
            base_prompt: Base prompt for AI
            code_snippet: Code to analyze (optional)
            vulnerability_type: Specific vulnerability type to focus on
            framework: Framework context (e.g., "Django", "React")
            top_k: Number of knowledge items to include
            min_similarity: Minimum similarity threshold (default: 0.5)

        Returns:
            Augmented prompt with relevant security knowledge
        """
        # Build search query
        query_parts = []
        if vulnerability_type:
            query_parts.append(vulnerability_type)
        if framework:
            query_parts.append(framework)
        if code_snippet:
            query_parts.append(code_snippet[:500])  # First 500 chars

        query = " ".join(query_parts) if query_parts else base_prompt

        # Determine collections to search
        collections = None
        if framework:
            framework_collection = f"framework_{framework.lower()}"
            if framework_collection in self.vector_store.list_collections():
                collections = [framework_collection, "cwe_database", "owasp_top10_llm"]

        # Retrieve relevant knowledge
        results = self.multi_search(
            query=query,
            collections=collections,
            top_k=top_k,
            min_similarity=min_similarity
        )

        if not results:
            logger.debug("No relevant knowledge found for prompt augmentation")
            return base_prompt

        # Build augmented prompt
        knowledge_context = self._build_knowledge_context(results)

        augmented_prompt = f"""# Security Analysis Task

{base_prompt}

## Relevant Security Knowledge (from knowledge base):

{knowledge_context}

## Instructions:
- Use the above security knowledge to enhance your analysis
- Look for patterns similar to the examples provided
- Apply framework-specific guidance if available
- Provide specific CWE/OWASP references where applicable

"""

        logger.info(f"Augmented prompt with {len(results)} knowledge items")
        return augmented_prompt

    def format_results(self, results: List[RetrievalResult]) -> str:
        """
        Format retrieval results into a knowledge context string.

        Args:
            results: List of RetrievalResult objects

        Returns:
            Formatted knowledge context string
        """
        context_parts = []

        for i, result in enumerate(results, 1):
            metadata = result.metadata
            title = metadata.get("title", "Unknown")
            metadata.get("category", "Unknown")
            cwe_id = metadata.get("cwe_id", "")
            owasp_id = metadata.get("owasp_id", "")

            header = f"### {i}. {title}"
            if cwe_id or owasp_id:
                refs = []
                if cwe_id:
                    refs.append(f"CWE: {cwe_id}")
                if owasp_id:
                    refs.append(f"OWASP: {owasp_id}")
                header += f" ({', '.join(refs)})"

            content = result.document.strip()
            # Truncate if too long
            if len(content) > 1000:
                content = content[:997] + "..."

            context_parts.append(f"{header}\n{content}\n")

        return "\n".join(context_parts)

    def _build_knowledge_context(self, results: list[RetrievalResult]) -> str:
        """
        Build formatted knowledge context from retrieval results.

        Deprecated: Use format_results instead.
        """
        return self.format_results(results)

    def get_similar_vulnerabilities(
        self,
        vulnerability_description: str,
        top_k: int = 10
    ) -> list[RetrievalResult]:
        """
        Find similar known vulnerabilities.

        Args:
            vulnerability_description: Description of the vulnerability
            top_k: Number of similar vulnerabilities to return

        Returns:
            List of similar vulnerabilities
        """
        return self.multi_search(
            query=vulnerability_description,
            collections=[
                "cwe_database",
                "owasp_top10_llm",
                "github_advisories",
                "research_agent"
            ],
            top_k=top_k,
            min_similarity=0.4
        )

    def search_by_framework(
        self,
        query: str,
        framework: str,
        top_k: int = 5
    ) -> list[RetrievalResult]:
        """
        Search framework-specific security patterns.

        Args:
            query: Search query
            framework: Framework name (e.g., "django", "react")
            top_k: Number of results

        Returns:
            List of framework-specific results
        """
        collection_name = f"framework_{framework.lower()}"

        return self.search(
            query=query,
            collection_name=collection_name,
            top_k=top_k
        )

    def search_by_cwe(
        self,
        cwe_id: str,
        top_k: int = 5
    ) -> list[RetrievalResult]:
        """
        Search by CWE ID.

        Args:
            cwe_id: CWE identifier (e.g., "CWE-89")
            top_k: Number of results

        Returns:
            List of results for the specified CWE
        """
        return self.search(
            query=cwe_id,
            collection_name="cwe_database",
            top_k=top_k,
            where={"cwe_id": cwe_id}
        )
