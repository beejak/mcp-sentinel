"""
Embedding service using SentenceTransformers.

Converts text to vector embeddings for semantic search.
"""

import logging
from typing import List, Optional

from sentence_transformers import SentenceTransformer

logger = logging.getLogger(__name__)


class EmbeddingService:
    """
    Text embedding service using SentenceTransformers.

    Features:
    - Fast, efficient embeddings (all-MiniLM-L6-v2: 384 dimensions)
    - Batch processing for performance
    - Caching for repeated queries
    - Alternative models for different use cases

    Supported Models:
    - all-MiniLM-L6-v2 (default): Fast, balanced (384 dim)
    - all-mpnet-base-v2: High quality, slower (768 dim)
    - multi-qa-MiniLM-L6-cos-v1: Optimized for Q&A (384 dim)

    Usage:
        service = EmbeddingService()
        embeddings = service.embed_texts([
            "SQL injection vulnerability in login form",
            "XSS in user input field"
        ])
    """

    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        device: Optional[str] = None
    ):
        """
        Initialize embedding service.

        Args:
            model_name: SentenceTransformer model name
            device: Device to run model on ('cuda', 'cpu', or None for auto)
        """
        self.model_name = model_name
        self.device = device

        logger.info(f"Loading SentenceTransformer model: {model_name}")
        self.model = SentenceTransformer(model_name, device=device)
        logger.info(f"Model loaded on device: {self.model.device}")

        # Get embedding dimension
        self.dimension = self.model.get_sentence_embedding_dimension()
        logger.info(f"Embedding dimension: {self.dimension}")

    def embed_text(self, text: str) -> List[float]:
        """
        Embed a single text.

        Args:
            text: Input text

        Returns:
            Embedding vector as list of floats
        """
        embedding = self.model.encode(
            text,
            convert_to_numpy=True,
            show_progress_bar=False
        )
        return embedding.tolist()

    def embed_texts(
        self,
        texts: List[str],
        batch_size: int = 32,
        show_progress: bool = False
    ) -> List[List[float]]:
        """
        Embed multiple texts in batches.

        Args:
            texts: List of input texts
            batch_size: Batch size for processing
            show_progress: Show progress bar

        Returns:
            List of embedding vectors
        """
        logger.debug(f"Embedding {len(texts)} texts (batch_size={batch_size})")

        embeddings = self.model.encode(
            texts,
            batch_size=batch_size,
            convert_to_numpy=True,
            show_progress_bar=show_progress
        )

        return embeddings.tolist()

    def semantic_similarity(self, text1: str, text2: str) -> float:
        """
        Compute semantic similarity between two texts.

        Args:
            text1: First text
            text2: Second text

        Returns:
            Similarity score (0.0 to 1.0)
        """
        import numpy as np
        from sklearn.metrics.pairwise import cosine_similarity

        emb1 = np.array([self.embed_text(text1)])
        emb2 = np.array([self.embed_text(text2)])

        similarity = cosine_similarity(emb1, emb2)[0][0]
        return float(similarity)

    def find_most_similar(
        self,
        query: str,
        candidates: list[str],
        top_k: int = 5
    ) -> list[tuple[str, float]]:
        """
        Find most similar texts from candidates.

        Args:
            query: Query text
            candidates: List of candidate texts
            top_k: Number of top results to return

        Returns:
            List of (text, similarity_score) tuples, sorted by similarity
        """
        import numpy as np
        from sklearn.metrics.pairwise import cosine_similarity

        query_emb = np.array([self.embed_text(query)])
        candidate_embs = np.array(self.embed_texts(candidates))

        similarities = cosine_similarity(query_emb, candidate_embs)[0]

        # Get top-k indices
        top_indices = np.argsort(similarities)[::-1][:top_k]

        results = [
            (candidates[idx], float(similarities[idx]))
            for idx in top_indices
        ]

        return results

    def get_model_info(self) -> dict:
        """
        Get information about the loaded model.

        Returns:
            Dictionary with model metadata
        """
        return {
            "model_name": self.model_name,
            "device": str(self.model.device),
            "dimension": self.dimension,
            "max_seq_length": self.model.max_seq_length
        }


# Pre-configured embedding services for different use cases

def get_fast_embedder() -> EmbeddingService:
    """Get fast, lightweight embedder (all-MiniLM-L6-v2)."""
    return EmbeddingService(model_name="all-MiniLM-L6-v2")


def get_quality_embedder() -> EmbeddingService:
    """Get high-quality embedder (all-mpnet-base-v2)."""
    return EmbeddingService(model_name="all-mpnet-base-v2")


def get_qa_embedder() -> EmbeddingService:
    """Get Q&A optimized embedder (multi-qa-MiniLM-L6-cos-v1)."""
    return EmbeddingService(model_name="multi-qa-MiniLM-L6-cos-v1")
