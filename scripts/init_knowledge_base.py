#!/usr/bin/env python3
"""
Initialize the RAG knowledge base with security data.

Usage:
    python scripts/init_knowledge_base.py [--reset]

Options:
    --reset: Delete existing knowledge base and start fresh
"""

import argparse
import logging
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from mcp_sentinel.rag import VectorStore, KnowledgeBase
from mcp_sentinel.rag.data_loaders import populate_knowledge_base

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def main():
    """Initialize knowledge base."""
    parser = argparse.ArgumentParser(description="Initialize RAG knowledge base")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Delete existing knowledge base and start fresh"
    )
    parser.add_argument(
        "--persist-dir",
        type=str,
        default="./data/chroma_db",
        help="Directory for ChromaDB storage (default: ./data/chroma_db)"
    )
    args = parser.parse_args()

    logger.info("=== MCP Sentinel RAG Knowledge Base Initialization ===")

    # Initialize vector store
    logger.info(f"Initializing vector store at: {args.persist_dir}")
    store = VectorStore(persist_dir=args.persist_dir)

    # Reset if requested
    if args.reset:
        logger.warning("Resetting knowledge base (deleting all collections)...")
        store.reset()
        logger.info("Knowledge base reset complete")

    # Initialize knowledge base
    kb = KnowledgeBase(store)
    logger.info("Initializing collections...")
    kb.initialize_collections()

    # Populate knowledge base
    logger.info("Populating knowledge base with security data...")
    stats = populate_knowledge_base(kb)

    logger.info("\n=== Population Complete ===")
    for collection, count in stats.items():
        logger.info(f"  {collection}: {count} items")

    # Show final statistics
    logger.info("\n=== Knowledge Base Statistics ===")
    all_stats = kb.get_stats()
    for collection, info in all_stats.items():
        if collection != "_total":
            logger.info(f"  {collection}: {info['count']} items - {info.get('description', '')}")

    logger.info(f"\n✓ Total items in knowledge base: {all_stats['_total']['count']}")
    logger.info(f"✓ Persist directory: {args.persist_dir}")
    logger.info("\nKnowledge base is ready for use!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        sys.exit(1)
