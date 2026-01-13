"""
Semantic Analysis Engine.

Provides AST parsing, taint tracking, and control flow analysis.
"""

from mcp_sentinel.engines.semantic.semantic_engine import (
    SemanticEngine,
    get_semantic_engine,
    analyze_code,
)

__all__ = [
    "SemanticEngine",
    "get_semantic_engine",
    "analyze_code",
]
