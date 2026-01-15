"""
Semantic Analysis Engine - Main Entry Point.

Combines AST parsing, taint tracking, and CFG analysis into a unified engine.
"""

import time

from mcp_sentinel.engines.semantic.ast_parser import ASTParser
from mcp_sentinel.engines.semantic.cfg_builder import SimpleCFGBuilder
from mcp_sentinel.engines.semantic.models import (
    SemanticAnalysisResult,
    TaintPath,
)
from mcp_sentinel.engines.semantic.taint_tracker import TaintTracker


class SemanticEngine:
    """
    Main semantic analysis engine.

    Provides high-level API for detecting vulnerabilities using semantic analysis.
    """

    def __init__(self, enable_cfg: bool = True):
        """
        Initialize semantic engine.

        Args:
            enable_cfg: Enable control flow analysis (slower but more accurate)
        """
        self.parser = ASTParser()
        self.enable_cfg = enable_cfg
        self.cfg_builder = SimpleCFGBuilder() if enable_cfg else None

    def analyze(self, code: str, file_path: str, language: str) -> SemanticAnalysisResult:
        """
        Perform semantic analysis on code.

        Args:
            code: Source code
            file_path: Path to file
            language: Programming language

        Returns:
            SemanticAnalysisResult with vulnerability paths
        """
        start_time = time.time()
        errors = []

        try:
            # Step 1: Parse AST and extract sources/sinks
            ast_result = self.parser.parse(code, language)
            if not ast_result:
                return SemanticAnalysisResult(
                    file_path=file_path,
                    language=language,
                    taint_paths=[],
                    errors=["Failed to parse code"],
                )

            # Step 2: Track taint flow
            tracker = TaintTracker(ast_result)
            taint_paths = tracker.track_flow()

            # Step 3: Build CFG and filter false positives (optional)
            cfg = None
            if self.enable_cfg and ast_result.language == "python":
                try:
                    cfg = self.cfg_builder.build(ast_result.raw_ast)

                    # Filter paths that have validation guards
                    filtered_paths = []
                    for path in taint_paths:
                        if not self._is_false_positive(path, cfg):
                            filtered_paths.append(path)
                    taint_paths = filtered_paths
                except Exception as e:
                    errors.append(f"CFG analysis failed: {str(e)}")

            analysis_time = (time.time() - start_time) * 1000  # Convert to ms

            return SemanticAnalysisResult(
                file_path=file_path,
                language=language,
                taint_paths=taint_paths,
                cfg=cfg,
                analysis_time_ms=analysis_time,
                errors=errors,
            )

        except Exception as e:
            return SemanticAnalysisResult(
                file_path=file_path,
                language=language,
                taint_paths=[],
                errors=[f"Analysis failed: {str(e)}"],
            )

    def _is_false_positive(self, path: TaintPath, cfg) -> bool:
        """
        Check if a taint path is likely a false positive.

        Uses control flow analysis to detect validation guards.

        Args:
            path: Taint path to check
            cfg: Control flow graph

        Returns:
            True if likely false positive, False otherwise
        """
        if not cfg:
            return False

        # Check if there are validation guards between source and sink
        is_safe = self.cfg_builder.is_path_safe(
            cfg, path.source.line, path.sink.line, path.source.name
        )

        return is_safe

    def quick_check(self, code: str, language: str) -> bool:
        """
        Quick check if code has potential vulnerabilities.

        Faster than full analysis - just checks for sources and sinks.

        Args:
            code: Source code
            language: Programming language

        Returns:
            True if potential vulnerabilities found, False otherwise
        """
        ast_result = self.parser.parse(code, language)
        if not ast_result:
            return False

        # Quick heuristic: if there are both sources and sinks, likely vulnerable
        return len(ast_result.sources) > 0 and len(ast_result.sinks) > 0


# Global instance for easy access
_default_engine = None


def get_semantic_engine(enable_cfg: bool = True) -> SemanticEngine:
    """
    Get or create the default semantic engine instance.

    Args:
        enable_cfg: Enable CFG analysis

    Returns:
        SemanticEngine instance
    """
    global _default_engine
    if _default_engine is None:
        _default_engine = SemanticEngine(enable_cfg=enable_cfg)
    return _default_engine


def analyze_code(code: str, file_path: str, language: str) -> SemanticAnalysisResult:
    """
    Convenience function to analyze code.

    Args:
        code: Source code
        file_path: Path to file
        language: Programming language

    Returns:
        SemanticAnalysisResult
    """
    engine = get_semantic_engine()
    return engine.analyze(code, file_path, language)
