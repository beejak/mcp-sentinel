"""
Control Flow Graph Builder (Simplified).

Builds basic control flow graphs for guard detection.
Phase 4.2 version - focuses on validation guard detection.
Full CFG implementation deferred to Phase 4.3.
"""

import ast

from mcp_sentinel.engines.semantic.models import (
    CFGNode,
    ControlFlowGraph,
    Guard,
)


class SimpleCFGBuilder:
    """
    Simplified CFG builder for Phase 4.2.

    Focuses on detecting validation guards (if statements that check inputs).
    Full control flow analysis deferred to Phase 4.3.
    """

    def __init__(self):
        self.node_counter = 0

    def build(self, code_ast: ast.AST) -> ControlFlowGraph:
        """
        Build a simplified CFG from Python AST.

        Args:
            code_ast: Python AST

        Returns:
            ControlFlowGraph with basic structure
        """
        cfg = ControlFlowGraph(nodes={}, entry_node=0, exit_nodes=[])
        self.node_counter = 0

        # Extract validation guards (if statements)
        visitor = GuardExtractor()
        visitor.visit(code_ast)

        # Create entry node
        entry = CFGNode(
            node_id=self._next_id(),
            node_type="entry",
            line=1,
            content="<entry>",
            guards=visitor.guards,
        )
        cfg.nodes[entry.node_id] = entry
        cfg.entry_node = entry.node_id

        # Create exit node
        exit_node = CFGNode(
            node_id=self._next_id(), node_type="exit", line=999999, content="<exit>"
        )
        cfg.nodes[exit_node.node_id] = exit_node
        cfg.exit_nodes = [exit_node.node_id]

        # Connect entry → exit
        cfg.add_edge(entry.node_id, exit_node.node_id)

        return cfg

    def find_guards_before_line(self, cfg: ControlFlowGraph, line: int) -> list[Guard]:
        """
        Find all guards that execute before a given line.

        Args:
            cfg: Control flow graph
            line: Line number

        Returns:
            List of Guard objects
        """
        # Simplified: return all guards before the line
        all_guards = []
        for node in cfg.nodes.values():
            all_guards.extend([g for g in node.guards if g.line < line])
        return all_guards

    def is_path_safe(
        self, cfg: ControlFlowGraph, source_line: int, sink_line: int, var_name: str
    ) -> bool:
        """
        Check if all paths from source to sink have validation guards.

        Args:
            cfg: Control flow graph
            source_line: Source line number
            sink_line: Sink line number
            var_name: Variable name to check

        Returns:
            True if safe (validated on all paths), False if potentially unsafe
        """
        # Find guards between source and sink
        guards = self.find_guards_before_line(cfg, sink_line)

        # Check if any guard validates the variable
        for guard in guards:
            if guard.line > source_line and guard.line < sink_line:
                if var_name in guard.variables:
                    # Found a validation guard!
                    if guard.is_exit:
                        # Guard causes early return/throw - path is safe
                        return True

        return False

    def _next_id(self) -> int:
        """Get next node ID."""
        node_id = self.node_counter
        self.node_counter += 1
        return node_id


class GuardExtractor(ast.NodeVisitor):
    """
    Extracts validation guards from Python AST.

    Guards are if statements that check variables for safety.
    """

    def __init__(self):
        self.guards: list[Guard] = []

    def visit_If(self, node: ast.If):
        """Visit if statements to extract guards."""
        # Extract condition as string
        condition = ast.unparse(node.test) if hasattr(ast, "unparse") else str(node.test)

        # Determine if this is a validation guard
        guard_type = self._classify_guard(condition)

        if guard_type:
            # Extract variables mentioned in condition
            variables = self._extract_variables(node.test)

            # Check if this guard causes early exit
            is_exit = self._has_early_exit(node)

            guard = Guard(
                condition=condition,
                line=node.lineno,
                guard_type=guard_type,
                variables=variables,
                is_exit=is_exit,
            )
            self.guards.append(guard)

        self.generic_visit(node)

    def _classify_guard(self, condition: str) -> str | None:
        """
        Classify guard type based on condition.

        Args:
            condition: Condition string

        Returns:
            Guard type or None if not a guard
        """
        condition_lower = condition.lower()

        # Check for common validation patterns
        validation_patterns = [
            "..",
            "startswith",
            "endswith",
            "in",
            "==",
            "!=",
            "is",
            "not",
            "contains",
            "match",
            "validate",
            "check",
        ]

        for pattern in validation_patterns:
            if pattern in condition_lower:
                return "validation"

        # Check for sanitization
        if "sanitize" in condition_lower or "clean" in condition_lower:
            return "sanitization"

        # Check for bounds checks
        if any(op in condition for op in ["<", ">", "<=", ">="]):
            return "bounds_check"

        return None

    def _extract_variables(self, node: ast.expr) -> set[str]:
        """Extract variable names from condition."""
        variables = set()

        class VarVisitor(ast.NodeVisitor):
            def visit_Name(self, n):
                variables.add(n.id)

        VarVisitor().visit(node)
        return variables

    def _has_early_exit(self, if_node: ast.If) -> bool:
        """Check if if block has return/raise/continue/break."""
        for stmt in if_node.body:
            if isinstance(stmt, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
                return True
        return False


# Convenience function
def build_cfg(code: str) -> ControlFlowGraph:
    """
    Build CFG from Python code string.

    Args:
        code: Python source code

    Returns:
        ControlFlowGraph
    """
    tree = ast.parse(code)
    builder = SimpleCFGBuilder()
    return builder.build(tree)
