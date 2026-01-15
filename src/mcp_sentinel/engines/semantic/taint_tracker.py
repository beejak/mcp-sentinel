"""
Taint Tracking Engine for semantic analysis.

Implements forward dataflow analysis to track tainted data from sources to sinks.
"""

import ast

from mcp_sentinel.engines.semantic.models import (
    TaintPath,
    TaintSource,
    UnifiedAST,
)


class TaintTracker:
    """
    Tracks taint flow from sources to sinks using dataflow analysis.

    Uses a forward dataflow algorithm:
    1. Initialize tainted variables from sources
    2. Propagate taint through assignments
    3. Detect when tainted variables reach sinks
    4. Build vulnerability paths
    """

    # Sanitization functions that remove taint
    SANITIZERS = {
        "realpath",
        "abspath",
        "normpath",
        "canonical",
        "sanitize",
        "validate",
        "escape",
        "quote",
        "is_safe",
        "check_safe",
        "verify_safe",
        "resolve",
        "normalize",
    }

    def __init__(self, unified_ast: UnifiedAST):
        """
        Initialize taint tracker with parsed AST.

        Args:
            unified_ast: UnifiedAST containing sources and sinks
        """
        self.ast = unified_ast
        self.tainted: dict[str, TaintSource] = {}  # var_name -> source
        self.sanitized: set[str] = set()  # Variables that have been sanitized
        self.vulnerability_paths: list[TaintPath] = []

        # Initialize tainted variables from sources
        for source in unified_ast.sources:
            self.tainted[source.name] = source

    def track_flow(self) -> list[TaintPath]:
        """
        Track taint flow from sources to sinks.

        Returns:
            List of TaintPath objects representing vulnerabilities
        """
        if self.ast.language == "python":
            return self._track_python_flow()
        else:
            # For non-Python, use simple heuristic matching
            return self._track_simple_flow()

    def _track_python_flow(self) -> list[TaintPath]:
        """Track taint flow in Python AST."""
        paths = []

        # Walk through AST to track variable assignments
        visitor = TaintFlowVisitor(self.tainted, self.sanitized)
        visitor.visit(self.ast.raw_ast)

        # Check each sink to see if its arguments are tainted
        for sink in self.ast.sinks:
            # Check if any argument is tainted
            for arg_name in sink.arguments:
                if arg_name in self.tainted and arg_name not in self.sanitized:
                    # Found a vulnerability path!
                    source = self.tainted[arg_name]
                    path = TaintPath(
                        source=source,
                        sink=sink,
                        path=[f"{arg_name}@L{source.line}", f"{sink.function_name}@L{sink.line}"],
                        sanitized=False,
                        confidence=1.0,
                    )
                    paths.append(path)
                    sink.tainted_args.append(sink.arguments.index(arg_name))

        return paths

    def _track_simple_flow(self) -> list[TaintPath]:
        """
        Simple taint tracking for non-Python languages.

        Uses name matching heuristics instead of full dataflow.
        """
        paths = []

        # For each sink, check if arguments match source variable names
        for sink in self.ast.sinks:
            for arg_name in sink.arguments:
                # Check if argument name matches any source variable
                for source in self.ast.sources:
                    if source.name in arg_name or arg_name in source.name:
                        path = TaintPath(
                            source=source,
                            sink=sink,
                            path=[
                                f"{source.name}@L{source.line}",
                                f"{sink.function_name}@L{sink.line}",
                            ],
                            sanitized=False,
                            confidence=0.7,  # Lower confidence for heuristic
                        )
                        paths.append(path)
                        break

        return paths

    def is_tainted(self, var_name: str) -> bool:
        """
        Check if a variable is currently tainted.

        Args:
            var_name: Variable name to check

        Returns:
            True if variable is tainted, False otherwise
        """
        return var_name in self.tainted and var_name not in self.sanitized

    def add_sanitization(self, var_name: str):
        """
        Mark a variable as sanitized (no longer tainted).

        Args:
            var_name: Variable name to sanitize
        """
        self.sanitized.add(var_name)


class TaintFlowVisitor(ast.NodeVisitor):
    """
    AST visitor to track taint flow through variable assignments.

    Handles:
    - Variable assignments (taint propagation)
    - Function calls (sanitization detection)
    - Attribute assignments
    """

    def __init__(self, tainted: dict[str, TaintSource], sanitized: set[str]):
        """
        Initialize visitor.

        Args:
            tainted: Dictionary of tainted variables
            sanitized: Set of sanitized variables
        """
        self.tainted = tainted
        self.sanitized = sanitized

    def visit_Assign(self, node: ast.Assign):
        """Visit assignment to track taint propagation."""
        # Get target variable names
        targets = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                targets.append(target.id)

        # Check if RHS is tainted
        rhs_tainted = False
        source = None

        # Case 1: RHS is a tainted variable (x = tainted_var)
        if isinstance(node.value, ast.Name):
            rhs_name = node.value.id
            if rhs_name in self.tainted:
                rhs_tainted = True
                source = self.tainted[rhs_name]

        # Case 2: RHS is a binary operation with tainted operands
        elif isinstance(node.value, ast.BinOp):
            if self._is_binop_tainted(node.value):
                rhs_tainted = True
                # Use the first tainted operand as source
                source = self._get_tainted_from_binop(node.value)

        # Case 3: RHS is a function call
        elif isinstance(node.value, ast.Call):
            # Check if it's a sanitization function
            func_name = self._get_func_name(node.value.func)
            if func_name in TaintTracker.SANITIZERS:
                # This is a sanitization - mark any arguments as sanitized
                for arg in node.value.args:
                    if isinstance(arg, ast.Name) and arg.id in self.tainted:
                        self.sanitized.add(arg.id)
                rhs_tainted = False
            else:
                # Check if any arguments are tainted
                for arg in node.value.args:
                    if isinstance(arg, ast.Name) and arg.id in self.tainted:
                        rhs_tainted = True
                        source = self.tainted[arg.id]
                        break

        # Case 4: RHS is a string format/concat with tainted data
        elif isinstance(node.value, ast.JoinedStr):  # f-string
            for value in node.value.values:
                if isinstance(value, ast.FormattedValue):
                    if isinstance(value.value, ast.Name) and value.value.id in self.tainted:
                        rhs_tainted = True
                        source = self.tainted[value.value.id]
                        break

        # Propagate taint to targets
        if rhs_tainted and source:
            for target in targets:
                self.tainted[target] = source

        self.generic_visit(node)

    def _is_binop_tainted(self, node: ast.BinOp) -> bool:
        """Check if a binary operation involves tainted data."""
        # Check left operand
        if isinstance(node.left, ast.Name) and node.left.id in self.tainted:
            return True
        # Check right operand
        if isinstance(node.right, ast.Name) and node.right.id in self.tainted:
            return True
        return False

    def _get_tainted_from_binop(self, node: ast.BinOp) -> TaintSource | None:
        """Get the taint source from a binary operation."""
        if isinstance(node.left, ast.Name) and node.left.id in self.tainted:
            return self.tainted[node.left.id]
        if isinstance(node.right, ast.Name) and node.right.id in self.tainted:
            return self.tainted[node.right.id]
        return None

    def _get_func_name(self, node) -> str:
        """Extract function name from a Call node's func."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return ""


class InterproceduralTaintTracker(TaintTracker):
    """
    Advanced taint tracker with inter-procedural analysis.

    Tracks taint across function calls (Phase 4.3 feature).
    For Phase 4.2, we use conservative assumptions.
    """

    def __init__(self, unified_ast: UnifiedAST):
        super().__init__(unified_ast)
        self.function_summaries: dict[str, dict] = (
            {}
        )  # func_name -> {taints_params: [], returns_taint: bool}

    def analyze_function(self, func_name: str) -> dict:
        """
        Analyze a function to determine if it propagates taint.

        Args:
            func_name: Function name

        Returns:
            Summary dict with taint info
        """
        # TODO: Implement inter-procedural analysis
        # For now, assume all functions propagate taint conservatively
        return {
            "taints_params": list(range(10)),  # Assume all params can be tainted
            "returns_taint": True,  # Assume function returns tainted data
        }
