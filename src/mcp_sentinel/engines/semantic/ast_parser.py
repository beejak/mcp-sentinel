"""
AST Parser for semantic analysis.

Parses source code into Abstract Syntax Trees and extracts taint sources/sinks.
Supports Python, JavaScript, and Java.
"""

import ast
import re

from mcp_sentinel.engines.semantic.models import (
    SinkType,
    TaintSink,
    TaintSource,
    TaintType,
    UnifiedAST,
)


class ASTParser:
    """Multi-language AST parser with taint source/sink extraction."""

    # Common taint source patterns (request, params, query, etc.)
    TAINT_SOURCE_PATTERNS = {
        "user_input": [
            r"request\.(args|form|data|json|params|query|cookies)",
            r"params\.",
            r"query\.",
            r"req\.(params|query|body|cookies)",
            r"\.getParameter\(",
            r"\.get\(['\"]",
        ],
        "file_system": [
            r"\.read\(",
            r"\.readFile\(",
            r"\.open\(",
        ],
        "environment": [
            r"os\.environ",
            r"process\.env",
            r"System\.getenv",
        ],
    }

    # Dangerous sink functions
    DANGEROUS_SINKS = {
        SinkType.FILE_OPERATION: ["open", "readFile", "writeFile", "File"],
        SinkType.COMMAND_EXECUTION: ["system", "popen", "spawn", "Runtime.exec"],
        SinkType.CODE_EVALUATION: ["eval", "exec", "Function", "compile"],
        SinkType.PATH_OPERATION: ["join", "resolve", "normalize", "File", "Paths.get"],
    }

    def __init__(self):
        """Initialize AST parser."""
        pass

    def parse(self, code: str, language: str) -> UnifiedAST | None:
        """
        Parse code into unified AST.

        Args:
            code: Source code string
            language: Programming language

        Returns:
            UnifiedAST object or None if parsing fails
        """
        if language == "python":
            return self._parse_python(code)
        elif language in ["javascript", "typescript"]:
            return self._parse_javascript(code)
        elif language == "java":
            return self._parse_java(code)
        else:
            return None

    def _parse_python(self, code: str) -> UnifiedAST | None:
        """Parse Python code using built-in ast module."""
        try:
            tree = ast.parse(code)
            unified_ast = UnifiedAST(language="python", raw_ast=tree)

            # Extract sources and sinks
            visitor = PythonTaintVisitor()
            visitor.visit(tree)

            unified_ast.sources = visitor.sources
            unified_ast.sinks = visitor.sinks
            unified_ast.variables = visitor.variables
            unified_ast.functions = visitor.functions

            return unified_ast
        except SyntaxError:
            # Invalid Python syntax
            return None

    def _parse_javascript(self, code: str) -> UnifiedAST | None:
        """Parse JavaScript code (stub for now - requires esprima)."""
        # TODO: Implement JavaScript parsing using esprima
        # For now, return a basic UnifiedAST with regex-based extraction
        unified_ast = UnifiedAST(language="javascript", raw_ast=None)
        unified_ast.sources = self._extract_sources_regex(code, "javascript")
        unified_ast.sinks = self._extract_sinks_regex(code, "javascript")
        return unified_ast

    def _parse_java(self, code: str) -> UnifiedAST | None:
        """Parse Java code (stub for now - requires javalang)."""
        # TODO: Implement Java parsing using javalang
        unified_ast = UnifiedAST(language="java", raw_ast=None)
        unified_ast.sources = self._extract_sources_regex(code, "java")
        unified_ast.sinks = self._extract_sinks_regex(code, "java")
        return unified_ast

    def _extract_sources_regex(self, code: str, language: str) -> list[TaintSource]:
        """Fallback: Extract taint sources using regex (for non-Python)."""
        sources = []
        lines = code.split("\n")

        for line_num, line in enumerate(lines, start=1):
            for taint_type, patterns in self.TAINT_SOURCE_PATTERNS.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        # Try to extract variable name
                        var_match = re.search(r"(\w+)\s*=\s*" + pattern, line)
                        var_name = var_match.group(1) if var_match else "unknown"

                        sources.append(
                            TaintSource(
                                name=var_name,
                                line=line_num,
                                column=match.start(),
                                taint_type=TaintType(taint_type),
                                origin=match.group(0),
                                confidence=0.7,  # Lower confidence for regex
                            )
                        )
        return sources

    def _extract_sinks_regex(self, code: str, language: str) -> list[TaintSink]:
        """Fallback: Extract sinks using regex (for non-Python)."""
        sinks = []
        lines = code.split("\n")

        for line_num, line in enumerate(lines, start=1):
            for sink_type, functions in self.DANGEROUS_SINKS.items():
                for func in functions:
                    pattern = rf"\b{re.escape(func)}\s*\("
                    matches = re.finditer(pattern, line)
                    for match in matches:
                        # Extract arguments (simplified)
                        args_start = match.end()
                        args_end = line.find(")", args_start)
                        if args_end > args_start:
                            args_str = line[args_start:args_end]
                            arguments = [arg.strip() for arg in args_str.split(",")]
                        else:
                            arguments = []

                        sinks.append(
                            TaintSink(
                                function_name=func,
                                line=line_num,
                                column=match.start(),
                                sink_type=sink_type,
                                arguments=arguments,
                                confidence=0.7,  # Lower confidence for regex
                            )
                        )
        return sinks


class PythonTaintVisitor(ast.NodeVisitor):
    """AST visitor to extract taint sources and sinks from Python code."""

    def __init__(self):
        self.sources: list[TaintSource] = []
        self.sinks: list[TaintSink] = []
        self.variables: dict = {}  # Track variable assignments
        self.functions: list[dict] = []  # Track function definitions
        self.current_line = 0

    def visit_Assign(self, node: ast.Assign):
        """Visit assignment statements to track variable flow."""
        self.current_line = node.lineno

        # Get target variable name(s)
        targets = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                targets.append(target.id)

        # Check if RHS is a taint source
        if isinstance(node.value, ast.Call):
            source = self._check_taint_source(node.value)
            if source and targets:
                source.name = targets[0]  # Assign to first target
                self.sources.append(source)
                # Track variable as tainted
                for target in targets:
                    self.variables[target] = {
                        "tainted": True,
                        "line": node.lineno,
                        "source": source.origin,
                    }
        elif isinstance(node.value, ast.Attribute):
            source = self._check_attribute_source(node.value)
            if source and targets:
                source.name = targets[0]
                self.sources.append(source)
                for target in targets:
                    self.variables[target] = {
                        "tainted": True,
                        "line": node.lineno,
                        "source": source.origin,
                    }

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Visit function calls to detect dangerous sinks."""
        self.current_line = node.lineno

        # Check if this is a dangerous sink
        sink = self._check_dangerous_sink(node)
        if sink:
            self.sinks.append(sink)

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Track function definitions."""
        self.functions.append(
            {
                "name": node.name,
                "line": node.lineno,
                "args": [arg.arg for arg in node.args.args],
            }
        )
        self.generic_visit(node)

    def _check_taint_source(self, node: ast.Call) -> TaintSource | None:
        """Check if a function call is a taint source."""
        # Check for request.args.get(), request.form.get(), os.environ.get(), etc.
        if isinstance(node.func, ast.Attribute):
            origin = self._get_attribute_chain(node.func)

            # Check against ALL taint source patterns
            for taint_type_str, patterns in ASTParser.TAINT_SOURCE_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, origin, re.IGNORECASE):
                        return TaintSource(
                            name="unknown",  # Will be set by caller
                            line=node.lineno,
                            column=node.col_offset,
                            taint_type=TaintType(taint_type_str),
                            origin=origin,
                            confidence=1.0,
                        )

        return None

    def _check_attribute_source(self, node: ast.Attribute) -> TaintSource | None:
        """Check if an attribute access is a taint source."""
        origin = self._get_attribute_chain(node)

        # Check against patterns
        for pattern in ASTParser.TAINT_SOURCE_PATTERNS["user_input"]:
            if re.search(pattern, origin, re.IGNORECASE):
                return TaintSource(
                    name="unknown",
                    line=node.lineno,
                    column=node.col_offset,
                    taint_type=TaintType.USER_INPUT,
                    origin=origin,
                    confidence=1.0,
                )

        # Check environment variables
        if "environ" in origin or "getenv" in origin:
            return TaintSource(
                name="unknown",
                line=node.lineno,
                column=node.col_offset,
                taint_type=TaintType.ENVIRONMENT,
                origin=origin,
                confidence=1.0,
            )

        return None

    def _check_dangerous_sink(self, node: ast.Call) -> TaintSink | None:
        """Check if a function call is a dangerous sink."""
        func_name = None

        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if not func_name:
            return None

        # Check against dangerous sinks
        for sink_type, functions in ASTParser.DANGEROUS_SINKS.items():
            if func_name in functions:
                # Extract argument expressions
                arguments = []
                for arg in node.args:
                    if isinstance(arg, ast.Name):
                        arguments.append(arg.id)
                    elif isinstance(arg, ast.Constant):
                        arguments.append(str(arg.value))
                    elif isinstance(arg, ast.Attribute):
                        arguments.append(self._get_attribute_chain(arg))
                    else:
                        arguments.append("complex_expr")

                return TaintSink(
                    function_name=func_name,
                    line=node.lineno,
                    column=node.col_offset,
                    sink_type=sink_type,
                    arguments=arguments,
                    confidence=1.0,
                )

        return None

    def _get_attribute_chain(self, node: ast.Attribute) -> str:
        """Get full attribute chain (e.g., 'request.args.get')."""
        parts = [node.attr]
        current = node.value

        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value

        if isinstance(current, ast.Name):
            parts.append(current.id)

        return ".".join(reversed(parts))
