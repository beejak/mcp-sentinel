"""
Data models for semantic analysis engine.

Defines core structures for taint tracking, control flow, and AST representation.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TaintType(Enum):
    """Types of taint sources."""

    USER_INPUT = "user_input"  # request.*, params.*, query.*
    FILE_SYSTEM = "file_system"  # file paths, file contents
    NETWORK = "network"  # network requests, sockets
    ENVIRONMENT = "environment"  # env vars, config
    DATABASE = "database"  # database queries


class SinkType(Enum):
    """Types of dangerous sinks."""

    FILE_OPERATION = "file_operation"  # open(), readFile(), etc.
    COMMAND_EXECUTION = "command_execution"  # exec(), system(), etc.
    CODE_EVALUATION = "code_evaluation"  # eval(), Function(), etc.
    SQL_QUERY = "sql_query"  # SQL operations
    NETWORK_REQUEST = "network_request"  # HTTP requests
    PATH_OPERATION = "path_operation"  # path.join(), File(), etc.


@dataclass
class TaintSource:
    """Represents a taint source (user input, external data, etc.)."""

    name: str  # Variable name
    line: int  # Line number
    column: int  # Column number
    taint_type: TaintType  # Type of taint
    origin: str  # Origin expression (e.g., "request.args.get('file')")
    confidence: float = 1.0  # Confidence level (0.0-1.0)

    def __hash__(self):
        return hash((self.name, self.line, self.column))

    def __eq__(self, other):
        if not isinstance(other, TaintSource):
            return False
        return self.name == other.name and self.line == other.line and self.column == other.column


@dataclass
class TaintSink:
    """Represents a dangerous operation that could be exploited."""

    function_name: str  # Function name (e.g., "open", "exec")
    line: int  # Line number
    column: int  # Column number
    sink_type: SinkType  # Type of sink
    arguments: list[str]  # Argument expressions
    tainted_args: list[int] = field(default_factory=list)  # Indices of tainted args
    confidence: float = 1.0  # Confidence level

    def __hash__(self):
        return hash((self.function_name, self.line, self.column))

    def __eq__(self, other):
        if not isinstance(other, TaintSink):
            return False
        return (
            self.function_name == other.function_name
            and self.line == other.line
            and self.column == other.column
        )


@dataclass
class TaintPath:
    """Represents a vulnerability path from source to sink."""

    source: TaintSource  # Taint source
    sink: TaintSink  # Dangerous sink
    path: list[str]  # Intermediate steps (variable names, assignments)
    sanitized: bool = False  # Whether taint was sanitized
    sanitizers: list[str] = field(default_factory=list)  # Sanitization functions
    confidence: float = 1.0  # Overall confidence

    def __repr__(self):
        return (
            f"TaintPath({self.source.name}@L{self.source.line} -> "
            f"{self.sink.function_name}@L{self.sink.line})"
        )


@dataclass
class Guard:
    """Represents a validation guard (if statement checking input)."""

    condition: str  # Guard condition expression
    line: int  # Line number
    guard_type: str  # Type: "validation", "sanitization", "bounds_check"
    variables: set[str] = field(default_factory=set)  # Variables involved
    is_exit: bool = False  # Does this guard exit (return, throw)?

    def __repr__(self):
        return f"Guard({self.guard_type}: {self.condition} @L{self.line})"


@dataclass
class CFGNode:
    """Control Flow Graph node."""

    node_id: int  # Unique node ID
    node_type: str  # "statement", "branch", "loop", "return", "merge"
    line: int  # Line number
    content: str  # Node content (code)
    successors: list[int] = field(default_factory=list)  # Next nodes
    predecessors: list[int] = field(default_factory=list)  # Previous nodes
    guards: list[Guard] = field(default_factory=list)  # Guards on this path

    def __repr__(self):
        return f"CFGNode({self.node_type}@L{self.line}: {self.content[:30]})"


@dataclass
class ControlFlowGraph:
    """Control flow graph for a function or code block."""

    nodes: dict[int, CFGNode]  # node_id -> CFGNode
    entry_node: int  # Entry point node ID
    exit_nodes: list[int]  # Exit point node IDs

    def add_edge(self, from_id: int, to_id: int):
        """Add edge from one node to another."""
        if from_id in self.nodes and to_id in self.nodes:
            self.nodes[from_id].successors.append(to_id)
            self.nodes[to_id].predecessors.append(from_id)

    def get_all_paths(self, from_id: int, to_id: int) -> list[list[int]]:
        """Get all paths from one node to another."""
        paths = []
        visited = set()

        def dfs(current: int, path: list[int]):
            if current == to_id:
                paths.append(path[:])
                return
            if current in visited:
                return
            visited.add(current)
            for successor in self.nodes[current].successors:
                path.append(successor)
                dfs(successor, path)
                path.pop()
            visited.remove(current)

        dfs(from_id, [from_id])
        return paths


@dataclass
class UnifiedAST:
    """Unified AST representation across languages."""

    language: str  # "python", "javascript", "java"
    raw_ast: Any  # Language-specific AST object
    sources: list[TaintSource] = field(default_factory=list)  # Extracted sources
    sinks: list[TaintSink] = field(default_factory=list)  # Extracted sinks
    variables: dict[str, Any] = field(default_factory=dict)  # Variable tracking
    functions: list[dict] = field(default_factory=list)  # Function definitions

    def __repr__(self):
        return (
            f"UnifiedAST({self.language}, " f"{len(self.sources)} sources, {len(self.sinks)} sinks)"
        )


@dataclass
class SemanticAnalysisResult:
    """Result of semantic analysis on a file."""

    file_path: str  # File being analyzed
    language: str  # Programming language
    taint_paths: list[TaintPath]  # Vulnerability paths found
    cfg: ControlFlowGraph | None = None  # Control flow graph
    analysis_time_ms: float = 0.0  # Analysis duration
    errors: list[str] = field(default_factory=list)  # Analysis errors

    def __repr__(self):
        return (
            f"SemanticAnalysisResult({self.file_path}, " f"{len(self.taint_paths)} vulnerabilities)"
        )
