# Phase 4.2 Roadmap - Semantic Analysis Engine

**Status**: 🎯 Ready to Begin (After Phase 4.1.1 Bug Fixing Sprint)
**Est. Duration**: 3-4 weeks
**Priority**: HIGH - Unblocks 9 xfailed tests + improves detection accuracy

---

## Executive Summary

Phase 4.2 will implement a **Semantic Analysis Engine** to overcome the limitations of static pattern matching identified in Phase 4.1.1. This engine will enable:

- **Multi-line taint tracking** (source → sink across statements)
- **Control flow analysis** (understand validation guards, early returns)
- **Context-aware detection** (distinguish safe vs unsafe usage patterns)
- **Comment block handling** (multi-line /* ... */ comments)

**Impact**: Expected to fix 8-9 of the 9 xfailed tests and reduce false positives by 40-50%.

---

## Problem Statement

### Static Pattern Matching Limitations (Phase 4.1.1 Findings)

The bug fixing sprint revealed fundamental limitations in line-by-line regex pattern matching:

#### 1. **Multi-Line Constructs** (5 Path Traversal + 4 Code Injection failures)
```python
# Pattern can't match across lines
filename = request.args.get('file')  # Line 2: taint source
with open(filename) as f:             # Line 3: taint sink - MISSED!
```

#### 2. **Variable Aliasing** (5 failures)
```python
# Pattern doesn't track variable assignments
user_file = req.params.file          # Line 1: user_file is now tainted
path = os.path.join(base, user_file)  # Line 2: MISSED! (no "request" keyword)
```

#### 3. **Control Flow Guards** (1 failure)
```python
# Pattern can't understand validation logic
if '..' in filename or filename.startswith('/'):
    return "Invalid"
# Safe here - but pattern still flags it
with open(filename) as f:
```

#### 4. **Multi-Line Comments** (1 failure)
```javascript
/*
 * This eval() call is just an example
 * eval(dangerous_code);  // <- Pattern matches inside block comment!
 */
```

---

## Phase 4.2 Objectives

### Primary Goals

1. ✅ **Taint Tracking System**
   - Track user input (sources) through variable assignments
   - Identify dangerous operations (sinks)
   - Detect tainted data reaching sinks

2. ✅ **Abstract Syntax Tree (AST) Parsing**
   - Parse Python, JavaScript, Java code into AST
   - Analyze code structure, not just text patterns
   - Handle multi-line constructs correctly

3. ✅ **Control Flow Analysis (CFG)**
   - Build control flow graphs for functions
   - Understand validation guards and early returns
   - Reduce false positives from safe code

4. ✅ **Multi-Line Context**
   - Track comment blocks (/* ... */)
   - Handle function calls spanning multiple lines
   - Detect patterns across statement boundaries

### Success Metrics

- **Tests**: 322/331 passing (97.3%) - up from 313/331 (94.6%)
- **XFailed Tests Fixed**: 8-9 of 9 tests should pass
- **False Positives**: Reduce by 40-50% through better context
- **Performance**: <500ms overhead per file for semantic analysis

---

## Technical Architecture

### Component 1: AST Parser Module

**Location**: `src/mcp_sentinel/engines/semantic/ast_parser.py`

**Responsibilities**:
- Parse source code into language-specific ASTs
- Provide unified interface across languages
- Extract taint sources and sinks

**Languages**:
- **Python**: Use built-in `ast` module
- **JavaScript/TypeScript**: Use `esprima` or `acorn` (via subprocess)
- **Java**: Use `javalang` library

**API Design**:
```python
class ASTParser:
    def parse(self, code: str, language: str) -> AST:
        """Parse code into AST."""

    def extract_sources(self, ast: AST) -> List[TaintSource]:
        """Find all user input sources (request.*, params.*, etc.)."""

    def extract_sinks(self, ast: AST) -> List[TaintSink]:
        """Find all dangerous operations (open, exec, eval, etc.)."""

    def get_function_calls(self, ast: AST) -> List[FunctionCall]:
        """Extract all function calls with arguments."""
```

**Example Usage**:
```python
parser = ASTParser()
ast = parser.parse(code, language="python")

# Find: filename = request.args.get('file')
sources = parser.extract_sources(ast)  # [TaintSource(name="filename", line=2)]

# Find: open(filename)
sinks = parser.extract_sinks(ast)      # [TaintSink(name="open", arg="filename", line=3)]
```

---

### Component 2: Taint Tracking Engine

**Location**: `src/mcp_sentinel/engines/semantic/taint_tracker.py`

**Responsibilities**:
- Track tainted variables through assignments
- Propagate taint through operations (string concat, etc.)
- Detect when tainted data reaches sinks

**Algorithm** (Forward Dataflow Analysis):
```
1. Initialize: tainted_vars = {all user input sources}
2. For each statement in execution order:
   a. If assignment: var = tainted_expr
      → Add var to tainted_vars
   b. If function call: sink(tainted_arg)
      → Report vulnerability
   c. If sanitization: var = sanitize(tainted)
      → Remove var from tainted_vars
```

**API Design**:
```python
class TaintTracker:
    def __init__(self, ast: AST):
        self.sources: List[TaintSource] = []
        self.sinks: List[TaintSink] = []
        self.tainted: Set[str] = set()  # Variable names

    def track_flow(self) -> List[TaintPath]:
        """Track taint from sources to sinks, return vulnerability paths."""

    def is_tainted(self, var_name: str, line_num: int) -> bool:
        """Check if variable is tainted at specific line."""

    def add_sanitization(self, var_name: str, line_num: int):
        """Mark variable as sanitized (no longer tainted)."""
```

**Example**:
```python
# Code:
# Line 2: filename = request.args.get('file')
# Line 3: with open(filename) as f:

tracker = TaintTracker(ast)
paths = tracker.track_flow()

# Result: TaintPath(
#   source=TaintSource(name="filename", line=2, origin="request.args"),
#   sink=TaintSink(name="open", arg="filename", line=3),
#   path=["filename(line2)", "open(line3)"]
# )
```

---

### Component 3: Control Flow Graph (CFG)

**Location**: `src/mcp_sentinel/engines/semantic/cfg_builder.py`

**Responsibilities**:
- Build control flow graphs for functions
- Identify branches, loops, early returns
- Detect validation guards before dangerous operations

**CFG Node Types**:
- **Statement Node**: Regular statement
- **Branch Node**: if/else decision point
- **Loop Node**: for/while loop
- **Return Node**: Early exit
- **Merge Node**: Control flow convergence

**API Design**:
```python
class CFGBuilder:
    def build(self, function_ast: AST) -> ControlFlowGraph:
        """Build CFG from function AST."""

    def find_guards(self, sink_node: CFGNode) -> List[Guard]:
        """Find validation guards protecting a sink."""

    def is_path_safe(self, source: CFGNode, sink: CFGNode) -> bool:
        """Check if all paths from source to sink have validation."""
```

**Example**:
```python
# Code:
# if '..' in filename or filename.startswith('/'):
#     return "Invalid"
# with open(filename) as f:

cfg = CFGBuilder().build(function_ast)
sink = cfg.find_node(line=4)  # open() call
guards = cfg.find_guards(sink)

# Result: guards = [
#   Guard(condition="'..' in filename", line=1, type="validation"),
#   Guard(condition="filename.startswith('/')", line=1, type="validation")
# ]
# Decision: SAFE - all paths to sink have validation
```

---

### Component 4: Semantic Detector Integration

**Location**: `src/mcp_sentinel/detectors/*` (updates to existing detectors)

**Approach**: Hybrid Static + Semantic

Each detector will use a **two-phase** approach:
1. **Phase 1 (Static)**: Fast regex patterns for obvious cases
2. **Phase 2 (Semantic)**: AST analysis for multi-line/complex cases

**Example - Path Traversal Detector**:
```python
class PathTraversalDetector(BaseDetector):
    async def detect(self, file_path, content, file_type):
        vulns = []

        # Phase 1: Static patterns (fast)
        vulns.extend(self._detect_static_patterns(content))

        # Phase 2: Semantic analysis (slower but accurate)
        if self.semantic_enabled:
            ast = self.ast_parser.parse(content, file_type)
            tracker = TaintTracker(ast)

            # Find: request.* → open/readFile/etc
            paths = tracker.track_flow(
                sources=["request.*", "params.*", "query.*"],
                sinks=["open", "readFile", "File()"]
            )

            for path in paths:
                # Check if path has validation guards
                cfg = CFGBuilder().build(ast)
                if not cfg.is_path_safe(path.source, path.sink):
                    vulns.append(self._create_vulnerability(path))

        return vulns
```

---

## Implementation Plan

### Week 1: AST Parser + Foundation

**Goals**:
- Set up AST parsing for Python, JavaScript, Java
- Build core data structures (TaintSource, TaintSink, AST wrappers)
- Write unit tests for AST extraction

**Tasks**:
1. Create `ast_parser.py` with multi-language support
2. Implement `extract_sources()` and `extract_sinks()`
3. Add AST traversal utilities
4. Test on 20 code samples (5 per detector type)

**Deliverables**:
- `ASTParser` class with 100% test coverage
- Support for Python, JavaScript, Java
- 50+ unit tests

---

### Week 2: Taint Tracking Engine

**Goals**:
- Implement forward dataflow analysis
- Track taint through variable assignments
- Detect source → sink paths

**Tasks**:
1. Create `TaintTracker` class
2. Implement variable tracking algorithm
3. Add sanitization detection
4. Test on 9 xfailed tests

**Deliverables**:
- `TaintTracker` with dataflow analysis
- Pass 5-6 of the 9 xfailed tests
- 80+ unit tests

---

### Week 3: Control Flow Analysis

**Goals**:
- Build control flow graphs
- Detect validation guards
- Reduce false positives

**Tasks**:
1. Create `CFGBuilder` class
2. Implement branch/loop detection
3. Add guard identification
4. Integrate with detectors

**Deliverables**:
- `ControlFlowGraph` implementation
- Pass 1-2 more xfailed tests (validation guards)
- 60+ unit tests

---

### Week 4: Integration + Performance

**Goals**:
- Integrate semantic engine with all detectors
- Optimize performance (<500ms overhead)
- Documentation and examples

**Tasks**:
1. Update all 8 detectors to use semantic analysis
2. Add configuration flags (enable/disable semantic)
3. Benchmark performance
4. Write migration guide

**Deliverables**:
- All detectors support semantic mode
- Performance benchmarks
- Documentation updates
- Pass 8-9 xfailed tests

---

## Technical Challenges & Solutions

### Challenge 1: Performance Overhead

**Problem**: AST parsing and dataflow analysis are slower than regex patterns.

**Solution**:
- **Caching**: Cache parsed ASTs (keyed by file content hash)
- **Lazy Analysis**: Only run semantic analysis if static patterns find something
- **Parallel Processing**: Analyze functions in parallel using asyncio
- **Configuration**: Allow users to disable semantic analysis for speed

**Target**: <500ms overhead per file (acceptable for security scanning)

---

### Challenge 2: Multi-Language Support

**Problem**: Different AST structures for Python, JavaScript, Java.

**Solution**:
- **Unified AST Interface**: Abstract language differences behind common API
- **Language-Specific Parsers**: Implement per-language extractors
- **Extensible Design**: Easy to add new languages later

**Example**:
```python
# Unified interface
class LanguageParser(ABC):
    @abstractmethod
    def parse(self, code: str) -> UnifiedAST:
        pass

# Language-specific implementations
class PythonParser(LanguageParser):
    def parse(self, code: str) -> UnifiedAST:
        ast = ast.parse(code)
        return UnifiedAST(ast, language="python")

class JavaScriptParser(LanguageParser):
    def parse(self, code: str) -> UnifiedAST:
        # Use esprima via subprocess
        ast = subprocess.check_output(["node", "parse.js", code])
        return UnifiedAST(ast, language="javascript")
```

---

### Challenge 3: Inter-Procedural Analysis

**Problem**: Taint can flow through function calls.

**Solution** (Phase 4.2 - Simple, Phase 4.3 - Advanced):
- **Phase 4.2**: Assume all function parameters are potentially tainted (conservative)
- **Phase 4.3**: Implement call graph and inter-procedural dataflow

**Example**:
```python
# Phase 4.2: Conservative approach
def process_file(filename):  # Assume filename is tainted
    with open(filename) as f:  # Flag as vulnerable
        return f.read()

# Phase 4.3: Call graph approach (future)
def handler(request):
    filename = request.args.get('file')  # Taint source
    result = process_file(filename)       # Propagate taint
```

---

## Test Strategy

### Unit Tests

- **AST Parser**: 50+ tests (one per language feature)
- **Taint Tracker**: 80+ tests (various taint scenarios)
- **CFG Builder**: 60+ tests (control flow patterns)

### Integration Tests

- **Detector Tests**: Re-run all 9 xfailed tests
- **End-to-End**: Full scans on sample codebases
- **Performance**: Benchmark on 1000+ file corpus

### Acceptance Criteria

1. ✅ 8-9 xfailed tests now pass
2. ✅ No regressions in existing 313 passing tests
3. ✅ Performance overhead <500ms per file
4. ✅ 100% test coverage for new semantic components

---

## Dependencies

### Python Libraries

- **AST Parsing**: Built-in `ast` module (Python)
- **JavaScript Parsing**: `esprima` or `acorn` (install via npm)
- **Java Parsing**: `javalang` (install via pip)

### Installation
```bash
pip install javalang
npm install esprima  # For JavaScript/TypeScript parsing
```

---

## Risks & Mitigation

| Risk | Severity | Mitigation |
|------|----------|------------|
| **Performance degradation** | HIGH | Caching, lazy analysis, parallel processing |
| **False negatives** | MEDIUM | Conservative taint propagation, extensive testing |
| **Complexity** | MEDIUM | Phased rollout, comprehensive docs, code reviews |
| **Language coverage gaps** | LOW | Focus on Python/JS first, add others later |

---

## Post-Phase 4.2 Roadmap

### Phase 4.3 (Advanced Semantic Analysis)
- Inter-procedural analysis (call graphs)
- Path-sensitive analysis (symbolic execution)
- Type inference and object tracking
- Custom sanitization detection

### Phase 4.4 (AI-Assisted Analysis)
- LLM-based code understanding
- Context-aware vulnerability explanations
- Automated fix suggestions

---

## Success Metrics (Recap)

**Before Phase 4.2**:
- 313/331 tests passing (94.6%)
- 9 xfailed (semantic analysis needed)
- 9 failed (need investigation)

**After Phase 4.2**:
- **Target**: 322/331 tests passing (97.3%)
- **Target**: 0-1 xfailed (only complex edge cases)
- **Target**: <9 failed (fix some during Phase 4.2)

**Long-Term Vision**:
- **Phase 4.3**: 330/331 tests passing (99.7%)
- **Phase 4.4**: 331/331 tests passing (100%)

---

## Conclusion

Phase 4.2 represents a significant leap from static pattern matching to semantic code analysis. By implementing AST parsing, taint tracking, and control flow analysis, we'll overcome the fundamental limitations identified in Phase 4.1.1 and achieve production-grade detection accuracy.

**Next Steps**:
1. Review and approve this roadmap
2. Set up development environment (AST libraries)
3. Begin Week 1 implementation (AST Parser)
4. Track progress in weekly standups

**References**:
- [BUGFIX_SPRINT_RESULTS.md](BUGFIX_SPRINT_RESULTS.md) - Detailed findings from Phase 4.1.1
- [Phase 4 Implementation](docs/phase4-implementation.md) - Original multi-engine plan
- [Test Results](tests/unit/) - All xfailed tests with reasons
