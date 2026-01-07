# Phase 4: Multi-Engine Analysis Platform - Implementation Plan

**Version**: 1.0.0
**Start Date**: January 2026
**Estimated Duration**: 6-8 weeks
**Complexity**: Very High
**Status**: Planning

---

## Executive Summary

Phase 4 will transform MCP Sentinel from a pattern-based security scanner into a comprehensive **multi-engine analysis platform** with 4 specialized engines working in concert. This represents the **most significant architectural enhancement** since project inception.

**Impact**: 10x detection accuracy, enterprise-grade analysis, industry-leading security platform

---

## Current State (Phase 3 Complete)

### What We Have
- ✅ 8 security detectors (100% parity)
- ✅ 98 vulnerability patterns
- ✅ 274 comprehensive tests (~95% coverage)
- ✅ 4 report formats (Terminal, JSON, SARIF, HTML)
- ✅ Pattern-based static analysis
- ✅ Enterprise documentation

### Limitations
- ❌ No semantic/context-aware analysis
- ❌ No AST-based detection
- ❌ No dataflow/taint tracking
- ❌ No integration with industry SAST tools
- ❌ No AI-powered analysis
- ❌ Limited to pattern matching

**Detection Accuracy**: ~85-90% (pattern-based only)

---

## Phase 4 Goals

### Target State
- ✅ 4 analysis engines working in concert
- ✅ AST-based semantic analysis
- ✅ Dataflow and taint tracking
- ✅ Integration with Semgrep + Bandit (1000+ rules)
- ✅ AI-powered contextual analysis
- ✅ Multi-engine coordination
- ✅ Engine attribution in reports
- ✅ Vulnerability deduplication

**Target Detection Accuracy**: ~98-99% (multi-engine)

---

## The 4 Analysis Engines

### 1. Semantic Analysis Engine (2 weeks)

**Purpose**: Context-aware analysis using AST parsing and dataflow tracking

**Components**:
- **Tree-sitter Integration** (4-5 days)
  - Parser setup for Python, JavaScript, TypeScript, Go
  - AST traversal infrastructure
  - Language-specific visitors
  - Node pattern matching

- **Dataflow Analysis** (4-5 days)
  - Taint source identification
  - Taint propagation tracking
  - Sink detection
  - Path-sensitive analysis

- **Control Flow Analysis** (2-3 days)
  - CFG construction
  - Reachability analysis
  - Dead code detection
  - Branch analysis

**Key Features**:
- Detects vulnerabilities missed by pattern matching
- Context-aware (knows variable scope, data flow)
- Multi-language support
- Precise location identification

**Example Detection**:
```python
# Pattern matching misses this, semantic analysis catches it:
user_input = request.GET['name']
sanitized = clean(user_input)  # Semantic analysis understands sanitization
query = f"SELECT * FROM users WHERE name = '{sanitized}'"  # SAFE

vs.

user_input = request.GET['name']
query = f"SELECT * FROM users WHERE name = '{user_input}'"  # UNSAFE - semantic analysis detects taint flow
```

**Implementation Files**:
```
src/mcp_sentinel/engines/semantic/
├── __init__.py
├── tree_sitter_parser.py      # Tree-sitter wrapper
├── ast_visitor.py              # AST traversal
├── dataflow_analyzer.py        # Taint tracking
├── control_flow_analyzer.py    # CFG construction
├── language_parsers/
│   ├── python_parser.py
│   ├── javascript_parser.py
│   ├── typescript_parser.py
│   └── go_parser.py
└── detectors/
    ├── semantic_sql_injection.py
    ├── semantic_xss.py
    └── semantic_code_injection.py
```

**Dependencies**:
- tree-sitter
- tree-sitter-python
- tree-sitter-javascript
- tree-sitter-typescript
- libcst (Python-specific)

**Tests**: 50+ test cases covering AST parsing, dataflow, and control flow

---

### 2. SAST Integration Engine (2 weeks)

**Purpose**: Leverage industry-leading SAST tools (Semgrep + Bandit)

**Components**:
- **Semgrep Integration** (5-6 days)
  - Semgrep subprocess wrapper
  - SARIF output parsing
  - Rule management and synchronization
  - Custom rule support
  - 1000+ community rules

- **Bandit Integration** (3-4 days)
  - Bandit subprocess wrapper
  - JSON output parsing
  - Configuration management
  - Python-specific security checks

- **Rule Management** (2-3 days)
  - Centralized rule registry
  - Auto-update mechanism
  - Organization-specific rules
  - Rule versioning

**Key Features**:
- Battle-tested SAST rules from community
- Continuous rule updates
- Custom organizational rules
- Multi-language support (Semgrep)
- Python security expertise (Bandit)

**Example Detection**:
```python
# Semgrep detects with community rules:
import pickle
data = pickle.loads(user_input)  # Semgrep: dangerous deserialization

# Bandit detects Python-specific issues:
import subprocess
subprocess.call(["ls", user_input])  # Bandit: potential command injection
```

**Implementation Files**:
```
src/mcp_sentinel/engines/sast/
├── __init__.py
├── semgrep_wrapper.py          # Semgrep integration
├── bandit_wrapper.py           # Bandit integration
├── rule_manager.py             # Rule synchronization
├── sarif_parser.py             # Parse SARIF output
└── rules/
    ├── semgrep/
    │   ├── security/           # Security rules
    │   ├── best-practices/     # Code quality
    │   └── custom/             # Organization rules
    └── bandit/
        └── config.yaml         # Bandit configuration
```

**Dependencies**:
- semgrep
- bandit
- sarif-tools (for parsing)

**Tests**: 40+ test cases covering Semgrep integration, Bandit integration, and rule management

---

### 3. AI Analysis Engine (2-3 weeks)

**Purpose**: AI-powered contextual analysis with multi-LLM support

**Components**:
- **LangChain Integration** (5-6 days)
  - Chain setup for security analysis
  - Prompt engineering for vulnerability detection
  - Result parsing and structuring
  - Error handling and retries

- **Multi-LLM Support** (4-5 days)
  - GPT-4 integration (OpenAI)
  - Claude integration (Anthropic)
  - Gemini integration (Google)
  - Ollama integration (local/self-hosted)
  - Provider abstraction layer
  - Fallback mechanisms

- **RAG Implementation** (4-5 days)
  - Vector database (ChromaDB)
  - Embedding generation (sentence-transformers)
  - Context retrieval
  - Relevant code snippet injection

- **Prompt Engineering** (2-3 days)
  - Security-focused prompts
  - Few-shot learning examples
  - Chain-of-thought reasoning
  - Vulnerability explanation generation

**Key Features**:
- Detects novel/unknown vulnerabilities
- Natural language explanations
- Context-aware analysis
- Self-hosted option (Ollama)
- Privacy-preserving (optional)

**Example Detection**:
```python
# AI detects subtle logic bugs and novel patterns:
def check_permissions(user, resource):
    if user.is_admin:
        return True
    if resource.owner == user:
        return True
    # AI: Missing authentication check - anonymous users can access!
    return True

# AI provides natural language explanation:
# "This function has a critical authentication bypass. The final
#  'return True' allows any user, including unauthenticated ones,
#  to access resources. Consider: return False"
```

**Implementation Files**:
```
src/mcp_sentinel/engines/ai/
├── __init__.py
├── langchain_wrapper.py        # LangChain integration
├── llm_providers/
│   ├── openai_provider.py      # GPT-4
│   ├── anthropic_provider.py   # Claude
│   ├── google_provider.py      # Gemini
│   └── ollama_provider.py      # Local LLMs
├── rag/
│   ├── vector_store.py         # ChromaDB integration
│   ├── embeddings.py           # Embedding generation
│   └── retriever.py            # Context retrieval
├── prompts/
│   ├── security_prompts.py     # Prompt templates
│   ├── few_shot_examples.py    # Training examples
│   └── chain_prompts.py        # Chain-of-thought
└── detectors/
    ├── ai_vulnerability.py     # Generic AI detector
    └── ai_logic_bugs.py        # Logic vulnerability detector
```

**Dependencies**:
- langchain
- langchain-openai
- langchain-anthropic
- langchain-google-genai
- chromadb
- sentence-transformers
- tiktoken (token counting)

**Tests**: 30+ test cases (with mocked LLM responses to avoid API costs)

---

### 4. Static Analysis Engine (Current - Enhancement)

**Purpose**: Centralized pattern registry with enhanced performance

**Components**:
- **Pattern Registry Centralization** (3-4 days)
  - Move all patterns to centralized registry
  - Pattern DSL for easier authoring
  - Pattern versioning
  - Pattern categories

- **Performance Optimization** (2-3 days)
  - Regex compilation caching
  - Parallel pattern matching
  - Memory-efficient processing
  - Incremental scanning

**Key Features**:
- Maintains current detection capabilities
- Better performance
- Easier pattern management
- Backward compatible

**Implementation Files**:
```
src/mcp_sentinel/engines/static/
├── __init__.py
├── pattern_registry.py         # Centralized registry
├── pattern_matcher.py          # Optimized matching
├── pattern_dsl.py              # Pattern authoring DSL
└── patterns/
    ├── secrets.yaml            # Secret patterns
    ├── injection.yaml          # Injection patterns
    ├── xss.yaml                # XSS patterns
    └── config.yaml             # Config patterns
```

---

## Multi-Engine Coordination

### Engine Orchestrator

**Purpose**: Coordinate execution of multiple engines and merge results

**Components**:
- **Engine Manager** (3-4 days)
  - Engine registration and discovery
  - Parallel/sequential execution
  - Resource management
  - Error handling

- **Result Merger** (3-4 days)
  - Vulnerability deduplication
  - Confidence scoring
  - Engine attribution
  - Result ranking

- **Report Generator** (2-3 days)
  - Engine comparison reports
  - Coverage analysis
  - Performance metrics
  - Overlap visualization

**Implementation Files**:
```
src/mcp_sentinel/core/
├── engine_orchestrator.py      # Coordinate engines
├── result_merger.py            # Deduplicate findings
├── confidence_scorer.py        # Score vulnerabilities
└── engine_attribution.py       # Track which engine found what
```

---

## Enhanced CLI

### New CLI Flags

```bash
# Engine selection
mcp-sentinel scan . --engines static                    # Static only (current)
mcp-sentinel scan . --engines static,semantic          # Static + Semantic
mcp-sentinel scan . --engines static,sast              # Static + SAST
mcp-sentinel scan . --engines static,semantic,sast,ai  # All engines
mcp-sentinel scan . --engines all                      # All engines

# Engine-specific configuration
mcp-sentinel scan . --engines ai --ai-provider openai  # Use GPT-4
mcp-sentinel scan . --engines ai --ai-provider ollama  # Use local LLM
mcp-sentinel scan . --engines sast --semgrep-rules security  # Semgrep security rules only

# Report enhancements
mcp-sentinel scan . --engines all --show-attribution   # Show which engine found each issue
mcp-sentinel scan . --engines all --compare-engines    # Engine comparison report
mcp-sentinel scan . --engines all --output html --json-file multi-engine-report.html
```

**Implementation**:
```python
# src/mcp_sentinel/cli/main.py

@click.option(
    "--engines",
    multiple=True,
    default=["static"],
    help="Analysis engines to use (static, semantic, sast, ai, all)"
)
@click.option(
    "--show-attribution",
    is_flag=True,
    help="Show which engine detected each vulnerability"
)
@click.option(
    "--compare-engines",
    is_flag=True,
    help="Generate engine comparison report"
)
```

---

## Implementation Timeline

### Week 1-2: Semantic Analysis Engine
- **Days 1-5**: Tree-sitter integration
  - Set up tree-sitter for Python, JS, TS, Go
  - Implement AST visitors
  - Test AST parsing

- **Days 6-10**: Dataflow analysis
  - Implement taint tracking
  - Source/sink identification
  - Path-sensitive analysis
  - Write 30+ tests

### Week 3-4: SAST Integration Engine
- **Days 11-16**: Semgrep integration
  - Subprocess wrapper
  - SARIF parsing
  - Rule management
  - 1000+ community rules

- **Days 17-20**: Bandit integration
  - Subprocess wrapper
  - JSON parsing
  - Configuration
  - Python-specific checks

- **Days 21-24**: Rule synchronization
  - Auto-update mechanism
  - Custom rules support
  - Write 40+ tests

### Week 5-7: AI Analysis Engine
- **Days 25-30**: LangChain setup
  - Chain architecture
  - Prompt engineering
  - Result parsing
  - Multi-provider abstraction

- **Days 31-35**: Multi-LLM integration
  - GPT-4, Claude, Gemini, Ollama
  - Provider abstraction
  - Fallback mechanisms
  - API key management

- **Days 36-40**: RAG implementation
  - ChromaDB setup
  - Embedding generation
  - Context retrieval
  - Write 30+ tests

### Week 8: Integration and Polish
- **Days 41-43**: Engine orchestration
  - Multi-engine coordinator
  - Result merging
  - Deduplication

- **Days 44-46**: CLI enhancement
  - Add --engines flag
  - Engine-specific options
  - Report enhancements

- **Days 47-50**: Testing and documentation
  - Integration tests
  - Performance benchmarks
  - Update documentation
  - Release preparation

---

## Testing Strategy

### Unit Tests
- **Semantic Engine**: 50+ tests
- **SAST Engine**: 40+ tests
- **AI Engine**: 30+ tests (mocked responses)
- **Orchestration**: 20+ tests

**Total**: 140+ new tests

### Integration Tests
- Multi-engine workflows (10 tests)
- Engine coordination (8 tests)
- Report generation (12 tests)
- CLI integration (10 tests)

**Total**: 40+ integration tests

### Performance Tests
- Semantic analysis benchmarks
- SAST integration performance
- AI response times
- Memory usage

### Target Metrics
- **Test Coverage**: >90%
- **Tests Passing**: >95%
- **Performance**: <30s for 1000-file project (all engines)

---

## Success Criteria

### Functional Requirements
- ✅ All 4 engines implemented and working
- ✅ CLI supports --engines flag
- ✅ Multi-engine coordination functional
- ✅ Vulnerability deduplication working
- ✅ Engine attribution in reports
- ✅ Backward compatible with Phase 3

### Performance Requirements
- ✅ Semantic analysis: <10s for 1000 files
- ✅ SAST integration: <15s for 1000 files
- ✅ AI analysis: <20s for critical files (with caching)
- ✅ Total: <30s for complete multi-engine scan

### Quality Requirements
- ✅ >90% test coverage
- ✅ >95% tests passing
- ✅ Zero breaking changes
- ✅ Documentation complete

### Detection Accuracy
- ✅ 98-99% accuracy (up from ~85-90%)
- ✅ <2% false positives
- ✅ Novel vulnerability detection (AI engine)

---

## Risk Assessment

### High Risks

**1. AI API Costs**
- **Risk**: GPT-4/Claude API calls expensive
- **Mitigation**:
  - Implement caching aggressively
  - Use Ollama for local/free option
  - Batch API calls
  - Smart file prioritization

**2. Performance Degradation**
- **Risk**: 4 engines slower than 1
- **Mitigation**:
  - Parallel engine execution
  - Aggressive caching
  - Smart file filtering
  - Incremental scanning

**3. Complexity Explosion**
- **Risk**: 4 engines hard to maintain
- **Mitigation**:
  - Strong abstraction layers
  - Comprehensive documentation
  - Extensive testing
  - Modular design

### Medium Risks

**4. Dependency Hell**
- **Risk**: Tree-sitter, Semgrep, LangChain conflicts
- **Mitigation**:
  - Lock dependency versions
  - Use virtual environments
  - Test on multiple platforms
  - Docker containerization

**5. False Positive Increase**
- **Risk**: More engines = more false positives
- **Mitigation**:
  - Confidence scoring
  - Smart deduplication
  - User feedback loops
  - Tunable thresholds

### Low Risks

**6. Breaking Changes**
- **Risk**: CLI changes break existing workflows
- **Mitigation**:
  - Backward compatibility
  - Deprecation warnings
  - Migration guides
  - Semantic versioning

---

## Dependencies

### New Dependencies
```toml
# Semantic Analysis
tree-sitter = "^0.20.4"
tree-sitter-python = "^0.20.4"
tree-sitter-javascript = "^0.20.3"
tree-sitter-typescript = "^0.20.3"
libcst = "^1.1.0"

# SAST Integration
semgrep = "^1.55.2"
bandit = "^1.7.6"

# AI Analysis
langchain = "^0.1.0"
langchain-openai = "^0.0.2"
langchain-anthropic = "^0.0.1"
langchain-google-genai = "^0.0.5"
chromadb = "^0.4.22"
sentence-transformers = "^2.2.2"
```

**Total**: Already included in pyproject.toml ✅

---

## Documentation Updates

### New Documentation
- **Phase 4 Architecture** (docs/PHASE_4_ARCHITECTURE.md)
- **Engine Configuration Guide** (docs/ENGINE_CONFIGURATION.md)
- **AI Engine Setup** (docs/AI_ENGINE_SETUP.md)
- **Custom Rule Authoring** (docs/CUSTOM_RULES.md)

### Updated Documentation
- **USER_GUIDE.md**: Add multi-engine usage examples
- **ARCHITECTURE.md**: Update with Phase 4 details
- **README.md**: Highlight multi-engine capabilities
- **CLI_REFERENCE.md**: Document new flags

---

## Post-Phase 4 Roadmap

### Phase 5: Enterprise Platform (8 weeks)
- REST API + GraphQL
- PostgreSQL database
- Celery task queue
- Multi-tenant support
- Web dashboard

### Phase 6: Advanced Features (6 weeks)
- Threat intelligence integration
- Advanced analytics
- Compliance scoring
- Historical trending

### Phase 7: Ecosystem Integration (4 weeks)
- Jira, Slack, PagerDuty integration
- IDE plugins
- Git hooks
- Continuous monitoring

---

## Budget and Resources

### Development Time
- **Full-time equivalent**: 6-8 weeks
- **Part-time (50%)**: 12-16 weeks
- **Part-time (25%)**: 24-32 weeks

### API Costs (If Using GPT-4)
- **Development/Testing**: ~$50-100 (with mocking)
- **Production (per 1000 scans)**: ~$20-50
- **Mitigation**: Use Ollama for free local LLMs

### Infrastructure
- **Development**: Local machine sufficient
- **CI/CD**: GitHub Actions (free tier OK)
- **Production**: Depends on deployment model

---

## Stakeholder Communication

### Weekly Updates
- Progress report
- Blockers/risks
- Next week's plan
- Demo (if applicable)

### Milestones
- **Milestone 1** (Week 2): Semantic engine complete
- **Milestone 2** (Week 4): SAST engine complete
- **Milestone 3** (Week 7): AI engine complete
- **Milestone 4** (Week 8): Integration complete

### Demo Schedule
- **Demo 1** (Week 2): Semantic analysis in action
- **Demo 2** (Week 4): SAST integration showcase
- **Demo 3** (Week 7): AI-powered detection
- **Final Demo** (Week 8): Complete multi-engine platform

---

## Getting Started

### Immediate Next Steps

1. **Review and Approve Plan** (You're here!)
2. **Set Up Development Environment**
   ```bash
   cd mcp-sentinel-python
   poetry install
   poetry run pytest tests/ -v
   ```

3. **Create Feature Branch**
   ```bash
   git checkout -b feature/phase-4-multi-engine
   ```

4. **Start with Semantic Engine**
   - Create directory structure
   - Install tree-sitter
   - Implement basic AST parsing
   - Write first tests

5. **Daily Standup** (Self-check)
   - What did I accomplish yesterday?
   - What will I work on today?
   - Any blockers?

---

## Questions and Decisions Needed

### Open Questions
1. **AI Provider**: Which should be default? GPT-4, Claude, or Ollama?
2. **Performance vs. Accuracy**: Trade-off thresholds?
3. **Pricing Model**: How to handle AI API costs for end users?
4. **Breaking Changes**: Any acceptable breaking changes?

### Decisions Needed
- [ ] Approve Phase 4 plan
- [ ] Choose default AI provider
- [ ] Set performance targets
- [ ] Define success metrics
- [ ] Allocate budget (if any)

---

**Document Version**: 1.0.0
**Last Updated**: 2026-01-07
**Next Review**: After Phase 4 completion

---

🚀 **Ready to transform MCP Sentinel into the industry-leading multi-engine security platform!**
