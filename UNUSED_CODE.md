# Unused / Dead Code Inventory

This document lists all code that was identified as unused stubs, dead implementations, or
over-engineered features not aligned with the core MCP security scanning use case.
Removed as part of the codebase footprint reduction (see plan: cleanup-codebase-footprint).

---

## 1. Complete Stub Directories (Zero Implementation)

These directories contain only empty `__init__.py` files — no logic, no functions, no classes.

| Directory | Purpose (Intended) | Status |
|---|---|---|
| `src/mcp_sentinel/integrations/` | Jira, Slack, GitHub, GitLab, PagerDuty, Splunk integrations | **EMPTY STUBS** |
| `src/mcp_sentinel/integrations/cicd/` | CI/CD pipeline integration | **EMPTY STUB** |
| `src/mcp_sentinel/integrations/vcs/` | Version control system integration | **EMPTY STUB** |
| `src/mcp_sentinel/integrations/ticketing/` | Issue tracker integration | **EMPTY STUB** |
| `src/mcp_sentinel/integrations/notifications/` | Slack/email notification integration | **EMPTY STUB** |
| `src/mcp_sentinel/integrations/logging/` | External logging integration | **EMPTY STUB** |
| `src/mcp_sentinel/monitoring/` | Prometheus, OpenTelemetry, Sentry, Datadog | **EMPTY STUB** |
| `src/mcp_sentinel/tasks/` | Celery distributed task queue | **EMPTY STUB** |
| `src/mcp_sentinel/storage/database/` | PostgreSQL via SQLAlchemy + asyncpg | **EMPTY STUB** |
| `src/mcp_sentinel/storage/database/models/` | ORM models | **EMPTY STUB** |
| `src/mcp_sentinel/storage/database/repositories/` | Data access layer | **EMPTY STUB** |
| `src/mcp_sentinel/storage/objectstore/` | AWS S3 object storage via boto3 | **EMPTY STUB** |

---

## 2. Unused AI Provider Stubs

The AI engine has one real provider (Anthropic) and three TODO stubs with no implementation:

| File | Notes |
|---|---|
| `src/mcp_sentinel/engines/ai/providers/` (OpenAI, Google, Ollama) | Lines 481-488 in `ai_engine.py` are `# TODO: Implement X provider` comments only |

---

## 3. Removed Features (Had Implementation, Now Deleted)

### 3.1 AI Analysis Engine — `src/mcp_sentinel/engines/ai/`
- **Why removed:** Sends user code to external Anthropic API — a security concern for a security tool.
  Adds $1/scan cost, requires API key management, and introduces an external dependency in
  the threat model. The static engine covers MCP-relevant patterns without exfiltrating code.
- **Files:** `ai_engine.py` (603 lines), `providers/base.py`, `providers/anthropic_provider.py` (397 lines)

### 3.2 Semantic Analysis Engine — `src/mcp_sentinel/engines/semantic/`
- **Why removed:** AST parsing + CFG building + taint tracking across 5 files is over-engineered
  for the MCP scanner use case. Heavy deps (tree-sitter, libcst). Marginal accuracy gain over
  static patterns for the specific MCP threat model.
- **Files:** `semantic_engine.py`, `ast_parser.py`, `cfg_builder.py`, `taint_tracker.py`, `models.py`

### 3.3 SAST Integration Engine — `src/mcp_sentinel/engines/sast/`
- **Why removed:** Semgrep requires a binary installation and internet access for rule updates.
  Bandit is Python-only. External tool orchestration adds failure modes. The MCP-specific
  detectors in the static engine are more targeted than generic SAST rules.
- **Files:** `sast_engine.py`, `semgrep_adapter.py`, `bandit_adapter.py`

### 3.4 RAG System — `src/mcp_sentinel/rag/`
- **Why removed:** 2,400+ LOC. ChromaDB (vector store) + sentence-transformers (ML model
  downloads). Served exclusively the AI engine. Security knowledge embedded in the RAG data
  loaders (1,204 LOC) is better expressed as focused static detector patterns.
- **Files:** `vector_store.py`, `embeddings.py`, `retriever.py`, `knowledge_base.py`, `data_loaders.py`

### 3.5 XSS Detector — `src/mcp_sentinel/detectors/xss.py`
- **Why removed:** MCP servers are not web UIs — they don't render HTML or handle browser DOM.
  XSS is a category error for this target environment.

### 3.6 Supply Chain Detector — `src/mcp_sentinel/detectors/supply_chain.py`
- **Why removed:** Generic typosquatting/dependency confusion patterns with no MCP registry
  awareness. High false-positive risk without knowledge of the actual MCP package ecosystem.

### 3.7 Remediation System + `fix` Command — `src/mcp_sentinel/remediation/`
- **Why removed:** `DiffBuilder.apply_patch()` directly writes AI-generated code to source files
  on disk. This is dangerous — if the AI-generated fix is incorrect, it silently corrupts user code.
  The `--auto-approve` flag makes it worse. No version control safety checks.
- **Files:** `models.py`, `diff_builder.py`; CLI: `fix()` command in `cli/main.py`

### 3.8 HTML Report Generator — `src/mcp_sentinel/reporting/generators/html_generator.py`
- **Why removed:** 590 lines, Jinja2 dependency. Three output formats (terminal, JSON, SARIF)
  are sufficient. Terminal for humans, JSON for CI/CD pipelines, SARIF for GitHub Code Scanning.

### 3.9 API Server — `src/mcp_sentinel/api/`
- **Why removed:** One real endpoint (`POST /api/v1/scan`), 75 lines total. Adds FastAPI and
  Uvicorn as runtime dependencies for what is fundamentally a CLI tool. Not core to the
  MCP scanner use case.
- **Files:** `main.py`, `v1/endpoints/scan.py`, `v1/schemas.py`

---

## 4. Unused Dependencies Removed from `pyproject.toml`

### AI / ML
- `anthropic` — AI engine removed
- `langchain`, `langchain-openai`, `langchain-anthropic`, `langchain-google-genai` — AI engine removed
- `openai` — OpenAI provider stub removed
- `transformers` — sentence-transformers dependency chain
- `sentence-transformers` — RAG embeddings removed
- `chromadb` — RAG vector store removed

### Database
- `sqlalchemy` — database layer is stubs only
- `alembic` — no migrations exist
- `asyncpg` — no PostgreSQL connections made
- `psycopg2-binary` — no PostgreSQL connections made

### Object Storage
- `boto3` — S3 integration is a stub

### Monitoring / Observability
- `prometheus-client` — monitoring module is an empty stub
- `opentelemetry-api`, `opentelemetry-sdk`, `opentelemetry-instrumentation-fastapi` — stubs only
- `structlog` — structured logging is a stub
- `sentry-sdk` — error tracking is a stub
- `datadog` — monitoring is a stub

### Enterprise Integrations
- `jira` — integration is an empty stub
- `slack-sdk` — integration is an empty stub
- `PyGithub` — integration is an empty stub
- `gql` — GraphQL, no usage
- `python-gitlab` — integration is an empty stub
- `pdpyras` — PagerDuty, integration is an empty stub
- `splunk-sdk` — integration is an empty stub

### Task Queue / Cache / RPC
- `celery` — tasks module is an empty stub
- `redis` — task/cache layer is a stub
- `grpcio`, `grpcio-tools` — no gRPC usage
- `strawberry-graphql` — no GraphQL schema implemented

### Web Framework (with API server removed)
- `fastapi` — API server removed
- `uvicorn` — API server removed

### Semantic Engine
- `tree-sitter` + language bindings — semantic engine removed
- `libcst` — semantic engine + remediation removed

### SAST Engine
- `semgrep` — SAST engine removed
- `bandit` — SAST engine removed

---

## 5. Test Files Removed

Tests for features that no longer exist:

| Test File | Covered Feature |
|---|---|
| `tests/unit/engines/test_ai_engine.py` | AI analysis engine |
| `tests/unit/engines/test_sast_engine.py` | SAST engine |
| `tests/unit/engines/test_semantic_engine.py` | Semantic engine |
| `tests/unit/detectors/test_xss.py` | XSS detector |
| `tests/unit/detectors/test_supply_chain.py` | Supply chain detector |
| `tests/unit/rag/test_retriever.py` | RAG retriever |
| `tests/unit/rag/test_vector_store.py` | RAG vector store |
| `tests/unit/rag/test_rag_system.py` | RAG system |
| `tests/integration/test_report_generators.py` | HTML report generator |
| `tests/integration/test_full_scan.py` | Multi-engine scan (AI/SAST/Semantic) |

---

## 6. What Remains

After cleanup, the codebase is:

```
src/mcp_sentinel/
├── cli/main.py              # scan command only
├── core/
│   ├── config.py            # simplified - no DB/Redis/AI settings
│   ├── logger.py
│   ├── cache_manager.py
│   ├── exceptions.py
│   └── multi_engine_scanner.py  # static engine only
├── detectors/
│   ├── secrets.py           # hardcoded keys, tokens, connection strings
│   ├── prompt_injection.py  # jailbreak/role-manipulation patterns (MCP-specific)
│   ├── tool_poisoning.py    # zero-width chars, homoglyphs, RTLO (MCP-specific)
│   ├── code_injection.py    # eval/exec/subprocess abuse
│   ├── path_traversal.py    # ../traversal, unsafe file ops
│   └── config_security.py  # debug modes, CORS misconfigs
├── engines/
│   └── static/              # pattern-based, fast, no external deps
├── models/
│   ├── vulnerability.py
│   └── scan_result.py
└── reporting/
    ├── terminal_reporter.py
    ├── json_reporter.py
    └── sarif_generator.py
```

**Approximate stats:** ~3,500 LOC (from 13,795) | ~15 dependencies (from 100+) | ~20 files (from 81)
