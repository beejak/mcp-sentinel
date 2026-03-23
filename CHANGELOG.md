# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-03-23

Major codebase reduction. Removed everything that was over-engineered, stub-only, or created unnecessary attack surface for a security tool. What remains is a focused, auditable static scanner with no external binary dependencies and no network calls.

### Added
- `UNUSED_CODE.md` documenting all removed features and security rationale
- Lightweight stdlib `ast`-based `_detect_shell_true_ast()` in `CodeInjectionDetector` for multi-line `subprocess(shell=True)` detection without any external dependencies

### Removed
- **AI engine** (`engines/ai/`) — sent source code to external LLM APIs; antithetical for a security tool
- **SAST engine** (`engines/sast/`) — Semgrep/Bandit wrappers; external binary dependencies with version drift risk
- **Semantic/CFG engine** (`engines/semantic/`) — over-engineered; stdlib AST covers the critical cases
- **RAG system** (`rag/`) — ChromaDB + sentence-transformers; only served the removed AI engine
- **Remediation system** (`remediation/`) — `DiffBuilder.apply_patch()` wrote AI output directly to source files
- **`fix` CLI command** — automated writes to production code from a security scanner is too dangerous
- **API server** (`api/`) — stub FastAPI server; out of scope for a CLI scanner
- **Integrations, Monitoring, Tasks, Storage** — all empty stubs
- **XSS detector** — generic web vulnerability with low signal-to-noise for MCP servers
- **Supply chain detector** — was stub-only; to be rebuilt properly in v0.3
- **HTML report generator** — unnecessary dependency surface
- **`--engines` CLI flag** — no longer needed with a single engine
- **~30 pyproject.toml dependencies:** fastapi, uvicorn, sqlalchemy, alembic, asyncpg, anthropic, langchain*, openai, transformers, sentence-transformers, chromadb, boto3, redis, celery, grpcio*, strawberry-graphql, prometheus-client, opentelemetry*, structlog, sentry-sdk, jira, slack-sdk, PyGithub, tree-sitter*, libcst, semgrep, bandit, pandas, plotly, reportlab, jinja2, weasyprint, and others

### Changed
- `EngineType` enum reduced from `{STATIC, SEMANTIC, SAST, AI}` to `{STATIC}` only
- `EngineSettings` reduced to `enable_static: bool` only
- `Settings` stripped to: `environment`, `log_level`, `engines`, `max_workers`, `cache_ttl`
- `_get_default_detectors()` reduced from 8 to 6 detectors
- `multi_engine_scanner.py` simplified to single-engine orchestration
- `cli/main.py` rewritten — removed `fix` command, `--engines`, `--output html`
- `detectors/__init__.py` — exports `ConfigSecurityDetector` and `PathTraversalDetector`; removes `SupplyChainDetector`
- `reporting/generators/__init__.py` — exports `SARIFGenerator` only

### Fixed
- Tests updated to match current detector count (6, not 8)
- Multi-engine scanner progress callback assertion corrected to `EngineType.STATIC`
- Framework detection test: XSS assertion removed (XSSDetector deleted)
- Path traversal: two multi-line taint tests marked `@pytest.mark.xfail`
- Config test fully rewritten (previously imported 5 removed config classes)

### Test results
- **248 passed, 4 xfailed, 0 failed**
- xfail tests document multi-line taint patterns that require semantic analysis

---

## [v1.0.0-beta.4] - 2026-01-24

### Added
- **Advanced Logging System**:
  - Structured JSON logging support for file output.
  - Console logging with `rich` formatting and colors.
  - Log rotation (10MB max size, 5 backups).
  - CLI options `--log-level` and `--log-file`.
- **Enhanced CLI**:
  - Interactive prompts using `questionary` when required arguments are missing.
  - Improved help messages and command structure.
- **Documentation**:
  - Added `TUTORIAL.md` covering CLI and logging features.

### Changed
- Refactored `main.py` to use `setup_logging` before command execution.
- Updated `ScanResult` model to use string status instead of enum for better compatibility.

### Fixed
- Fixed `ScanStatus` import error in tests.
- Improved test coverage for CLI and logging modules.

## [v1.0.0-beta.3] - 2026-01-15

### Added
- Phase 4.3 AI Analysis Engine integration.
- Support for Claude 3.5 Sonnet.
- Cost tracking and budget management.

## [v1.0.0-beta.2] - 2026-01-10

### Added
- Phase 4.2.2 Semantic Analysis improvements.
- JavaScript multi-line comment detection.
- Python fixture detection enhancements.
