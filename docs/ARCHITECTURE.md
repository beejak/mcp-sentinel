# MCP Sentinel — Architecture

**Version**: v0.3.0
**Status**: 10 detectors, 409 tests, static engine

---

## Table of Contents

1. [Overview](#overview)
2. [Module Structure](#module-structure)
3. [Scan Pipeline](#scan-pipeline)
4. [Static Analysis Engine](#static-analysis-engine)
5. [Detector System](#detector-system)
6. [Async Architecture](#async-architecture)
7. [Configuration](#configuration)
8. [CLI Design](#cli-design)
9. [Reporting](#reporting)
10. [Caching](#caching)
11. [Testing Architecture](#testing-architecture)
12. [Future Plans](#future-plans)

---

## Overview

MCP Sentinel is a **static pattern-matching security scanner** purpose-built for MCP (Model Context Protocol) servers. v0.3.0 is intentionally focused: one engine (static), ten detectors, no external service dependencies.

### Key design decisions

| Decision | Rationale |
|---|---|
| Static engine only | Fast, deterministic, no API keys, works air-gapped |
| Async-first | All file I/O is async; concurrent scanning via configurable worker pool |
| Detector per vulnerability class | Focused, independently testable, easy to extend |
| Pydantic v2 configuration | Type-safe settings with env var overrides |
| SARIF output | Native integration with GitHub, GitLab, Azure DevOps security tabs |
| CLI-only | No REST API, no server, no database — minimal footprint |

---

## Module Structure

```
src/mcp_sentinel/
├── __init__.py                  # Public API exports
├── __main__.py                  # python -m mcp_sentinel entry point
│
├── cli/
│   ├── main.py                  # Click CLI — `mcp-sentinel scan`
│   └── output/                  # Terminal rendering (Rich)
│
├── core/
│   ├── config.py                # Settings (Pydantic v2, env var loading)
│   ├── scanner.py               # Single-file scanner
│   ├── multi_engine_scanner.py  # Orchestrator — discovers files, dispatches workers
│   ├── cache_manager.py         # MD5-based file result cache
│   ├── exceptions.py            # Custom exception hierarchy
│   └── logger.py                # Structured logging setup
│
├── engines/
│   ├── base.py                  # AbstractEngine interface
│   └── static/
│       └── static_engine.py     # StaticAnalysisEngine — runs all detectors per file
│
├── detectors/
│   ├── base.py                  # BaseDetector interface
│   ├── secrets.py               # SecretsDetector
│   ├── code_injection.py        # CodeInjectionDetector
│   ├── prompt_injection.py      # PromptInjectionDetector
│   ├── tool_poisoning.py        # ToolPoisoningDetector
│   ├── path_traversal.py        # PathTraversalDetector
│   ├── config_security.py       # ConfigSecurityDetector
│   ├── ssrf.py                  # SSRFDetector
│   ├── network_binding.py       # NetworkBindingDetector
│   ├── missing_auth.py          # MissingAuthDetector
│   └── supply_chain.py          # SupplyChainDetector
│
├── models/
│   ├── vulnerability.py         # Vulnerability dataclass
│   └── scan_result.py           # ScanResult dataclass
│
└── reporting/
    └── generators/
        └── sarif_generator.py   # SARIF 2.1.0 output
```

---

## Scan Pipeline

```
User runs: mcp-sentinel scan /path/to/server

          CLI (main.py)
              │
              ▼
    MultiEngineScanner.scan()
              │
    ┌─────────▼──────────┐
    │  File Discovery    │  Walk directory tree, apply .sentinelignore
    └─────────┬──────────┘
              │  list[Path]
    ┌─────────▼──────────┐
    │  Cache Check       │  Skip unchanged files (MD5 hash)
    └─────────┬──────────┘
              │  uncached files
    ┌─────────▼──────────┐
    │  Worker Pool       │  asyncio.Semaphore(MAX_WORKERS)
    │  (async, parallel) │
    └─────────┬──────────┘
              │  per file
    ┌─────────▼──────────┐
    │  StaticEngine      │  Calls each detector in sequence
    └─────────┬──────────┘
              │  list[Vulnerability] per file
    ┌─────────▼──────────┐
    │  Deduplication     │  Remove identical findings
    └─────────┬──────────┘
              │
    ┌─────────▼──────────┐
    │  ScanResult        │  Aggregate, compute risk score
    └─────────┬──────────┘
              │
         CLI output
    (terminal / JSON / SARIF)
```

---

## Static Analysis Engine

`StaticAnalysisEngine` (`engines/static/static_engine.py`) is the only engine in v0.2.0. It:

1. Receives a file path and reads its content
2. Checks each detector's `is_applicable(file)` — skips detectors that don't apply to the file type
3. Calls `await detector.detect(file, content)` for applicable detectors
4. Collects and returns all `Vulnerability` objects

All detector calls are awaited sequentially per file. Parallelism is at the file level (via the worker pool), not the detector level.

---

## Detector System

### Interface

```python
class BaseDetector:
    name: str
    enabled: bool = True

    def is_applicable(self, file: Path) -> bool:
        """Return True if this detector should run on this file."""

    async def detect(self, file: Path, content: str) -> list[Vulnerability]:
        """Analyze content and return any found vulnerabilities."""
```

### Detector scope (v0.3.0)

| Detector | Languages / File Types | Patterns |
|---|---|---|
| `SecretsDetector` | All | AWS keys, OpenAI keys, Anthropic keys, private keys, DB URLs |
| `CodeInjectionDetector` | Python, JS, TS | `os.system`, `subprocess(shell=True)`, `eval`, `exec`, `child_process.exec` |
| `PromptInjectionDetector` | All text/code | Role manipulation, jailbreak keywords, system prompt assignment |
| `ToolPoisoningDetector` | JSON, YAML, code, text | Invisible unicode, cross-tool instructions, sensitive file references in tool schemas |
| `PathTraversalDetector` | Python, JS, Java, PHP | `../` sequences, unsafe `zipfile`/`tarfile` extraction, unvalidated `open()` |
| `ConfigSecurityDetector` | Python, JS, YAML, JSON, nginx, Dockerfile | Debug mode, wildcard CORS, weak TLS, insecure cookies, `ALLOWED_HOSTS=*` |
| `SSRFDetector` | Python, JS, TS, Go, Java | HTTP calls with variable URLs, cloud metadata endpoints |
| `NetworkBindingDetector` | Python, Go, JS, YAML, `.env` | `host="0.0.0.0"`, `:8080` shorthand, `BIND_HOST=0.0.0.0` |
| `MissingAuthDetector` | Python, JS, TS, JSON | Sensitive routes/tools without auth decorators/middleware |
| `SupplyChainDetector` | Python, JS, TS, Shell, manifests | Encoded payloads, install-time exec/network, exfiltration, BCC injection, typosquatting |

### Adding a new detector

1. Create `src/mcp_sentinel/detectors/my_detector.py` inheriting from `BaseDetector`
2. Implement `is_applicable()` and `detect()`
3. Add to `src/mcp_sentinel/detectors/__init__.py`
4. Register in `StaticAnalysisEngine`
5. Add tests in `tests/unit/test_my_detector.py`

---

## Async Architecture

All scan I/O is async. Concurrency is controlled by an `asyncio.Semaphore` keyed to `MAX_WORKERS`:

```python
semaphore = asyncio.Semaphore(settings.max_workers)

async def scan_file(path: Path):
    async with semaphore:
        content = await aiofiles.open(path).read()
        return await engine.scan_file(path, content)

results = await asyncio.gather(*[scan_file(p) for p in files])
```

This means at most `MAX_WORKERS` files are processed concurrently. Memory usage scales linearly with `MAX_WORKERS` × average file size.

---

## Configuration

Configuration uses Pydantic v2 `BaseSettings`. Environment variables are loaded automatically:

```python
class Settings(BaseSettings):
    enable_static_analysis: bool = True
    log_level: str = "info"
    max_workers: int = 4
    cache_ttl: int = 3600
    environment: str = "development"

    model_config = SettingsConfigDict(env_file=".env")
```

---

## CLI Design

The CLI uses [Click](https://click.palletsprojects.com/). Entry point: `mcp_sentinel.cli.main:cli`.

```
mcp-sentinel
└── scan <target>
    ├── --output [terminal|json|sarif]
    ├── --json-file <path>
    ├── --severity [critical|high|medium|low|info]
    ├── --no-progress
    ├── --log-level [debug|info|warning|error]
    └── --log-file <path>
```

Terminal output uses [Rich](https://github.com/Textualize/rich) for tables, progress bars, and syntax-highlighted code snippets.

---

## Reporting

### Terminal

Rich table with columns: severity badge, title, file:line, code snippet.

### JSON

Direct serialization of `ScanResult` — all vulnerabilities with full metadata.

### SARIF 2.1.0

Generated by `SARIFGenerator`. Compatible with:
- GitHub Code Scanning (Security tab)
- GitLab Security reports
- Azure DevOps Security Code Scanning
- VS Code SARIF Viewer extension

---

## Caching

`CacheManager` stores scan results per file indexed by MD5 hash of file content:

- On scan: check cache → if hit and TTL valid → return cached vulnerabilities
- On scan: if miss → run detectors → store result with timestamp
- Cache file: `.sentinel/cache.json` (added to `.gitignore`)
- TTL: controlled by `CACHE_TTL` env var (default 3600s)

This makes rescans of unchanged codebases near-instant.

---

## Testing Architecture

```
tests/
├── unit/
│   ├── core/
│   │   └── test_config.py           # Settings/configuration
│   ├── test_code_injection.py       # 34 tests
│   ├── test_config_security.py      # 51 tests
│   ├── test_prompt_injection.py     # 41 tests
│   ├── test_tool_poisoning.py       # 38 tests
│   ├── test_tool_poisoning_enhanced.py  # 20 tests (v0.2.0)
│   ├── test_path_traversal.py       # 42 tests
│   ├── test_ssrf_detector.py        # 25 tests (v0.2.0)
│   ├── test_network_binding.py      # 22 tests (v0.2.0)
│   ├── test_missing_auth.py         # 19 tests (v0.2.0)
│   ├── test_secrets_detector.py     # 8 tests
│   ├── test_multi_engine_scanner.py # 11 tests
│   ├── test_static_engine.py        # 6 tests
│   ├── test_cli_enhanced.py         # 4 tests
│   ├── test_framework_detection.py  # 3 tests
│   └── test_logger.py               # 3 tests
├── integration/
│   └── test_scanner.py              # 7 end-to-end tests
└── test_caching.py                  # 1 cache test
```

**Total: 334 tests** — see [`docs/TEST_COVERAGE.md`](TEST_COVERAGE.md) for per-test documentation.

All detector tests follow the same structure:
- Detection tests (positive cases)
- False-positive suppression tests (negative cases)
- `is_applicable()` file type tests
- Metadata quality tests (line numbers, code snippets, remediation text)

---

## Future Plans

| Version | Planned |
|---|---|
| v0.3.0 | Per-detector enable/disable via config; custom pattern rules |
| v0.4.0 | SARIF baseline diffing; suppress known findings |
| v0.5.0 | Multi-line taint tracking (cross-line dataflow for PathTraversal, SSRF) |
| v1.0.0 | Stable API; plugin system for community detectors |
