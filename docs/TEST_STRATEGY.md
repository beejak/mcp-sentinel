# MCP Sentinel — Test Strategy

**Version**: v0.2.0
**Total tests**: 334 (327 unit, 7 integration)

---

## Table of Contents

1. [Overview](#overview)
2. [Test Pyramid](#test-pyramid)
3. [Async Testing Patterns](#async-testing-patterns)
4. [Test Coverage by Component](#test-coverage-by-component)
5. [Test Infrastructure](#test-infrastructure)
6. [Running Tests](#running-tests)
7. [Writing New Tests](#writing-new-tests)
8. [CI/CD Integration](#cicd-integration)

---

## Overview

MCP Sentinel uses an **async-first testing strategy** driven by `pytest-asyncio`. All detector tests are async — they mirror the async `detect()` interface exactly, which means tests run at the same concurrency level as production.

**v0.2.0 test status:**
- 334 tests collected
- 330 pass, 4 xfail (documented multi-line taint tracking gaps)
- 2 XPASS (tracked — patterns improved beyond original xfail expectation)
- 0 failures
- 33% overall coverage (detector logic is well covered; CLI and reporting paths have lower coverage)

Full test inventory: [`docs/TEST_COVERAGE.md`](TEST_COVERAGE.md)

---

## Test Pyramid

```
         /\
        /  \   Integration (7)
       /────\  Full pipeline: scan dir, find secrets,
      /      \ risk score, severity filtering
     /────────\
    /          \ Unit (327)
   /            \ Per-detector detection, false positives,
  /              \ applicability, metadata quality
 /────────────────\
```

---

## Async Testing Patterns

### Basic async detector test

```python
import pytest
from pathlib import Path

@pytest.fixture
def detector():
    return SSRFDetector()

async def test_detect_requests_get_variable(detector):
    content = 'requests.get(url)'
    vulns = await detector.detect(Path("app.py"), content)
    assert len(vulns) == 1
    assert vulns[0].severity == "high"
```

`asyncio_mode = "auto"` in `pyproject.toml` means `@pytest.mark.asyncio` is not required.

### False-positive suppression test

```python
async def test_no_false_positive_literal_url(detector):
    content = 'requests.get("https://api.example.com/data")'
    vulns = await detector.detect(Path("app.py"), content)
    assert len(vulns) == 0
```

### Fixture-based tests

```python
@pytest.fixture
def python_fixture_path(tmp_path):
    fixture = Path("tests/fixtures/python/code_injection_samples.py")
    return fixture

async def test_python_fixture_file(detector, python_fixture_path):
    content = python_fixture_path.read_text()
    vulns = await detector.detect(python_fixture_path, content)
    assert len(vulns) > 0
```

### xfail for known gaps

```python
@pytest.mark.xfail(
    reason="Multi-line taint tracking requires semantic analysis (v0.5.0)"
)
async def test_detect_open_with_request_param(detector):
    content = """
x = request.args.get("filename")
open(x)
"""
    vulns = await detector.detect(Path("app.py"), content)
    assert len(vulns) == 1
```

---

## Test Coverage by Component

| Component | Tests | Coverage | Notes |
|---|---|---|---|
| `SecretsDetector` | 8 | ~80% | Core patterns well covered |
| `CodeInjectionDetector` | 34 | ~70% | Multi-line patterns xfail'd |
| `ConfigSecurityDetector` | 51 | ~65% | Largest detector test file |
| `PromptInjectionDetector` | 41 | ~70% | Full pattern coverage |
| `ToolPoisoningDetector` | 58 | ~75% | Core + enhanced patterns |
| `PathTraversalDetector` | 42 | ~65% | 4 xfail for taint tracking |
| `SSRFDetector` | 25 | ~75% | New in v0.2.0 |
| `NetworkBindingDetector` | 22 | ~70% | New in v0.2.0 |
| `MissingAuthDetector` | 19 | ~65% | New in v0.2.0 |
| `MultiEngineScanner` | 11 | ~60% | Orchestration logic |
| `StaticAnalysisEngine` | 6 | ~55% | Engine dispatch |
| `Settings/Config` | 5 | 100% | Full coverage |
| CLI | 4 | ~50% | Entry points only |
| Logger | 3 | ~60% | Formatter + handlers |
| Integration | 7 | — | End-to-end only |

---

## Test Infrastructure

### Dependencies (`pyproject.toml` `[dev]` extras)

```toml
[project.optional-dependencies]
dev = [
    "pytest>=7.4",
    "pytest-asyncio>=0.21",
    "pytest-cov>=4.1",
    "pytest-mock>=3.11",
    "ruff",
    "mypy",
    "bandit",
]
```

Install with:

```bash
pip install -e ".[dev]"
```

### pytest configuration (`pyproject.toml`)

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
addopts = [
    "--cov=src/mcp_sentinel",
    "--cov-report=term-missing",
    "--cov-report=html",
    "--cov-report=xml",
]
```

### Test directory layout

```
tests/
├── conftest.py              # Shared fixtures (temp dirs, sample files)
├── fixtures/                # Real code samples for detector tests
│   ├── python/
│   ├── javascript/
│   └── mcp_schemas/
├── unit/
│   ├── core/
│   │   └── test_config.py
│   ├── test_ssrf_detector.py
│   ├── test_network_binding.py
│   ├── test_missing_auth.py
│   ├── test_tool_poisoning_enhanced.py
│   ├── test_tool_poisoning.py
│   ├── test_prompt_injection.py
│   ├── test_path_traversal.py
│   ├── test_config_security.py
│   ├── test_code_injection.py
│   ├── test_secrets_detector.py
│   ├── test_multi_engine_scanner.py
│   ├── test_static_engine.py
│   ├── test_cli_enhanced.py
│   ├── test_framework_detection.py
│   └── test_logger.py
├── integration/
│   └── test_scanner.py
└── test_caching.py
```

---

## Running Tests

```bash
# Full suite with coverage
pytest tests/ -v

# Fast (no coverage overhead)
pytest tests/ -v --no-cov

# Unit tests only
pytest tests/unit/ -v

# Specific detector
pytest tests/unit/test_ssrf_detector.py -v

# v0.2.0 new detectors only
pytest tests/unit/test_ssrf_detector.py \
       tests/unit/test_network_binding.py \
       tests/unit/test_missing_auth.py \
       tests/unit/test_tool_poisoning_enhanced.py -v

# Show xfail details
pytest tests/ -v -rN

# Skip xfail tests entirely
pytest tests/ -p no:xfail
```

---

## Writing New Tests

### File naming

- One test file per detector: `tests/unit/test_<detector_name>.py`
- Integration tests: `tests/integration/test_<feature>.py`

### Test naming conventions

```
test_detect_<pattern>           # positive detection
test_no_false_positive_<case>   # negative (should not detect)
test_is_applicable_<filetype>   # file type filter
test_not_applicable_<filetype>  # exclusion
test_<property>_<assertion>     # metadata quality
```

### Required test coverage for a new detector

Every new detector must have:

1. At least one positive detection test per pattern variant
2. At least one false-positive suppression test per pattern
3. `is_applicable()` tests for all supported and excluded file types
4. `test_detector_name(detector)` — verify the `name` property
5. `test_detector_enabled_by_default(detector)` — verify `enabled == True`
6. Line number accuracy test
7. Code snippet captured test
8. Vulnerability metadata tests (severity, remediation text, references)

---

## CI/CD Integration

```yaml
# GitHub Actions snippet
- name: Run tests
  run: |
    pip install -e ".[dev]"
    pytest tests/ \
      --cov=src/mcp_sentinel \
      --cov-report=xml \
      -v
```

Full configs for all CI platforms: [`docs/CI_CD_INTEGRATION.md`](CI_CD_INTEGRATION.md)

Matrix tested against: Python 3.9, 3.10, 3.11, 3.12 on Linux, macOS, Windows.
