# MCP Sentinel — QA Checklist

**Version**: v0.4.0

---

## Table of Contents

1. [Testing Philosophy](#testing-philosophy)
2. [Test Pyramid](#test-pyramid)
3. [Quality Gates](#quality-gates)
4. [Pre-Release Checklist](#pre-release-checklist)
5. [Test Categories](#test-categories)
6. [Security Testing](#security-testing)
7. [CI/CD Integration](#cicd-integration)
8. [Common Issues & Solutions](#common-issues--solutions)

---

## Testing Philosophy

1. **Test what matters** — focus on security-sensitive detection logic; trust the framework for boilerplate
2. **Fast feedback** — unit tests run in < 1s each; full suite in < 2 minutes
3. **Realistic inputs** — test with real code samples from `tests/fixtures/`, not toy strings
4. **Automated gates** — no manual QA steps; all checks run in CI

---

## Test Pyramid

```
         /\
        /  \    Integration (7 tests)
       /────\   End-to-end scanner pipeline
      /      \
     /────────\  Unit (327 tests)
    /          \  Detector logic, engine, CLI, config
   /────────────\
```

**Current distribution (v0.4.0):**
- Unit tests: 327 (96%)
- Integration tests: 7 (2%)
- Other (caching, CLI): 6 (2%)
- **Total: 334 tests**

See [`docs/TEST_COVERAGE.md`](TEST_COVERAGE.md) for the full test inventory.

---

## Quality Gates

### Must pass before merge

```bash
# Full test suite — zero failures
pytest tests/ -v

# Type checking (non-blocking in CI, blocking for release)
mypy src/mcp_sentinel --ignore-missing-imports

# Linting
ruff check src/

# Security scan of MCP Sentinel's own source
bandit -r src/
```

### Performance gates

- Full test suite: < 2 minutes
- No single test: > 10 seconds
- No performance regression vs. previous release baseline

---

## Pre-Release Checklist

### Code quality

- [ ] All 334 tests pass (`pytest tests/ -v`)
- [ ] No unexpected test failures or regressions
- [ ] xfail tests still xfail (4 expected: multi-line taint tracking)
- [ ] Type checking passes (`mypy src/mcp_sentinel --ignore-missing-imports`)
- [ ] Linting passes (`ruff check src/`)
- [ ] Security scan passes (`bandit -r src/`)
- [ ] No debug `print()` statements left in production code

### Detector quality

For each of the 9 detectors, verify:

- [ ] `SecretsDetector` — detects AWS keys, OpenAI keys, private keys; ignores placeholder values
- [ ] `CodeInjectionDetector` — detects `os.system`, `subprocess(shell=True)`, `eval`/`exec`; ignores comments
- [ ] `PromptInjectionDetector` — detects role manipulation, jailbreaks; ignores legitimate `system:` usage
- [ ] `ToolPoisoningDetector` — detects invisible unicode, cross-tool instructions, file references in schemas
- [ ] `PathTraversalDetector` — detects `../`, unsafe archive extraction; ignores `realpath`/`resolve` usage
- [ ] `ConfigSecurityDetector` — detects debug mode, wildcard CORS, weak TLS; ignores test files
- [ ] `SSRFDetector` — detects variable URLs in HTTP calls, metadata endpoints; ignores literal URLs
- [ ] `NetworkBindingDetector` — detects `0.0.0.0` binding; ignores `127.0.0.1`
- [ ] `MissingAuthDetector` — detects unauthenticated sensitive routes; ignores routes with auth decorators

### Functional verification

- [ ] `mcp-sentinel --help` renders correctly
- [ ] `mcp-sentinel scan --help` renders correctly
- [ ] `mcp-sentinel --version` shows `v0.4.0`
- [ ] `mcp-sentinel scan .` completes without error on this repo
- [ ] `--output terminal` produces readable terminal output
- [ ] `--output json --json-file out.json` produces valid JSON
- [ ] `--output sarif --json-file out.sarif` produces valid SARIF 2.1.0
- [ ] `--severity critical` filters to critical only
- [ ] `--no-progress` suppresses progress bar (for CI)

### Documentation

- [ ] `README.md` reflects current features
- [ ] `docs/TEST_COVERAGE.md` matches actual test suite
- [ ] `docs/CI_CD_INTEGRATION.md` uses correct CLI flags
- [ ] `docs/CONFIGURATION.md` lists only real env vars
- [ ] `CHANGELOG.md` has entry for this version

---

## Test Categories

### Detector tests (pattern)

Each detector test file covers:

```python
# 1. Detection tests — positive cases
async def test_detect_<pattern>(detector):
    content = "... code with vulnerability ..."
    vulns = await detector.detect(Path("file.py"), content)
    assert len(vulns) == 1
    assert vulns[0].severity == "high"

# 2. False-positive suppression — negative cases
async def test_ignore_<safe_pattern>(detector):
    content = "... safe equivalent code ..."
    vulns = await detector.detect(Path("file.py"), content)
    assert len(vulns) == 0

# 3. File type applicability
def test_is_applicable_python(detector):
    assert detector.is_applicable(Path("app.py")) is True

def test_is_applicable_markdown(detector):
    assert detector.is_applicable(Path("README.md")) is False

# 4. Metadata quality
async def test_line_number_accuracy(detector):
    vulns = await detector.detect(Path("file.py"), content)
    assert vulns[0].line == 3  # exact line number

async def test_code_snippet_captured(detector):
    vulns = await detector.detect(Path("file.py"), content)
    assert "os.system" in vulns[0].code_snippet
```

### Integration tests

```python
# tests/integration/test_scanner.py
async def test_scan_directory(temp_dir, sample_python_file):
    result = await scanner.scan(temp_dir)
    assert result.total_files_scanned >= 1

async def test_scan_finds_secrets(temp_dir, sample_python_file):
    result = await scanner.scan(temp_dir)
    secrets = result.get_by_severity("high")
    assert len(secrets) > 0
```

---

## Security Testing

### Self-scan

MCP Sentinel scans its own source on every CI run:

```bash
mcp-sentinel scan src/ --output sarif --json-file self-scan.sarif --no-progress
```

This catches regressions where newly written detector code accidentally triggers its own detectors.

### Input handling

- [ ] Empty files handled gracefully (no crash, empty result)
- [ ] Binary files skipped without error
- [ ] Extremely long lines don't cause ReDoS (regex patterns are anchored/bounded)
- [ ] Permission-denied files logged as errors, scan continues
- [ ] Symlinks handled safely (no infinite loops)

### False-positive rate

Monitor the ratio of false positives on the `tests/fixtures/` corpus. Each detector maintains explicit suppression tests — any new false positive must be accompanied by a suppression test.

---

## CI/CD Integration

```bash
# Install
pip install -e ".[dev]"

# Full suite with coverage
pytest tests/ \
  --cov=src/mcp_sentinel \
  --cov-report=xml \
  --cov-report=term \
  -v

# Unit only (fast, <30s)
pytest tests/unit/ -v

# Integration only
pytest tests/integration/ -v

# Specific detector
pytest tests/unit/test_ssrf_detector.py -v
```

See [`.github/workflows/python-ci.yml`](../.github/workflows/python-ci.yml) for the full matrix (Python 3.9–3.12, Linux/macOS/Windows).

---

## Common Issues & Solutions

**Issue: `async def` tests not collected**
- Ensure `pytest-asyncio` is installed and `asyncio_mode = "auto"` is set in `pyproject.toml`

**Issue: Tests pass locally but fail in CI**
- Check Python version — CI matrix covers 3.9–3.12; some fixture syntax differs
- Run with the same Python version: `python3.9 -m pytest tests/`

**Issue: xfail tests unexpectedly passing (XPASS)**
- Two XPASS tests in `test_code_injection.py` are expected and tracked — the underlying patterns were improved
- New unexpected XPASSes should prompt removal of the `xfail` marker and addition of a proper assertion

**Issue: Coverage drop**
- New detector code added without tests will drop coverage
- Run `pytest --cov=src/mcp_sentinel --cov-report=term-missing` to identify uncovered lines
- Target: maintain or improve overall coverage with each PR
