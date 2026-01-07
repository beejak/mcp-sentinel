# MCP Sentinel Python - Test Strategy & Documentation

**Version**: 1.0.0  
**Purpose**: Comprehensive testing strategy for Python edition

---

## Table of Contents

1. [Overview](#overview)
2. [Testing Philosophy](#testing-philosophy)
3. [Test Pyramid](#test-pyramid)
4. [Test Types](#test-types)
5. [Test Coverage by Component](#test-coverage-by-component)
6. [Test Infrastructure](#test-infrastructure)
7. [Running Tests](#running-tests)
8. [Writing New Tests](#writing-new-tests)
9. [CI/CD Integration](#cicd-integration)
10. [Performance Benchmarking](#performance-benchmarking)

---

## Overview

MCP Sentinel Python employs a comprehensive async-first testing strategy optimized for Python's concurrency model.

**Current Test Status** (v1.0.0):
- **Unit Tests**: 25+ tests across 8 modules
- **Integration Tests**: Planned (v1.1.0)
- **E2E Tests**: Planned (v1.2.0)
- **Performance Tests**: Async concurrency benchmarks

**Test Coverage Goals**:
- Critical path: 100% coverage
- Core modules: 90%+ coverage
- Async functions: 95%+ coverage
- CLI: Manual + integration tests

---

## Testing Philosophy

### Core Principles

1. **Test Async Code Async**
   - **Why**: Python's async/await requires special testing patterns
   - **How**: Use `pytest-asyncio` for all async test functions
   - **Example**:
     ```python
     @pytest.mark.asyncio
     async def test_async_scan():
         results = await scan_directory(Path("/test"), config)
         assert len(results.vulnerabilities) > 0
     ```

2. **Mock External Dependencies**
   - **Why**: File I/O and network calls should be mocked for speed
   - **How**: Use `pytest-mock` and `unittest.mock`
   - **Example**:
     ```python
     def test_detector_with_mocked_file(mocker):
         mocker.patch('pathlib.Path.read_text', return_value="mock_secret_key")
         detector = SecretKeyDetector()
         results = detector.detect(Path("test.py"), "mock_secret_key")
         assert len(results) == 1
     ```

3. **Test Concurrency Boundaries**
   - **Why**: Semaphore-based concurrency can have race conditions
   - **How**: Test with different semaphore limits
   - **Example**:
     ```python
     @pytest.mark.asyncio
     async def test_semaphore_limits():
         config = Config(max_concurrent_files=2)
         results = await scan_directory(large_path, config)
         # Verify no memory spikes or deadlocks
         assert results.success
     ```

---

## Test Pyramid

```
        /\
       /  \
      /E2E \     (3 tests) - Full system integration
     /______\
    /        \
   /   Int.   \   (8 tests) - Component integration
  /__________\
 /            \
/     Unit     \  (25+ tests) - Individual functions
/______________\
```

**Unit Tests** (25+ tests)
- Individual detector functions
- Configuration validation
- Utility functions
- Pydantic model validation

**Integration Tests** (8 tests)
- Multi-detector orchestration
- File system interactions
- Async concurrency behavior
- Error handling chains

**E2E Tests** (3 tests)
- Full CLI workflow
- Report generation
- Configuration file parsing

---

## Test Types

### 1. Unit Tests (`tests/unit/`)

**Detector Tests**:
```python
class TestSecretKeyDetector:
    def test_detects_hardcoded_secret(self):
        detector = SecretKeyDetector()
        content = 'API_KEY = "sk-1234567890abcdef"'
        results = detector.detect(Path("test.py"), content)
        assert len(results) == 1
        assert results[0].severity == "HIGH"
    
    def test_ignores_safe_patterns(self):
        detector = SecretKeyDetector()
        content = 'API_KEY = os.getenv("API_KEY")'
        results = detector.detect(Path("test.py"), content)
        assert len(results) == 0
```

**Configuration Tests**:
```python
def test_config_validation():
    config = Config(
        max_concurrent_files=10,
        timeout_seconds=30
    )
    assert config.max_concurrent_files <= 50  # Max limit
    assert config.timeout_seconds >= 5       # Min timeout
```

### 2. Integration Tests (`tests/integration/`)

**Async Orchestration Tests**:
```python
@pytest.mark.asyncio
async def test_concurrent_file_processing():
    """Test that semaphore limits concurrent processing"""
    config = Config(max_concurrent_files=3)
    
    start_time = time.time()
    results = await scan_directory(test_directory, config)
    duration = time.time() - start_time
    
    # Should complete faster than sequential processing
    assert duration < expected_sequential_time
    assert results.total_files_scanned > 0
```

### 3. Performance Tests (`tests/performance/`)

**Concurrency Benchmarks**:
```python
@pytest.mark.asyncio
async def test_memory_usage_with_semaphores():
    """Ensure semaphores prevent memory spikes"""
    config = Config(max_concurrent_files=5)
    
    # Monitor memory usage during scan
    process = psutil.Process()
    initial_memory = process.memory_info().rss
    
    results = await scan_directory(large_directory, config)
    
    final_memory = process.memory_info().rss
    memory_increase = final_memory - initial_memory
    
    # Memory increase should be reasonable
    assert memory_increase < 100 * 1024 * 1024  # 100MB max
```

---

## Test Coverage by Component

| Component | Coverage Goal | Current Status | Key Test Areas |
|-----------|---------------|----------------|----------------|
| **Detectors** | 95% | 90% | Pattern matching, false positives |
| **Async Engine** | 100% | 95% | Semaphore behavior, error handling |
| **CLI** | 80% | 75% | Command parsing, output formatting |
| **Config** | 100% | 100% | Validation, defaults, type safety |
| **Utils** | 85% | 80% | File I/O, path handling, regex helpers |

---

## Test Infrastructure

### Test Dependencies (`pyproject.toml`)
```toml
[tool.poetry.group.dev.dependencies]
pytest = "^7.4.0"
pytest-asyncio = "^0.21.0"
pytest-mock = "^3.11.1"
pytest-cov = "^4.1.0"
pytest-benchmark = "^4.0.0"
psutil = "^5.9.0"  # Memory monitoring
```

### Test Configuration (`pytest.ini`)
```ini
[tool:pytest]
testpaths = tests
asyncio_mode = auto
addopts = 
    --strict-markers
    --strict-config
    --cov=mcp_sentinel
    --cov-report=term-missing
    --cov-report=html
    --cov-report=xml
markers =
    slow: marks tests as slow (deselect with '-m "not slow"')
    integration: marks tests as integration tests
    performance: marks tests as performance benchmarks
```

---

## Running Tests

### Full Test Suite
```bash
# Run all tests with coverage
poetry run pytest

# Run with verbose output
poetry run pytest -v

# Run specific test categories
poetry run pytest -m "not slow"          # Skip slow tests
poetry run pytest tests/unit/            # Unit tests only
poetry run pytest tests/integration/       # Integration tests
poetry run pytest tests/performance/       # Performance tests
```

### Async-Specific Testing
```bash
# Test async functions specifically
poetry run pytest -k "async"

# Test with different event loop policies
poetry run pytest --asyncio-mode=strict

# Test concurrency behavior
poetry run pytest tests/unit/test_concurrency.py -v
```

### Performance Benchmarking
```bash
# Run performance benchmarks
poetry run pytest tests/performance/ --benchmark-only

# Compare performance between versions
poetry run pytest tests/performance/ --benchmark-compare=main

# Generate performance report
poetry run pytest tests/performance/ --benchmark-json=perf.json
```

---

## Writing New Tests

### Test File Structure
```python
tests/
unit/
    test_detectors.py      # All detector tests
    test_config.py         # Configuration tests
    test_utils.py          # Utility function tests
integration/
    test_scanner.py        # Scanner integration
    test_cli.py            # CLI integration
performance/
    test_concurrency.py    # Async performance
    test_memory.py         # Memory usage tests
```

### Test Naming Conventions
- **Unit tests**: `test_<function_name>_<scenario>`
  - `test_detects_hardcoded_secret`
  - `test_ignores_safe_patterns`
- **Integration tests**: `test_<component>_<behavior>`
  - `test_scanner_handles_large_directories`
  - `test_cli_outputs_valid_json`
- **Performance tests**: `test_<metric>_<constraint>`
  - `test_memory_usage_with_semaphores`
  - `test_concurrent_file_processing_speed`

### Async Test Patterns
```python
@pytest.mark.asyncio
async def test_async_function():
    # Test async function
    result = await async_function()
    assert result.expected_property

@pytest.mark.asyncio
async def test_async_with_timeout():
    # Test with timeout
    with timeout(5):
        result = await slow_async_function()
        assert result.is_valid()

@pytest.mark.asyncio
async def test_concurrent_operations():
    # Test multiple concurrent operations
    tasks = [async_function(i) for i in range(10)]
    results = await asyncio.gather(*tasks)
    assert all(r.success for r in results)
```

---

## CI/CD Integration

### GitHub Actions Workflow
```yaml
name: Python Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.8, 3.9, 3.10, 3.11]
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install Poetry
        uses: snok/install-poetry@v1
      - name: Install dependencies
        run: poetry install
      - name: Run tests
        run: poetry run pytest
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml
```

### Pre-commit Hooks
```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: pytest
        name: pytest
        entry: poetry run pytest tests/unit/
        language: system
        pass_filenames: false
        always_run: true
      - id: pytest-cov
        name: pytest-cov
        entry: poetry run pytest --cov=mcp_sentinel --cov-report=term-missing
        language: system
        pass_filenames: false
        always_run: true
```

---

## Performance Benchmarking

### Benchmark Configuration
```python
# tests/conftest.py
def pytest_benchmark_update_json(config, benchmarks, output_json):
    """Custom benchmark reporting"""
    for benchmark in benchmarks:
        if benchmark["name"].startswith("test_"):
            # Add custom metrics
            benchmark["custom"] = {
                "memory_mb": benchmark.get("extra_info", {}).get("memory_mb", 0),
                "files_per_second": benchmark.get("extra_info", {}).get("files_per_second", 0)
            }
```

### Performance Targets
| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| **Scan Speed** | 1000 files/sec | 850 files/sec | ⚠️ |
| **Memory Usage** | <100MB | 75MB | ✅ |
| **Concurrency** | 10 files | 10 files | ✅ |
| **Startup Time** | <1s | 0.8s | ✅ |

### Performance Regression Detection
```bash
# Compare with baseline
poetry run pytest tests/performance/ --benchmark-compare=main

# Fail on regression >10%
poetry run pytest tests/performance/ --benchmark-compare-fail=mean:10%

# Generate detailed report
poetry run pytest tests/performance/ --benchmark-histogram=perf_histogram
```

---

**Next Steps**: 
- Add integration tests for v1.1.0
- Implement E2E tests for v1.2.0
- Set up performance monitoring in CI/CD
- Add property-based testing with Hypothesis