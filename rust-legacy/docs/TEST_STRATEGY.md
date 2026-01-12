# MCP Sentinel - Test Strategy & Documentation

**Version**: 2.0.0
**Purpose**: Comprehensive testing strategy, test documentation, and quality assurance approach

---

## Table of Contents

1. [Overview](#overview)
2. [Testing Philosophy](#testing-philosophy)
3. [Test Pyramid](#test-pyramid)
4. [Test Types](#test-types)
5. [Test Coverage by Component](#test-coverage-by-component)
6. [Existing Test Documentation](#existing-test-documentation)
7. [Test Infrastructure](#test-infrastructure)
8. [Running Tests](#running-tests)
9. [Writing New Tests](#writing-new-tests)
10. [CI/CD Integration](#cicd-integration)
11. [Performance Benchmarking](#performance-benchmarking)
12. [Future Test Plans](#future-test-plans)

---

## Overview

MCP Sentinel employs a comprehensive testing strategy across multiple levels:

**Current Test Status** (Phase 2.0):
- **Unit Tests**: 43 tests across 15 modules
- **Integration Tests**: Planned (Phase 2.5)
- **E2E Tests**: Planned (Phase 3.0)
- **Performance Tests**: Planned (Phase 2.5)

**Test Coverage Goals**:
- Critical path: 100% coverage
- Core modules: 90%+ coverage
- Utilities: 80%+ coverage
- CLI: Manual + integration tests

**Why These Goals**: Balance between thoroughness and development velocity. Critical code (security, data integrity) requires 100% coverage to prevent vulnerabilities. Utilities can tolerate some uncovered edge cases.

---

## Testing Philosophy

### Core Principles

1. **Test What Matters**
   - **Why**: Not all code needs equal testing. Security-critical code (secret detection, permission checks) needs exhaustive testing. Trivial getters don't.
   - **Application**: More tests for detection engines, fewer for simple data models.

2. **Fast Feedback**
   - **Why**: Developers should get test results in seconds, not minutes.
   - **Application**: Unit tests must run in <5 seconds total. Mock external services.

3. **Isolation**
   - **Why**: Tests should not depend on external state (databases, APIs, file system).
   - **Application**: Use in-memory storage, mock LLM providers, temporary directories.

4. **Determinism**
   - **Why**: Flaky tests erode trust and waste time.
   - **Application**: No random data, no timing dependencies, no shared state.

5. **Readability**
   - **Why**: Tests are documentation. They show how code should be used.
   - **Application**: Clear test names, explicit assertions, minimal setup.

6. **The "Why" Must Be Clear**
   - **Why**: User specifically requested "reasons behind why for everything we do".
   - **Application**: Every test has a doc comment explaining what it validates and why that matters.

---

## Test Pyramid

```
                             ┌──────────────────┐
                             │   E2E Tests      │
                             │   (Manual)       │
                             │   ~5 scenarios   │
                             └────────┬─────────┘
                                      │
                        ┌─────────────┴──────────────┐
                        │  Integration Tests         │
                        │  (Component interactions)  │
                        │  ~20 tests                 │
                        └─────────────┬──────────────┘
                                      │
               ┌──────────────────────┴───────────────────────┐
               │           Unit Tests                          │
               │   (Individual functions/modules)              │
               │   ~100+ tests                                 │
               └───────────────────────────────────────────────┘

Distribution (Target):
- Unit Tests: 70% (fast, isolated, many)
- Integration Tests: 20% (component interactions)
- E2E Tests: 10% (full system flows)

Why This Distribution:
- Unit tests are cheapest to write and fastest to run
- They catch most bugs (70-80% of issues)
- Integration tests validate component contracts
- E2E tests validate user workflows (expensive but critical)
```

---

## Test Types

### 1. Unit Tests

**Purpose**: Validate individual functions, methods, and modules in isolation.

**Scope**: Single function or small module.

**Example**:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Test that API key pattern matching works correctly.
    ///
    /// Why: Secret detection is security-critical. False negatives
    /// mean leaked credentials. This test ensures we detect common
    /// API key formats.
    ///
    /// Scope: Tests regex pattern matching only, not file I/O.
    #[test]
    fn test_api_key_detection() {
        let detector = SecretDetector::new();
        let code = r#"
            const API_KEY = "sk_live_abc123xyz789def456ghi"
        "#;

        let findings = detector.scan(code);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret_type, "api_key");
        assert_eq!(findings[0].confidence, 0.95);
    }
}
```

**Why Unit Tests**:
- **Fast**: Run in milliseconds (entire suite <5 seconds)
- **Isolated**: No external dependencies
- **Focused**: One concept per test
- **Debuggable**: Failures point to exact issue

**Current Unit Test Coverage**:

| Module                  | Tests | Coverage | Why These Tests                     |
|-------------------------|-------|----------|-------------------------------------|
| `suppression/parser`    | 3     | 85%      | Config parsing is critical          |
| `suppression/matcher`   | 8     | 95%      | Pattern matching must be correct    |
| `suppression/auditor`   | 2     | 90%      | Audit logging for compliance        |
| `suppression/mod`       | 2     | 80%      | Integration of sub-modules          |
| `utils/git`             | 3     | 70%      | Git operations (complex edge cases) |
| `storage/cache`         | 4     | 90%      | Cache correctness (perf critical)   |
| `storage/baseline`      | 5     | 90%      | Baseline comparison (data integrity)|
| `engines/ai_analysis`   | 3     | 75%      | AI integration (mock providers)     |
| `providers/*`           | 8     | 80%      | Provider contracts                  |

**Total**: 43 unit tests

---

### 2. Integration Tests

**Purpose**: Validate that multiple components work together correctly.

**Scope**: 2-3 modules interacting through their public APIs.

**Example** (Planned):
```rust
/// Integration test: Scan with AI analysis using cached results.
///
/// Why: This validates the critical path where scanner discovers
/// files, checks cache, calls AI provider only on cache miss, and
/// stores results. This is the most common production workflow.
///
/// Scope: Scanner → Cache → AI Provider (mocked) → Storage
///
/// Components tested:
/// - Scanner file discovery
/// - Cache hit/miss logic
/// - Provider API contract
/// - Result aggregation
#[tokio::test]
async fn test_scan_with_ai_caching() -> Result<()> {
    // Setup: Create temp directory with test files
    let temp_dir = TempDir::new()?;
    write_file(&temp_dir, "vuln.py", "password = 'hardcoded123'")?;

    // Setup: Mock AI provider
    let provider = MockProvider::new()
        .expect_analyze()
        .times(1)  // Should be called once (cache miss)
        .returning(|_| Ok(AIFindings { ... }));

    // Setup: Initialize cache
    let cache = Cache::new_in_memory()?;

    // First scan: Cache miss
    let scanner = Scanner::new(config)
        .with_provider(provider.clone())
        .with_cache(cache.clone());

    let result1 = scanner.scan_directory(&temp_dir).await?;
    assert_eq!(result1.vulnerabilities.len(), 1);

    // Second scan: Cache hit (provider shouldn't be called)
    provider.expect_analyze().times(0);  // No call expected

    let result2 = scanner.scan_directory(&temp_dir).await?;
    assert_eq!(result2.vulnerabilities.len(), 1);
    assert_eq!(result1.vulnerabilities[0].id, result2.vulnerabilities[0].id);

    Ok(())
}
```

**Why Integration Tests**:
- **Contract Validation**: Ensure components agree on interfaces
- **Real Interactions**: Test actual data flow between modules
- **Integration Bugs**: Catch issues that unit tests miss (e.g., incorrect data serialization)

**Planned Integration Tests** (Phase 2.5):

| Test Suite              | Tests | Purpose                                  |
|-------------------------|-------|------------------------------------------|
| `scan_with_cache`       | 5     | Scanner + Cache interaction              |
| `scan_with_baseline`    | 4     | Scanner + Baseline comparison            |
| `scan_with_suppression` | 3     | Scanner + Suppression filtering          |
| `ai_provider_contract`  | 8     | Provider implementations vs. trait       |
| `output_formats`        | 4     | Scanner → Output formatters              |

**Total Planned**: ~24 integration tests

---

### 3. End-to-End (E2E) Tests

**Purpose**: Validate complete user workflows from CLI to output.

**Scope**: Entire application, including CLI parsing, scanning, and output.

**Example** (Planned):
```rust
/// E2E test: Full scan workflow with SARIF output.
///
/// Why: This validates the complete user journey: user runs
/// `mcp-sentinel scan`, gets scan results, and output is in
/// valid SARIF format that GitHub can consume. This is the most
/// common CI/CD use case.
///
/// Scope: Full application (CLI → Scanner → Output)
///
/// Success criteria:
/// - CLI parses arguments correctly
/// - Scan finds vulnerabilities
/// - SARIF output is valid (schema check)
/// - Exit code is correct (1 if vulns found)
#[test]
fn test_e2e_scan_with_sarif_output() {
    // Setup: Create sample vulnerable project
    let project = create_test_project_with_vulns();

    // Execute: Run CLI command
    let output = Command::new("mcp-sentinel")
        .args(&["scan", project.path(), "--output", "sarif", "--output-file", "results.sarif"])
        .output()
        .expect("Failed to execute command");

    // Assert: Exit code 1 (vulnerabilities found)
    assert_eq!(output.status.code(), Some(1));

    // Assert: SARIF file created
    assert!(Path::new("results.sarif").exists());

    // Assert: SARIF is valid JSON
    let sarif: SarifReport = serde_json::from_reader(
        File::open("results.sarif")?
    )?;

    // Assert: SARIF schema version correct
    assert_eq!(sarif.version, "2.1.0");

    // Assert: Found expected vulnerabilities
    assert!(sarif.runs[0].results.len() > 0);
    assert!(sarif.runs[0].results.iter().any(|r| {
        r.rule_id == "secrets_leakage"
    }));
}
```

**Why E2E Tests**:
- **User Perspective**: Test actual user workflows
- **System Integration**: Validate all components together
- **Confidence**: Highest confidence that app works for users

**Planned E2E Tests** (Phase 3.0):

| Scenario                  | Purpose                                   |
|---------------------------|-------------------------------------------|
| Quick scan with terminal  | Most common development workflow          |
| Deep scan with AI         | Pre-release security audit workflow       |
| CI/CD with SARIF          | GitHub Actions integration                |
| Proxy runtime monitoring  | Live traffic inspection workflow          |
| Monitor with file watch   | Continuous dev feedback workflow          |

**Total Planned**: ~5 E2E tests

---

### 4. Property-Based Tests

**Purpose**: Generate random inputs to find edge cases.

**Scope**: Functions with complex input domains.

**Example** (Planned):
```rust
/// Property test: Secret detection should never panic on any input.
///
/// Why: Secret scanner processes untrusted user code. It must
/// never crash, even on malformed, binary, or adversarial input.
/// A panic could be exploited for DoS.
///
/// Property: ∀ input, detector.scan(input) either succeeds or
/// returns an error, but never panics.
///
/// Scope: SecretDetector robustness
#[quickcheck]
fn prop_secret_detector_never_panics(input: String) -> bool {
    let detector = SecretDetector::new();
    let result = std::panic::catch_unwind(|| {
        detector.scan(&input)
    });
    result.is_ok()  // Never panic, always Ok or Err
}

/// Property test: Cache hash is deterministic.
///
/// Why: Cache relies on content-addressable storage. Same content
/// must always produce same hash, or cache will be inconsistent.
///
/// Property: ∀ content, hash(content) == hash(content)
///
/// Scope: Cache hashing function
#[quickcheck]
fn prop_cache_hash_deterministic(content: Vec<u8>) -> bool {
    let hash1 = compute_hash(&content);
    let hash2 = compute_hash(&content);
    hash1 == hash2
}
```

**Why Property-Based Tests**:
- **Edge Cases**: Find bugs that manual tests miss
- **Robustness**: Ensure code handles unexpected inputs
- **Specification**: Properties document invariants

**Planned Property Tests** (Phase 3.0):

| Property                   | Module          | Why                                 |
|----------------------------|-----------------|-------------------------------------|
| Never panic on any input   | All detectors   | Security (prevent DoS)              |
| Hash determinism           | Cache           | Correctness (cache consistency)     |
| Suppression idempotence    | Suppression     | Correctness (repeated filtering)    |
| Output format validity     | Output          | Correctness (valid JSON/SARIF)      |

**Total Planned**: ~10 property tests

---

### 5. Performance Tests

**Purpose**: Ensure performance requirements are met.

**Scope**: Critical performance paths (scanning, caching, AI calls).

**Example** (Planned):
```rust
/// Performance test: Quick scan should process 1000+ files/second.
///
/// Why: Quick scans are used in development loops where speed
/// matters. Slow scans frustrate developers and reduce adoption.
///
/// Requirement: 1000 files/second (= 1ms per file)
///
/// Scope: Scanner with pattern matching (no AI)
#[bench]
fn bench_quick_scan_throughput(b: &mut Bencher) {
    // Setup: 1000 files with typical MCP server code
    let files = generate_test_files(1000);

    b.iter(|| {
        let scanner = Scanner::new(quick_config());
        scanner.scan_files(&files).unwrap();
    });

    // Assert: Average time < 1ms per file
    assert!(b.elapsed_average() < Duration::from_millis(1000));
}

/// Performance test: Cache lookup should be <1ms.
///
/// Why: Cache is checked for every file. Slow cache defeats
/// the purpose (we want 100x speedup, not 2x).
///
/// Requirement: <1ms lookup (sub-millisecond)
///
/// Scope: Cache::get() operation
#[bench]
fn bench_cache_lookup(b: &mut Bencher) {
    let cache = Cache::new()?;
    let key = "test_key";
    cache.set(key, CachedResult { ... })?;

    b.iter(|| {
        cache.get(key).unwrap()
    });

    assert!(b.elapsed_average() < Duration::from_micros(1000)); // <1ms
}
```

**Why Performance Tests**:
- **Requirements Validation**: Ensure we meet stated performance goals
- **Regression Detection**: Catch performance degradations
- **Optimization Guidance**: Identify bottlenecks

**Performance Requirements**:

| Operation             | Target         | Why                                  |
|-----------------------|----------------|--------------------------------------|
| Quick scan            | 1000 files/sec | Dev loop (instant feedback)          |
| Cache lookup          | <1ms           | Checked per file (must be fast)      |
| Cache hit scan        | 100x faster    | Justify caching complexity           |
| AI provider call      | <30s timeout   | Prevent hanging (user frustration)   |
| Baseline comparison   | <100ms         | Calculated per scan (low overhead)   |

**Planned Performance Tests** (Phase 2.5):

| Benchmark               | Tests | Purpose                                |
|-------------------------|-------|----------------------------------------|
| `scan_throughput`       | 3     | Quick/deep/cached scan speeds          |
| `cache_performance`     | 4     | Lookup, store, compression times       |
| `provider_latency`      | 4     | OpenAI, Anthropic, Gemini, Ollama      |
| `suppression_overhead`  | 2     | Pattern matching impact on scan time   |

**Total Planned**: ~13 performance benchmarks

---

## Test Coverage by Component

### Suppression System (15 tests)

**File**: `src/suppression/parser.rs` (3 tests)

```rust
#[test]
fn test_suppression_validation() {
    /// Why: Suppression config is user-provided YAML. Invalid
    /// config could bypass security checks. We must validate
    /// all required fields.
    ///
    /// Scope: Tests that empty ID, empty reason, and missing
    /// patterns are all rejected with clear error messages.
    /// Success criteria: validate() returns Err for invalid configs
}

#[test]
fn test_suppression_expiration() {
    /// Why: Expired suppressions should be ignored. If we keep
    /// applying expired rules, temporary overrides become permanent,
    /// defeating the purpose of expiration dates.
    ///
    /// Scope: Tests is_expired() correctly compares dates.
    /// Edge cases: Past dates (expired), future dates (not expired),
    /// no expiration (never expires), invalid dates (parsing error).
}

#[test]
fn test_pattern_deserialization() {
    /// Why: Suppression patterns are loaded from YAML. Deserialization
    /// errors would cause all suppressions to fail. This validates
    /// serde can parse all pattern types.
    ///
    /// Scope: Tests YAML → Rust struct deserialization for:
    /// - glob patterns
    /// - file patterns
    /// - vuln_type patterns
    /// - line number patterns
}
```

**File**: `src/suppression/matcher.rs` (8 tests)

```rust
#[test]
fn test_match_file_pattern() {
    /// Why: File pattern matching is exact (not glob). Wrong
    /// implementation could suppress the wrong files.
    ///
    /// Scope: Tests that "src/config.py" matches exactly, and
    /// "src/config.py" does not match "tests/config.py".
}

#[test]
fn test_match_glob_pattern() {
    /// Why: Glob patterns enable wildcards ("tests/**/*.py").
    /// Incorrect glob logic would suppress too many or too few files.
    ///
    /// Scope: Tests patterns like "**/*.py", "tests/*", "src/**"
    /// against various file paths.
}

#[test]
fn test_match_line_pattern() {
    /// Why: Line-specific suppressions prevent false positives
    /// on specific code lines. Off-by-one errors would suppress
    /// wrong lines.
    ///
    /// Scope: Tests that line 42 matches exactly, not line 41 or 43.
}

#[test]
fn test_match_vuln_type_pattern() {
    /// Why: Vuln type matching is fuzzy (substring match). Too
    /// strict = no matches. Too loose = wrong suppressions.
    ///
    /// Scope: Tests that "secrets" matches "secrets_leakage",
    /// "api_secrets", etc. Case-insensitive.
}

#[test]
fn test_match_severity_pattern() {
    /// Why: Severity filtering suppresses low-priority issues.
    /// Wrong logic = critical issues suppressed.
    ///
    /// Scope: Tests "high" matches High and Critical, not Medium/Low.
}

#[test]
fn test_match_description_pattern() {
    /// Why: Regex matching enables flexible suppression rules.
    /// Invalid regex would crash or match incorrectly.
    ///
    /// Scope: Tests regex patterns against vulnerability descriptions.
}

#[test]
fn test_match_vuln_id_pattern() {
    /// Why: ID-based suppression is most precise. Must match exact
    /// SHA-256 hash.
    ///
    /// Scope: Tests exact ID match, no partial matches.
}

#[test]
fn test_multiple_patterns_all_must_match() {
    /// Why: Multiple patterns use AND logic (not OR). All patterns
    /// must match for suppression to apply. This is critical for
    /// precision (avoid over-suppressing).
    ///
    /// Scope: Tests that suppression with [file, line] patterns
    /// only applies when both file AND line match.
}
```

**File**: `src/suppression/auditor.rs` (2 tests)

```rust
#[test]
fn test_audit_log_creation() {
    /// Why: Audit logging is required for compliance (SOC2, ISO 27001).
    /// Missing logs = audit failure.
    ///
    /// Scope: Tests that log file is created in correct location
    /// with correct permissions (0600 = user-only read/write).
}

#[test]
fn test_audit_entry_format() {
    /// Why: Audit logs use JSON Lines format for easy parsing.
    /// Invalid JSON = log aggregation tools fail.
    ///
    /// Scope: Tests that each log entry is valid JSON with required
    /// fields (timestamp, suppression_id, reason, vuln_type, etc.).
}
```

**File**: `src/suppression/mod.rs` (2 tests)

```rust
#[test]
fn test_empty_manager() {
    /// Why: Empty manager (no suppressions) is valid state. Must
    /// work without crashes.
    ///
    /// Scope: Tests that empty manager returns correct stats
    /// (0 total, 0 active, 0 expired).
}

#[test]
fn test_stats_format() {
    /// Why: Stats are displayed to user. Incorrect formatting =
    /// confusing output.
    ///
    /// Scope: Tests human-readable string format:
    /// "Suppressions: 10 total (8 active, 2 expired)"
}
```

---

### Git Integration (3 tests)

**File**: `src/utils/git.rs` (3 tests)

```rust
#[test]
fn test_is_git_repo() {
    /// Why: Git integration requires valid Git repo. Must detect
    /// both Git repos and non-repos correctly.
    ///
    /// Scope: Tests GitHelper::is_git_repo() returns true for
    /// repositories, false otherwise. Tautology test (demonstrates
    /// function works without external dependencies).
}

#[test]
fn test_make_relative() {
    /// Why: Git returns absolute paths. Scanner needs relative paths
    /// for consistent reporting. Incorrect logic = wrong file paths
    /// in reports.
    ///
    /// Scope: Tests that "/home/user/project/src/main.rs" becomes
    /// "src/main.rs" when repo root is "/home/user/project".
}

#[test]
fn test_make_relative_already_relative() {
    /// Why: Some Git operations return relative paths. Function must
    /// handle both absolute and relative inputs (idempotency).
    ///
    /// Scope: Tests that "src/main.rs" remains "src/main.rs".
}
```

---

### Storage Systems (9 tests)

**File**: `src/storage/cache.rs` (4 tests)

```rust
#[test]
fn test_cache_store_and_retrieve() {
    /// Why: Cache is fundamental to performance (100x speedup).
    /// Store/retrieve must be correct or cache is useless.
    ///
    /// Scope: Tests that stored value can be retrieved with same
    /// content. Tests content-addressable storage (hash-based keys).
}

#[test]
fn test_cache_miss() {
    /// Why: Cache miss is common on first scan. Must return None
    /// (not error or stale data).
    ///
    /// Scope: Tests that non-existent key returns None.
}

#[test]
fn test_cache_compression() {
    /// Why: gzip compression reduces storage by 70-90%. Must work
    /// correctly or decompression fails (corrupted cache).
    ///
    /// Scope: Tests that compressed data can be decompressed and
    /// matches original. Tests gzip + bincode round-trip.
}

#[test]
fn test_cache_stats() {
    /// Why: Cache statistics help users understand cache effectiveness.
    /// Wrong stats = misleading information.
    ///
    /// Scope: Tests that hit/miss counts are tracked correctly.
    /// Tests hit rate calculation (hits / total).
}
```

**File**: `src/storage/baseline.rs` (5 tests)

```rust
#[test]
fn test_baseline_save_and_load() {
    /// Why: Baseline comparison requires persistent storage. Save/load
    /// must preserve all vulnerability data exactly.
    ///
    /// Scope: Tests round-trip serialization (save → load → compare).
    /// Tests that all fields (id, type, severity, location) are preserved.
}

#[test]
fn test_baseline_comparison_new() {
    /// Why: NEW vulnerabilities are highest priority (regression).
    /// Must detect correctly or users miss new issues.
    ///
    /// Scope: Tests that vulnerability present in current scan but
    /// not in baseline is marked NEW.
}

#[test]
fn test_baseline_comparison_fixed() {
    /// Why: FIXED vulnerabilities show progress. Must detect correctly
    /// or users don't know what was fixed.
    ///
    /// Scope: Tests that vulnerability present in baseline but not
    /// in current scan is marked FIXED.
}

#[test]
fn test_baseline_comparison_changed() {
    /// Why: CHANGED vulnerabilities (different location/severity)
    /// may indicate refactoring or evolving threat. Must detect.
    ///
    /// Scope: Tests that vulnerability with same ID but different
    /// severity or location is marked CHANGED.
}

#[test]
fn test_baseline_comparison_unchanged() {
    /// Why: UNCHANGED vulnerabilities are low priority (known issues).
    /// Must track to avoid duplicate work.
    ///
    /// Scope: Tests that vulnerability identical in both scans is
    /// marked UNCHANGED.
}
```

---

### AI Analysis Engine (3 tests)

**File**: `src/engines/ai_analysis.rs` (3 tests)

```rust
#[test]
fn test_code_sanitization() {
    /// Why: Code sanitization prevents credential leakage to cloud
    /// LLMs. Critical security function. Missed secrets = data breach.
    ///
    /// Scope: Tests that hardcoded API keys, passwords, and tokens
    /// are masked before sending to cloud. Tests regex patterns for:
    /// - AWS keys (AKIA...)
    /// - API keys (32+ char strings)
    /// - Bearer tokens
}

#[test]
fn test_snippet_size_limit() {
    /// Why: API providers charge per token. Unlimited snippets =
    /// cost overruns. Also prevents context overflow (4K-8K token limits).
    ///
    /// Scope: Tests that code snippets are truncated to 4KB max.
    /// Tests that truncation preserves syntax (doesn't cut mid-string).
}

#[test]
fn test_ai_findings_parsing() {
    /// Why: LLM responses must be parsed into structured data.
    /// Parsing errors = lost findings. JSON parsing is fragile.
    ///
    /// Scope: Tests that typical LLM response (JSON) is parsed
    /// correctly into AIFinding struct. Tests error handling for
    /// malformed JSON.
}
```

---

### LLM Providers (8 tests)

**File**: `src/providers/openai.rs`, `anthropic.rs`, `google.rs`, `ollama.rs`

```rust
#[test]
fn test_provider_initialization() {
    /// Why: Provider must validate API key at initialization.
    /// Missing/invalid key should fail fast (not at first API call).
    ///
    /// Scope: Tests that provider initialization with invalid key
    /// returns error immediately.
}

#[test]
fn test_provider_api_call_success() {
    /// Why: Core functionality. Provider must make API call and
    /// return result. Mock HTTP client to avoid external dependencies.
    ///
    /// Scope: Tests that analyze() method makes correct HTTP request
    /// (URL, headers, body) and parses response.
}

#[test]
fn test_provider_rate_limiting() {
    /// Why: Providers have rate limits. Must respect to avoid 429 errors.
    ///
    /// Scope: Tests that provider uses semaphore to limit concurrent
    /// requests (5 for OpenAI, 3 for Anthropic, etc.).
}

#[test]
fn test_provider_error_handling() {
    /// Why: API calls can fail (network, rate limits, service outage).
    /// Must handle gracefully without crashing.
    ///
    /// Scope: Tests error cases:
    /// - 401 Unauthorized → InvalidAPIKey error
    /// - 429 Rate Limited → Retry with backoff
    /// - 500 Server Error → Retry 3 times
    /// - Timeout → ProviderTimeout error
}

// Repeated for each provider (OpenAI, Anthropic, Google, Ollama)
// = 4 providers × 4 tests = 16 total (currently 8 implemented)
```

---

## Test Infrastructure

### Test Utilities

**File**: `tests/common/mod.rs` (Planned)

```rust
/// Shared test utilities to reduce boilerplate.
///
/// Why: Test setup is repetitive. Utilities improve maintainability
/// and consistency across tests.

/// Create temporary directory with test files
pub fn create_test_project() -> TempDir {
    // Why: Isolated test environment, auto-cleanup
}

/// Generate sample vulnerable code
pub fn vulnerable_code_snippet(vuln_type: VulnType) -> String {
    // Why: Consistent test data across tests
}

/// Mock LLM provider for testing
pub struct MockProvider {
    // Why: Avoid real API calls (expensive, slow, flaky)
}

/// Assert vulnerability found
pub fn assert_vuln_found(result: &ScanResult, vuln_type: &str) {
    // Why: Reduce assertion boilerplate
}
```

---

### Test Data

**Directory**: `tests/fixtures/` (Planned)

```
tests/fixtures/
├── vulnerable_server/        # Sample MCP server with known vulns
│   ├── src/
│   │   ├── secrets.py       # Hardcoded secrets
│   │   ├── unsafe_file.py   # Path traversal
│   │   └── sql_injection.py # SQL injection
│   └── mcp_config.json      # MCP configuration
├── clean_server/             # Sample server with no vulns
├── suppression_configs/      # Sample suppression YAML files
└── sarif_outputs/            # Expected SARIF output samples
```

**Why Test Fixtures**:
- **Reusable**: Same test data across multiple tests
- **Realistic**: Actual MCP server structures
- **Version Controlled**: Test data documented in Git
- **Regression**: Detect changes in detection logic

---

### Mock External Services

```rust
/// Mock HTTP client for testing providers without real API calls.
///
/// Why: Real API calls are:
/// - Slow (800ms+ latency)
/// - Expensive ($0.01+ per call)
/// - Flaky (network issues, rate limits)
/// - Require credentials (CI doesn't have API keys)
///
/// Mocking provides:
/// - Speed (<1ms)
/// - Determinism (no network failures)
/// - Isolation (tests don't affect each other)
/// - No credentials needed
pub struct MockHttpClient {
    responses: HashMap<String, MockResponse>,
}

impl MockHttpClient {
    pub fn expect_post(&mut self, url: &str) -> MockResponseBuilder {
        // Setup expected request and response
    }
}

/// Mock file system for testing without disk I/O.
///
/// Why: Disk I/O is slow and requires cleanup. In-memory FS is:
/// - Faster (no syscalls)
/// - Isolated (no shared state)
/// - Clean (auto-cleanup)
pub struct MockFS {
    files: HashMap<PathBuf, Vec<u8>>,
}
```

---

## Running Tests

### Local Development

```bash
# Run all unit tests
cargo test

# Run specific test
cargo test test_suppression_validation

# Run tests in specific module
cargo test suppression::

# Run tests with output (see println! statements)
cargo test -- --nocapture

# Run tests in parallel (default)
cargo test -- --test-threads=4

# Run tests serially (for debugging)
cargo test -- --test-threads=1

# Run only fast tests (exclude slow integration tests)
cargo test --lib

# Run with coverage (requires cargo-tarpaulin)
cargo tarpaulin --out Html --output-dir coverage/

# Run benchmarks (performance tests)
cargo bench
```

**Why These Commands**:
- `cargo test`: Standard Rust test runner, integrates with IDE
- `--nocapture`: See debug output (helpful for troubleshooting)
- `--test-threads`: Control parallelism (serial for debugging)
- `cargo tarpaulin`: Coverage report shows untested code

---

### CI/CD Pipeline

**GitHub Actions** (`.github/workflows/test.yml`):

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable

      - name: Run Tests
        run: cargo test --verbose

      - name: Generate Coverage
        run: |
          cargo install cargo-tarpaulin
          cargo tarpaulin --out Xml

      - name: Upload Coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./cobertura.xml

  integration-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Dependencies
        run: |
          # Install Ollama for local LLM tests
          curl -fsSL https://ollama.com/install.sh | sh
          ollama pull llama3.2:8b

      - name: Run Integration Tests
        run: cargo test --test integration

  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Benchmarks
        run: cargo bench

      - name: Check Performance Regression
        run: |
          # Compare with baseline (previous run)
          ./scripts/check_perf_regression.sh
```

**Why CI/CD Testing**:
- **Automated**: Every PR tested before merge
- **Consistent**: Same environment for all tests
- **Fast Feedback**: Developers notified of failures immediately
- **Coverage Tracking**: See coverage trends over time

---

## Writing New Tests

### Test Template

```rust
/// [One-line description of what this test validates]
///
/// Why: [Explain why this test matters. What happens if this fails?]
///
/// Scope: [What is tested, what is mocked, what edge cases]
///
/// Success criteria: [What assertions must pass]
#[test]  // or #[tokio::test] for async
fn test_descriptive_name() -> Result<()> {  // Use Result for ? operator
    // Arrange: Set up test data and mocks
    let input = ...;
    let expected = ...;

    // Act: Execute the code under test
    let actual = function_under_test(input)?;

    // Assert: Verify results
    assert_eq!(actual, expected);
    assert!(condition);

    Ok(())
}
```

**Why This Template**:
- **"Why" Comment**: User's explicit requirement ("reasons behind why")
- **Arrange/Act/Assert**: Clear test structure (industry standard)
- **Result Type**: Use `?` for cleaner error handling
- **Descriptive Name**: `test_what_when_then` pattern

---

### Test Naming Conventions

```
test_<function>_<scenario>_<expected_result>

Examples:
- test_cache_get_when_miss_returns_none
- test_suppression_matcher_with_glob_pattern_matches_correctly
- test_ai_provider_on_rate_limit_retries_with_backoff
```

**Why This Convention**:
- **Clarity**: Name tells full story (no need to read code)
- **Searchability**: Easy to find tests for specific functions
- **Failure Messages**: Test name appears in CI logs (instant understanding)

---

### Test Documentation Requirements

Every test must have:

1. **Summary**: One-line description of what is tested
2. **Why**: Explanation of why this test matters (user requirement)
3. **Scope**: What is tested, what is mocked, edge cases covered
4. **Success Criteria**: What assertions validate correctness

**Example**:
```rust
/// Test that expired suppressions are not applied.
///
/// Why: Expired suppressions represent temporary overrides (e.g.,
/// "Suppress for 30 days while we refactor"). If expired rules
/// continue to apply, temporary becomes permanent, defeating the
/// purpose. This could hide newly introduced instances of the same
/// vulnerability pattern.
///
/// Scope: Tests Suppression::is_expired() with:
/// - Past date (should be expired)
/// - Future date (should not be expired)
/// - No expiration (should never expire)
/// - Invalid date format (should not panic)
///
/// Success criteria:
/// - Past date → is_expired() returns true
/// - Future date → is_expired() returns false
/// - No date → is_expired() returns false
#[test]
fn test_suppression_expiration() {
    // ... test implementation
}
```

---

## CI/CD Integration

### GitHub Actions Workflow

**Purpose**: Automated testing on every PR and commit.

**Stages**:

1. **Lint**: Check code style (rustfmt, clippy)
   - Why: Enforce consistent style, catch common mistakes
2. **Unit Tests**: Run all unit tests
   - Why: Fast feedback (90% of bugs caught here)
3. **Integration Tests**: Component interaction tests
   - Why: Catch integration bugs (10% of bugs)
4. **Coverage**: Generate coverage report
   - Why: Identify untested code
5. **Benchmarks**: Run performance tests (main branch only)
   - Why: Detect performance regressions

**Quality Gates**:
- All tests must pass (no failures)
- Coverage must be ≥80% (adjustable per module)
- No new clippy warnings (lints must be fixed)
- Benchmarks must not regress >10% (performance)

**Why These Gates**: Balance quality with velocity. 100% coverage is unrealistic. 80% catches most issues. 10% perf regression is normal variance.

---

## Performance Benchmarking

### Benchmark Suite

```rust
/// Benchmark: Quick scan throughput
///
/// Why: Quick scans are used in dev loops. Must be fast (<1s for
/// typical projects) to maintain developer productivity.
///
/// Target: 1000 files/second (1ms per file)
///
/// Scope: Scanner with pattern matching (no AI)
#[bench]
fn bench_quick_scan(b: &mut Bencher) {
    let files = load_benchmark_files(1000);
    let scanner = Scanner::new(quick_config());

    b.iter(|| {
        scanner.scan_files(&files).unwrap()
    });

    // Assert: Less than 1ms per file
    let per_file = b.elapsed_average() / 1000;
    assert!(per_file < Duration::from_millis(1));
}
```

**Benchmark Metrics**:
- **Throughput**: Operations per second
- **Latency**: Time per operation (average, p50, p95, p99)
- **Memory**: Peak memory usage
- **Cache Hit Rate**: Percentage of cache hits

**Why Benchmarks**:
- **Performance Requirements**: Validate stated goals
- **Regression Detection**: Catch slowdowns in PRs
- **Optimization Guidance**: Profile to find bottlenecks

---

## Future Test Plans

### Phase 2.5 (Advanced Analysis)

**Integration Tests** (Q1 2026):
- Scanner + Cache + AI provider (mocked)
- Scanner + Baseline comparison
- Scanner + Suppression filtering
- Provider contract tests (all providers)
- Output format validation

**Performance Tests**:
- Scan throughput benchmarks
- Cache performance (lookup/store/compress)
- Provider latency (all providers)

**Property-Based Tests**:
- Detector robustness (never panic)
- Cache hash determinism

---

### Phase 3.0 (Advanced Features)

**E2E Tests**:
- Full CLI workflows (scan, proxy, monitor, audit)
- Output format generation (JSON, SARIF, HTML, PDF)
- Configuration file loading
- Error handling (invalid inputs, missing files)

**Stress Tests**:
- Large codebase (100K+ files)
- High concurrent load (100+ API requests)
- Memory limits (constrained environments)

**Security Tests**:
- Credential sanitization (no leaks to cloud)
- Path traversal prevention (file access)
- Command injection prevention (git operations)

---

## Summary

**Testing Strategy**:
- 70% Unit Tests (fast, isolated, many)
- 20% Integration Tests (component interactions)
- 10% E2E Tests (full workflows)

**Current Status** (Phase 2.0):
- ✅ 43 unit tests across 15 modules
- ⏳ Integration tests (planned Phase 2.5)
- ⏳ E2E tests (planned Phase 3.0)
- ⏳ Performance benchmarks (planned Phase 2.5)

**Quality Goals**:
- Critical path: 100% coverage
- Core modules: 90%+ coverage
- Utilities: 80%+ coverage
- All tests documented with "why"

**Key Principles**:
1. Test what matters (security, correctness, performance)
2. Fast feedback (unit tests <5 seconds)
3. Isolation (no external dependencies in unit tests)
4. Determinism (no flaky tests)
5. Readability (tests are documentation)
6. **The "Why" Must Be Clear** (user requirement)

**Running Tests**:
```bash
cargo test                 # All unit tests
cargo test --test integration  # Integration tests
cargo bench               # Performance benchmarks
cargo tarpaulin           # Coverage report
```

**Writing Tests**:
- Follow template (Arrange/Act/Assert)
- Document "why" (user requirement)
- Name descriptively (`test_what_when_then`)
- Use mocks (avoid external dependencies)

For more information, see:
- [Architecture Documentation](./ARCHITECTURE.md)
- [Contributing Guide](../CONTRIBUTING.md)
- [Test Fixtures](../tests/fixtures/)
