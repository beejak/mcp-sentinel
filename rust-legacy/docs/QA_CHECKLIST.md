# MCP Sentinel - QA Checklist & Test Cases

**Version**: 2.0.0
**Purpose**: Comprehensive quality assurance checklist for pre-release validation

---

## Table of Contents

1. [Overview](#overview)
2. [Pre-Release Checklist](#pre-release-checklist)
3. [Functional Test Cases](#functional-test-cases)
4. [Integration Test Cases](#integration-test-cases)
5. [Performance Test Cases](#performance-test-cases)
6. [Security Test Cases](#security-test-cases)
7. [Usability Test Cases](#usability-test-cases)
8. [Compatibility Test Cases](#compatibility-test-cases)
9. [Regression Test Cases](#regression-test-cases)
10. [Release Readiness Criteria](#release-readiness-criteria)

---

## Overview

This document provides a comprehensive QA checklist for MCP Sentinel releases. Each test case includes:
- **ID**: Unique identifier for traceability
- **Test Case**: What to test
- **Why**: Reason this test matters (user requirement)
- **Steps**: How to execute the test
- **Expected Result**: What should happen
- **Actual Result**: What actually happened (filled during testing)
- **Status**: Pass/Fail/Blocked
- **Priority**: Critical/High/Medium/Low

**When to Use This Checklist**:
- Before every release (major, minor, patch)
- After major refactoring
- When adding new features
- For security audits

---

## Pre-Release Checklist

### Code Quality

- [ ] **QA-001**: All unit tests pass
  - **Why**: Unit tests catch 70-80% of bugs. Failing tests = known bugs in release.
  - **Command**: `cargo test`
  - **Expected**: 0 failures, all tests pass

- [ ] **QA-002**: Code coverage ≥80%
  - **Why**: Untested code likely has bugs. 80% is industry standard for critical software.
  - **Command**: `cargo tarpaulin --out Html`
  - **Expected**: Total coverage ≥80%, critical modules ≥90%

- [ ] **QA-003**: No clippy warnings
  - **Why**: Clippy catches common mistakes (unused variables, unnecessary clones, etc.).
  - **Command**: `cargo clippy -- -D warnings`
  - **Expected**: 0 warnings

- [ ] **QA-004**: Code formatted with rustfmt
  - **Why**: Consistent style improves readability and reduces cognitive load.
  - **Command**: `cargo fmt -- --check`
  - **Expected**: No formatting differences

- [ ] **QA-005**: No known security vulnerabilities
  - **Why**: Vulnerable dependencies = security incidents. Must audit before release.
  - **Command**: `cargo audit`
  - **Expected**: 0 vulnerabilities

---

### Documentation

- [ ] **QA-006**: README.md updated
  - **Why**: First thing users see. Outdated README = confused users.
  - **Check**: Version number, feature list, installation instructions

- [ ] **QA-007**: CHANGELOG.md updated
  - **Why**: Users need to know what changed. Missing changelog = upgrade confusion.
  - **Check**: New version entry with features, fixes, breaking changes

- [ ] **QA-008**: CLI help text accurate
  - **Why**: Users rely on `--help` for usage. Wrong help = incorrect usage.
  - **Command**: `mcp-sentinel --help`, verify all commands/flags

- [ ] **QA-009**: Architecture docs updated
  - **Why**: Developers need accurate architecture for contributions.
  - **Check**: docs/ARCHITECTURE.md reflects current design

- [ ] **QA-010**: API documentation generated
  - **Why**: Public API needs documentation for library users.
  - **Command**: `cargo doc --no-deps --open`
  - **Expected**: All public items documented

---

### Build & Packaging

- [ ] **QA-011**: Clean build succeeds
  - **Why**: Build errors = broken release. Must compile on clean system.
  - **Command**: `cargo clean && cargo build --release`
  - **Expected**: Build succeeds, 0 errors

- [ ] **QA-012**: Binary size reasonable
  - **Why**: Large binaries = slow downloads, storage issues.
  - **Command**: `ls -lh target/release/mcp-sentinel`
  - **Expected**: <50MB (stripped binary)

- [ ] **QA-013**: Dependencies up-to-date
  - **Why**: Outdated dependencies = missing bug fixes, security patches.
  - **Command**: `cargo outdated`
  - **Expected**: No critical dependencies outdated

- [ ] **QA-014**: Version number updated
  - **Why**: Wrong version = confusion, package conflicts.
  - **Check**: Cargo.toml, README.md, CHANGELOG.md all match

---

## Functional Test Cases

### Scan Command

#### TC-SCAN-001: Basic Quick Scan
- **Priority**: Critical
- **Why**: Most common use case. Must work correctly or tool is useless.
- **Steps**:
  1. Create test project with sample MCP server code
  2. Run: `mcp-sentinel scan ./test-project`
  3. Verify scan completes without errors
  4. Check terminal output for vulnerabilities
- **Expected Result**:
  - Scan completes in <10 seconds
  - Terminal shows colored output with vulnerability summary
  - Exit code 0 (no --fail-on flag)
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-SCAN-002: Deep Scan with Local LLM (Ollama)
- **Priority**: High
- **Why**: AI analysis is key feature. Local LLM enables private, free analysis.
- **Preconditions**: Ollama installed and running (`ollama serve`)
- **Steps**:
  1. Create test project with subtle vulnerability (e.g., logic flaw)
  2. Run: `mcp-sentinel scan ./test-project --mode deep --llm-provider ollama`
  3. Wait for scan to complete (may take 1-2 minutes)
  4. Verify AI findings in output
- **Expected Result**:
  - Scan completes without API errors
  - AI findings appear in output (marked with "AI detected")
  - More vulnerabilities found than quick scan
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-SCAN-003: Deep Scan with Cloud LLM (OpenAI)
- **Priority**: High
- **Why**: Cloud LLMs offer best quality. Must work for users with API keys.
- **Preconditions**: Valid OpenAI API key in env var `MCP_SENTINEL_API_KEY`
- **Steps**:
  1. Export API key: `export MCP_SENTINEL_API_KEY=sk-...`
  2. Run: `mcp-sentinel scan ./test-project --mode deep --llm-provider openai`
  3. Monitor for API calls (should see requests to api.openai.com)
  4. Verify scan completes
- **Expected Result**:
  - Scan completes with API calls to OpenAI
  - AI findings in output
  - Cost displayed at end (if implemented)
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-SCAN-004: SARIF Output Generation
- **Priority**: Critical
- **Why**: SARIF enables GitHub Code Scanning integration (major use case).
- **Steps**:
  1. Run: `mcp-sentinel scan ./test-project --output sarif --output-file results.sarif`
  2. Verify results.sarif file created
  3. Parse SARIF JSON: `jq . results.sarif`
  4. Validate against SARIF schema: Use online validator or schema check
- **Expected Result**:
  - results.sarif file created
  - Valid JSON with correct SARIF schema (version 2.1.0)
  - All vulnerabilities present in SARIF results
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-SCAN-005: JSON Output Generation
- **Priority**: High
- **Why**: JSON enables programmatic consumption (scripts, tools).
- **Steps**:
  1. Run: `mcp-sentinel scan ./test-project --output json --output-file report.json`
  2. Verify report.json file created
  3. Parse JSON: `jq . report.json`
  4. Check structure (summary, vulnerabilities, metadata)
- **Expected Result**:
  - report.json created with valid JSON
  - Contains: summary.critical, summary.high, vulnerabilities array
  - Each vulnerability has: id, type, severity, location, description
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-SCAN-006: Scan with Fail-On Threshold
- **Priority**: Critical
- **Why**: CI/CD integration depends on exit codes. Wrong exit code = broken pipeline.
- **Steps**:
  1. Create project with known critical vulnerability
  2. Run: `mcp-sentinel scan ./test-project --fail-on critical`
  3. Check exit code: `echo $?`
- **Expected Result**:
  - Scan finds critical vulnerability
  - Output shows: "❌ Found vulnerabilities at or above Critical level"
  - Exit code is 1 (not 0)
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-SCAN-007: Scan with Custom Config File
- **Priority**: Medium
- **Why**: Project-specific config is common (exclude paths, custom patterns).
- **Steps**:
  1. Create .mcp-sentinel.yaml with custom exclude paths
  2. Run: `mcp-sentinel scan ./test-project --config .mcp-sentinel.yaml`
  3. Verify excluded paths are not scanned
- **Expected Result**:
  - Config file loaded (check verbose output)
  - Excluded paths skipped
  - Custom patterns applied
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-SCAN-008: Scan Non-Existent Directory
- **Priority**: High
- **Why**: Error handling matters. Must give helpful error, not crash.
- **Steps**:
  1. Run: `mcp-sentinel scan /nonexistent/path`
  2. Check error message and exit code
- **Expected Result**:
  - Error message: "Target path does not exist: '/nonexistent/path'"
  - Helpful suggestion: "Please provide a valid directory path."
  - Exit code is 2 (scan error)
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-SCAN-009: Scan File Instead of Directory
- **Priority**: Medium
- **Why**: Common user mistake. Must give clear error.
- **Steps**:
  1. Run: `mcp-sentinel scan README.md`
  2. Check error message
- **Expected Result**:
  - Error: "Target must be a directory, but 'README.md' is a file."
  - Suggestion: "Please provide a directory to scan."
  - Exit code is 2
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-SCAN-010: Scan with Invalid API Key
- **Priority**: High
- **Why**: API key issues are common. Must fail fast with clear message.
- **Steps**:
  1. Run: `mcp-sentinel scan ./test-project --mode deep --llm-provider openai --llm-api-key invalid`
  2. Check error message
- **Expected Result**:
  - Error: "Invalid API key for OpenAI"
  - No scan performed (fail fast)
  - Exit code is 3 (usage error)
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

### Init Command

#### TC-INIT-001: Initialize Default Config
- **Priority**: Medium
- **Why**: Onboarding experience. Must create valid config.
- **Steps**:
  1. Run: `mcp-sentinel init`
  2. Check ~/.mcp-sentinel/config.yaml created
  3. Verify config is valid YAML
- **Expected Result**:
  - Config file created at default location
  - Valid YAML with all required fields
  - Confirmation message: "✅ Configuration initialized at ..."
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-INIT-002: Initialize Project-Specific Config
- **Priority**: Medium
- **Why**: Per-project config is common workflow.
- **Steps**:
  1. Run: `mcp-sentinel init --config-path .mcp-sentinel.yaml`
  2. Verify .mcp-sentinel.yaml created in current directory
- **Expected Result**:
  - .mcp-sentinel.yaml created
  - Contains default config values
  - File has correct permissions (0644)
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

### Proxy Command (Planned - Phase 2.5)

#### TC-PROXY-001: Start Basic Proxy
- **Priority**: High
- **Why**: Proxy is core feature for runtime monitoring.
- **Steps**:
  1. Create test MCP config JSON
  2. Run: `mcp-sentinel proxy --config test-mcp.json --port 8080`
  3. Verify proxy starts without errors
  4. Check port 8080 is listening: `nc -zv localhost 8080`
- **Expected Result**:
  - Proxy starts successfully
  - Output: "🛡️ Proxy listening on: http://localhost:8080"
  - Port 8080 is open
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

### Monitor Command (Planned - Phase 2.5)

#### TC-MONITOR-001: File Watch Mode
- **Priority**: High
- **Why**: Real-time feedback during development.
- **Steps**:
  1. Run: `mcp-sentinel monitor ./test-project --watch`
  2. Modify a file in test-project
  3. Verify rescan is triggered automatically
- **Expected Result**:
  - Monitor starts and watches files
  - File change detected within 1 second
  - Rescan triggered automatically
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

### Audit Command (Planned - Phase 2.5)

#### TC-AUDIT-001: Comprehensive Audit
- **Priority**: High
- **Why**: Pre-release security sign-off workflow.
- **Steps**:
  1. Run: `mcp-sentinel audit ./test-project --comprehensive`
  2. Wait for audit to complete (may take 5-10 minutes)
  3. Verify all engines ran (static, AI, config, dependency)
- **Expected Result**:
  - Audit completes without errors
  - Report includes findings from all engines
  - Output shows "✅ Audit complete"
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

### Whitelist Command

#### TC-WHITELIST-001: Add Item to Whitelist
- **Priority**: Medium
- **Why**: False positive management is critical for usability.
- **Steps**:
  1. Run: `mcp-sentinel whitelist add tool test_tool abc123...`
  2. Run: `mcp-sentinel whitelist list`
  3. Verify item appears in list
- **Expected Result**:
  - Add command succeeds
  - List shows new item
  - Whitelist stored persistently
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-WHITELIST-002: Export/Import Whitelist
- **Priority**: Low
- **Why**: Team collaboration (share whitelist across team).
- **Steps**:
  1. Add several items to whitelist
  2. Run: `mcp-sentinel whitelist export whitelist.json`
  3. Delete local whitelist
  4. Run: `mcp-sentinel whitelist import whitelist.json`
  5. Verify items restored
- **Expected Result**:
  - Export creates valid JSON file
  - Import restores all items
  - No data loss
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

## Integration Test Cases

### Cache Integration

#### TC-CACHE-001: Cache Hit Performance
- **Priority**: High
- **Why**: Cache is performance optimization. Must provide 100x speedup.
- **Steps**:
  1. Run first scan: `mcp-sentinel scan ./test-project --mode deep`
  2. Note scan duration (e.g., 120 seconds)
  3. Run second scan immediately (no code changes)
  4. Note scan duration (should be ~1-2 seconds)
- **Expected Result**:
  - Second scan is 50-100x faster
  - Output shows cache hit statistics
  - Results are identical
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-CACHE-002: Cache Invalidation on Code Change
- **Priority**: High
- **Why**: Stale cache = missed vulnerabilities. Must invalidate correctly.
- **Steps**:
  1. Run scan with deep mode
  2. Modify a file (add new vulnerability)
  3. Run scan again
  4. Verify new vulnerability detected (cache miss for changed file)
- **Expected Result**:
  - Changed file has cache miss
  - Unchanged files have cache hits
  - New vulnerability detected
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

### Baseline Integration

#### TC-BASELINE-001: Detect New Vulnerabilities
- **Priority**: Critical
- **Why**: Regression detection is key use case. Must catch new issues.
- **Steps**:
  1. Run scan and save baseline: `mcp-sentinel scan ./test-project --save-baseline`
  2. Add new vulnerability to code
  3. Run scan with baseline: `mcp-sentinel scan ./test-project --baseline`
  4. Verify NEW vulnerability detected
- **Expected Result**:
  - Output shows "NEW" badge for new vulnerability
  - Exit code 1 (new issue found)
  - Baseline stats displayed
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-BASELINE-002: Detect Fixed Vulnerabilities
- **Priority**: High
- **Why**: Show progress (motivate developers).
- **Steps**:
  1. Scan project with vulnerabilities, save baseline
  2. Fix one vulnerability
  3. Scan with baseline comparison
  4. Verify FIXED status shown
- **Expected Result**:
  - Output shows "FIXED" badge
  - Summary shows "1 fixed"
  - Exit code 0 (no new issues)
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

### Suppression Integration

#### TC-SUPPRESSION-001: Apply Suppression Rules
- **Priority**: High
- **Why**: Suppression reduces noise from false positives.
- **Steps**:
  1. Create .mcp-sentinel-ignore.yaml with suppression rule
  2. Run scan
  3. Verify suppressed vulnerability not in output
  4. Check suppression audit log
- **Expected Result**:
  - Suppressed vulnerability not shown
  - Audit log contains suppression entry
  - Output shows "2 suppressions applied"
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-SUPPRESSION-002: Expired Suppression Not Applied
- **Priority**: Medium
- **Why**: Expired rules should not apply (temporary becomes permanent).
- **Steps**:
  1. Create suppression with past expiration date
  2. Run scan
  3. Verify vulnerability is NOT suppressed
- **Expected Result**:
  - Vulnerability appears in output
  - Warning: "1 expired suppression ignored"
  - Audit log notes expired rule
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

### Git Integration

#### TC-GIT-001: Diff-Aware Scanning
- **Priority**: Medium
- **Why**: 10-100x performance improvement for incremental scans.
- **Steps**:
  1. Initialize Git repo, commit all files
  2. Modify 1 file out of 100
  3. Run: `mcp-sentinel scan . --diff`
  4. Verify only changed file scanned
- **Expected Result**:
  - Only 1 file scanned (not 100)
  - Scan completes in <1 second
  - Output shows "Scanning 1 changed file"
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

## Performance Test Cases

### Scan Performance

#### TC-PERF-001: Quick Scan Performance (1000 Files)
- **Priority**: High
- **Why**: Quick scans must be fast (<10 seconds).
- **Steps**:
  1. Create project with 1000 Python files (typical size)
  2. Run: `time mcp-sentinel scan ./large-project --mode quick`
  3. Measure scan duration
- **Expected Result**:
  - Scan completes in <10 seconds
  - Throughput: 100+ files/second
  - Memory usage: <500MB
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-PERF-002: Deep Scan Performance with Cache (1000 Files)
- **Priority**: High
- **Why**: Cached deep scans should be as fast as quick scans.
- **Steps**:
  1. Run deep scan once (cache cold): `mcp-sentinel scan ./large-project --mode deep`
  2. Note duration (e.g., 5 minutes)
  3. Run again (cache hot)
  4. Measure duration
- **Expected Result**:
  - First scan: 3-10 minutes (depends on LLM)
  - Second scan: <15 seconds (100x faster)
  - Cache hit rate: >95%
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-PERF-003: Memory Usage Under Load
- **Priority**: Medium
- **Why**: Must work on constrained environments (CI containers with 2GB RAM).
- **Steps**:
  1. Run scan with 10,000 files
  2. Monitor memory: `htop` or `/usr/bin/time -v`
  3. Check peak memory usage
- **Expected Result**:
  - Peak memory: <1GB
  - No memory leaks (constant usage)
  - No OOM errors
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

### API Performance

#### TC-PERF-004: OpenAI API Call Latency
- **Priority**: Medium
- **Why**: API latency impacts deep scan speed. Must be reasonable.
- **Steps**:
  1. Run deep scan with OpenAI
  2. Enable verbose logging
  3. Measure average API call latency
- **Expected Result**:
  - Average latency: 500-2000ms
  - No timeouts (all requests succeed)
  - Rate limiting respected (no 429 errors)
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-PERF-005: Ollama Local Inference Speed
- **Priority**: High
- **Why**: Local LLM is free alternative. Must be reasonably fast.
- **Steps**:
  1. Run deep scan with Ollama
  2. Measure average inference time per file
  3. Check GPU utilization (nvidia-smi)
- **Expected Result**:
  - GPU: 50-200ms per file (depending on model)
  - CPU: 1000-3000ms per file
  - No crashes or hangs
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

## Security Test Cases

### Credential Sanitization

#### TC-SEC-001: API Keys Masked Before Cloud Upload
- **Priority**: Critical
- **Why**: Credential leakage to cloud LLMs is security incident.
- **Steps**:
  1. Create file with hardcoded API key: `API_KEY = "sk_live_abc123..."`
  2. Enable network capture: `tcpdump -i any port 443 -w capture.pcap`
  3. Run deep scan with OpenAI
  4. Analyze capture: Verify API key was masked in request body
- **Expected Result**:
  - Request body contains `"API_KEY = [REDACTED]"`
  - Actual API key NOT in network traffic
  - Vulnerability still detected (pattern preserved)
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-SEC-002: Passwords Masked
- **Priority**: Critical
- **Why**: Password leakage is unacceptable.
- **Steps**:
  1. Create file with password: `PASSWORD = "mypassword123"`
  2. Run deep scan with cloud LLM
  3. Verify password masked in API request
- **Expected Result**:
  - Password masked as `[REDACTED]`
  - Not present in any network traffic
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-SEC-003: No Credentials in Cache
- **Priority**: High
- **Why**: Cache stored on disk. Credentials in cache = persistent leak.
- **Steps**:
  1. Scan file with API key
  2. Examine cache database: `strings ~/.mcp-sentinel/cache/cache.db`
  3. Verify no credentials in cache
- **Expected Result**:
  - Cache contains masked code only
  - No API keys, passwords, or tokens
  - Full code sanitized before caching
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

### Input Validation

#### TC-SEC-004: Path Traversal Prevention
- **Priority**: High
- **Why**: Path traversal = arbitrary file read (security vulnerability).
- **Steps**:
  1. Try to scan outside project: `mcp-sentinel scan ../../../etc/passwd`
  2. Verify access denied
- **Expected Result**:
  - Error: Path traversal attempt blocked
  - No access to files outside project
  - Exit code 2
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-SEC-005: Command Injection Prevention (Git)
- **Priority**: Critical
- **Why**: Git commands execute shell. Injection = code execution.
- **Steps**:
  1. Create project with malicious filename: `"; rm -rf / #.py"`
  2. Run Git-integrated scan
  3. Verify no command execution
- **Expected Result**:
  - File handled safely
  - No shell command execution
  - Scan completes without errors
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

### Denial of Service

#### TC-SEC-006: Large File Handling
- **Priority**: Medium
- **Why**: Malicious large files could crash scanner (DoS).
- **Steps**:
  1. Create 1GB file
  2. Place in project directory
  3. Run scan
  4. Verify scanner doesn't crash
- **Expected Result**:
  - Large file skipped (with warning)
  - Scan continues for other files
  - No OOM error
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-SEC-007: Binary File Handling
- **Priority**: Medium
- **Why**: Binary files could cause parser crashes.
- **Steps**:
  1. Add binary file (e.g., PNG image) to project
  2. Run scan
  3. Verify no crash
- **Expected Result**:
  - Binary file skipped (not scanned)
  - No panic or crash
  - Other files scanned normally
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

## Usability Test Cases

### Error Messages

#### TC-USABILITY-001: Helpful Error Messages
- **Priority**: High
- **Why**: Good errors save support time. Bad errors frustrate users.
- **Steps**:
  1. Try various invalid inputs:
     - Invalid path: `mcp-sentinel scan /does/not/exist`
     - Invalid flag: `mcp-sentinel scan . --invalid-flag`
     - Missing API key: `mcp-sentinel scan . --mode deep --llm-provider openai`
  2. Verify each error is clear and actionable
- **Expected Result**:
  - Each error explains what went wrong
  - Each error suggests fix (e.g., "Did you mean --llm-provider?")
  - No stack traces (unless --verbose)
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

### Terminal Output

#### TC-USABILITY-002: Colored Output Readability
- **Priority**: Medium
- **Why**: Color coding helps users quickly identify severity.
- **Steps**:
  1. Run scan with vulnerabilities
  2. Verify color coding:
     - Critical: Red
     - High: Orange
     - Medium: Yellow
     - Low: Green
  3. Check colors work in both light and dark terminals
- **Expected Result**:
  - Colors render correctly
  - High contrast (readable)
  - Severity instantly recognizable
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-USABILITY-003: Progress Indicators
- **Priority**: Medium
- **Why**: Long scans need progress feedback (user knows it's working).
- **Steps**:
  1. Run deep scan on large project
  2. Verify progress indicators displayed
  3. Check progress updates regularly (not frozen)
- **Expected Result**:
  - Progress bar or spinner displayed
  - Updates every 1-2 seconds
  - Shows: "Scanning file 450/1000 (45%)"
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

### CLI Usability

#### TC-USABILITY-004: Help Text Quality
- **Priority**: Medium
- **Why**: --help is primary documentation. Must be clear.
- **Steps**:
  1. Run: `mcp-sentinel --help`
  2. Run: `mcp-sentinel scan --help`
  3. Review for clarity, examples, completeness
- **Expected Result**:
  - All commands documented
  - All flags explained
  - Examples provided
  - Formatting clean (not cluttered)
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-USABILITY-005: Tab Completion
- **Priority**: Low
- **Why**: Tab completion improves UX (faster, fewer typos).
- **Steps**:
  1. Install shell completions (if implemented)
  2. Try tab-completing commands and flags
  3. Verify completions are correct
- **Expected Result**:
  - Commands auto-complete
  - Flags auto-complete
  - File paths auto-complete
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

## Compatibility Test Cases

### Platform Compatibility

#### TC-COMPAT-001: Linux (Ubuntu 22.04)
- **Priority**: Critical
- **Why**: Primary target platform (CI/CD, servers).
- **Steps**:
  1. Run all functional tests on Ubuntu 22.04
  2. Verify binary works
  3. Check all features functional
- **Expected Result**:
  - All tests pass
  - No platform-specific errors
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-COMPAT-002: macOS (M1/M2)
- **Priority**: High
- **Why**: Popular development platform.
- **Steps**:
  1. Build for aarch64-apple-darwin
  2. Run functional tests on macOS
  3. Test Ollama integration (Metal GPU)
- **Expected Result**:
  - Binary runs natively (no Rosetta)
  - Ollama uses Metal acceleration
  - All features work
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-COMPAT-003: Windows 10/11
- **Priority**: Medium
- **Why**: Windows users exist (though less common for backend dev).
- **Steps**:
  1. Build for x86_64-pc-windows-msvc
  2. Run functional tests on Windows
  3. Check path handling (backslashes)
- **Expected Result**:
  - Binary runs on Windows
  - Path handling correct (\ vs /)
  - All features work
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

### Environment Compatibility

#### TC-COMPAT-004: GitHub Actions
- **Priority**: Critical
- **Why**: Primary CI/CD target.
- **Steps**:
  1. Create GitHub Actions workflow
  2. Run scan in CI
  3. Upload SARIF to GitHub Code Scanning
- **Expected Result**:
  - Scan runs in CI (<5 minutes)
  - SARIF upload succeeds
  - Findings appear in GitHub Security tab
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-COMPAT-005: GitLab CI
- **Priority**: High
- **Why**: Common CI platform.
- **Steps**:
  1. Create .gitlab-ci.yml
  2. Run scan in GitLab CI
  3. Generate code quality report
- **Expected Result**:
  - Scan runs successfully
  - Report generated
  - MR shows code quality changes
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-COMPAT-006: Docker Container
- **Priority**: High
- **Why**: Common deployment (CI, servers).
- **Steps**:
  1. Run in Docker container with 2GB RAM
  2. Verify all features work
  3. Check resource usage
- **Expected Result**:
  - Runs in constrained environment
  - Memory usage <1.5GB
  - No permission errors
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

## Regression Test Cases

### Known Issues (From Previous Releases)

#### TC-REGRESSION-001: Cache Corruption Bug
- **Priority**: Critical
- **Why**: Previous version had cache corruption. Must not regress.
- **Steps**:
  1. Run scan 10 times in a row (exercise cache)
  2. Verify no corruption errors
  3. Verify results consistent
- **Expected Result**:
  - No "Cache corrupted" errors
  - Results identical across runs
  - Cache size reasonable (<100MB)
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-REGRESSION-002: Rate Limit Handling
- **Priority**: High
- **Why**: Previous version didn't handle 429 errors correctly.
- **Steps**:
  1. Run deep scan with OpenAI (large project)
  2. Intentionally trigger rate limit (scan 100+ files)
  3. Verify exponential backoff works
- **Expected Result**:
  - 429 errors handled gracefully
  - Retries with backoff (1s, 2s, 4s, 8s)
  - Eventually succeeds (no permanent failure)
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

#### TC-REGRESSION-003: Git Repo Detection
- **Priority**: Medium
- **Why**: Previous version failed on submodules.
- **Steps**:
  1. Create project with Git submodule
  2. Run scan with --diff flag
  3. Verify both main repo and submodule scanned
- **Expected Result**:
  - Submodule detected
  - Files in submodule scanned
  - No errors about "not a Git repo"
- **Actual Result**: _____
- **Status**: ⬜ Pass / ⬜ Fail / ⬜ Blocked

---

## Release Readiness Criteria

### Mandatory (Must Pass Before Release)

- [ ] All **Critical** priority test cases pass
- [ ] All **High** priority test cases pass
- [ ] Code coverage ≥80%
- [ ] No known security vulnerabilities
- [ ] Documentation updated (README, CHANGELOG, CLI help)
- [ ] Binary builds successfully for all target platforms
- [ ] GitHub Actions CI passes
- [ ] No clippy warnings
- [ ] No failing unit tests

### Recommended (Should Pass)

- [ ] All **Medium** priority test cases pass
- [ ] Performance benchmarks meet targets
- [ ] Usability testing feedback positive
- [ ] No open critical/high bugs
- [ ] SARIF output validates against schema

### Optional (Nice to Have)

- [ ] All **Low** priority test cases pass
- [ ] Tab completion works
- [ ] All platform-specific tests pass

---

## Test Execution Log

### Release: v2.0.0
**Test Date**: _____________
**Tester**: _____________
**Environment**: _____________

### Summary

| Category            | Total | Pass | Fail | Blocked |
|---------------------|-------|------|------|---------|
| Functional          | 28    |      |      |         |
| Integration         | 8     |      |      |         |
| Performance         | 5     |      |      |         |
| Security            | 7     |      |      |         |
| Usability           | 5     |      |      |         |
| Compatibility       | 6     |      |      |         |
| Regression          | 3     |      |      |         |
| **Total**           | **62**|      |      |         |

### Critical Issues Found

1. **Issue**: _____________
   **Test Case**: _____________
   **Severity**: _____________
   **Status**: _____________

2. **Issue**: _____________
   **Test Case**: _____________
   **Severity**: _____________
   **Status**: _____________

### Sign-Off

**QA Lead**: _____________
**Date**: _____________
**Release Approved**: ⬜ Yes / ⬜ No (Reason: _____________)

---

## Summary

This QA checklist ensures MCP Sentinel meets quality standards before release. Key areas:

1. **Functional**: Core features work correctly
2. **Integration**: Components work together
3. **Performance**: Meets speed/memory requirements
4. **Security**: No vulnerabilities, credentials protected
5. **Usability**: Intuitive, helpful errors, good UX
6. **Compatibility**: Works on target platforms/environments
7. **Regression**: Previous bugs don't return

**Test Coverage**: 62 test cases across 7 categories.

**Critical Path**:
- Scan command (quick and deep modes)
- SARIF output for CI/CD
- Exit codes for pipeline integration
- Credential sanitization (security)
- Cache performance (100x speedup)

**Release Criteria**:
- All Critical tests pass
- All High tests pass
- 80%+ code coverage
- Documentation complete

For more information, see:
- [Test Strategy](./TEST_STRATEGY.md)
- [Architecture Documentation](./ARCHITECTURE.md)
- [CLI Reference](./CLI_REFERENCE.md)
