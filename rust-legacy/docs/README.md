# MCP Sentinel - Documentation Index

**Version**: 2.0.0
**Last Updated**: 2025-10-26

Welcome to the MCP Sentinel documentation. This index provides a comprehensive guide to all available documentation.

---

## 📚 Documentation Overview

MCP Sentinel is a comprehensive security scanner for Model Context Protocol (MCP) servers, combining static analysis, AI-powered detection, and runtime monitoring.

**What Makes This Documentation Special:**
- Every design decision is explained with the **"why"**
- Complete architecture diagrams (system, network, data flow)
- Detailed test strategy with documented scope and rationale
- Comprehensive QA checklist (62 test cases)
- CLI reference with real-world examples

---

## 🗂️ Documentation Structure

### Core Documentation

#### [ARCHITECTURE.md](./ARCHITECTURE.md) (~1000 lines)
**Purpose**: Complete system architecture with design rationale

**Contents**:
- System Overview (technology stack, design principles)
- High-Level Architecture (7-layer system design)
- Component Architecture (CLI, engines, providers, storage)
- Data Flow Diagrams (full scan flow, AI provider communication)
- Network Architecture (provider communication patterns)
- Security Architecture (threat model with mitigations)
- Performance Architecture (caching, concurrency, memory profiles)
- Deployment Architecture (local dev, CI/CD)
- Design Rationale (8 key decisions with "why" explanations)

**Key Sections**:
```
┌──────────────────────────────────────────────┐
│           MCP SENTINEL LAYERS                │
├──────────────────────────────────────────────┤
│ 1. CLI Interface    │ User interaction       │
│ 2. Static Analysis  │ Pattern matching       │
│ 3. AI Analysis      │ LLM-powered detection  │
│ 4. Provider Layer   │ OpenAI, Anthropic, etc │
│ 5. Storage Layer    │ Cache, baseline, DB    │
│ 6. Integration      │ Git, config, suppression│
│ 7. Output Layer     │ Terminal, JSON, SARIF  │
└──────────────────────────────────────────────┘
```

**When to Read**: Understanding system design, contributing, architectural decisions

---

#### [CLI_REFERENCE.md](./CLI_REFERENCE.md) (~500 lines)
**Purpose**: Complete command-line interface documentation

**Contents**:
- Installation instructions
- Global flags (--verbose, --no-color)
- All commands with examples:
  - `scan` - Vulnerability scanning (quick/deep modes)
  - `proxy` - Runtime monitoring
  - `monitor` - Continuous scanning
  - `audit` - Comprehensive analysis
  - `init` - Configuration initialization
  - `whitelist` - Manage trusted items
  - `rules` - Manage guardrails
- Exit codes (0, 1, 2, 3)
- Environment variables
- Configuration files (YAML format)
- Workflow examples (dev, CI/CD, audit)
- Troubleshooting guide

**Example Usage**:
```bash
# Quick scan (default)
mcp-sentinel scan ./server

# Deep scan with AI (local)
mcp-sentinel scan ./server --mode deep --llm-provider ollama

# CI/CD with SARIF output
mcp-sentinel scan . --fail-on medium --output sarif --output-file results.sarif
```

**When to Read**: Using MCP Sentinel CLI, CI/CD integration, workflow setup

---

#### [NETWORK_DIAGRAMS.md](./NETWORK_DIAGRAMS.md) (~800 lines)
**Purpose**: Network architecture, data flows, and communication patterns

**Contents**:
- Network Topology (scan modes: quick, deep cloud, deep local)
- Communication Patterns (HTTP/2, TLS 1.3, request/response flows)
- LLM Provider Integration:
  - OpenAI architecture (Cloudflare CDN, rate limits)
  - Anthropic architecture (AWS CloudFront, Trainium chips)
  - Google Gemini architecture (TPU v5 Pods)
  - Local Ollama architecture (GPU/CPU inference)
- Proxy Architecture (transparent MCP proxy flow)
- Security Boundaries (3 security zones: local, cloud, internet)
- Data Flow Diagrams (full scan with AI analysis, 11 steps)
- Performance & Latency (timing breakdowns, throughput analysis)
- Error Handling & Retries (exponential backoff, fallback strategies)
- Rate Limiting & Backpressure (semaphore-based, provider-specific)

**Network Flow Example**:
```
Quick Mode (Local Only):
┌─────────────┐
│   Scanner   │ ──> Local File System
└─────────────┘     (No network)

Deep Mode (Cloud):
┌─────────────┐         ┌──────────────┐
│   Scanner   │ ──TLS──>│  OpenAI API  │
└─────────────┘  1.3   └──────────────┘
    (Code sanitized)     (800ms latency)
```

**When to Read**: Understanding network flows, security boundaries, performance characteristics

---

#### [TEST_STRATEGY.md](./TEST_STRATEGY.md) (~900 lines)
**Purpose**: Complete testing strategy with documented rationale

**Contents**:
- Testing Philosophy (6 core principles)
- Test Pyramid (70% unit, 20% integration, 10% E2E)
- Test Types:
  - Unit Tests (43 existing, fast isolated tests)
  - Integration Tests (24 planned, component interactions)
  - E2E Tests (5 planned, full workflows)
  - Property-Based Tests (10 planned, edge cases)
  - Performance Tests (13 planned, benchmarks)
- Test Coverage by Component (15 modules documented):
  - Suppression System (15 tests)
  - Git Integration (3 tests)
  - Storage Systems (9 tests)
  - AI Analysis Engine (3 tests)
  - LLM Providers (8 tests)
- Test Infrastructure (mocks, fixtures, utilities)
- Running Tests (local and CI/CD)
- Writing New Tests (templates, conventions, documentation requirements)
- Performance Benchmarking

**Test Documentation Example**:
```rust
/// Test that expired suppressions are not applied.
///
/// Why: Expired suppressions represent temporary overrides.
/// If expired rules continue to apply, temporary becomes
/// permanent, defeating the purpose.
///
/// Scope: Tests Suppression::is_expired() with past/future dates.
///
/// Success criteria:
/// - Past date → is_expired() returns true
/// - Future date → is_expired() returns false
#[test]
fn test_suppression_expiration() { ... }
```

**When to Read**: Writing tests, understanding test coverage, test strategy decisions

---

#### [QA_CHECKLIST.md](./QA_CHECKLIST.md) (~700 lines)
**Purpose**: Comprehensive quality assurance checklist for pre-release validation

**Contents**:
- Pre-Release Checklist:
  - Code Quality (tests, coverage, clippy, format)
  - Documentation (README, CHANGELOG, API docs)
  - Build & Packaging (clean build, dependencies)
- Functional Test Cases (28 tests):
  - Scan command (10 test cases)
  - Init, Proxy, Monitor, Audit commands
  - Whitelist management
- Integration Test Cases (8 tests):
  - Cache integration (hit performance, invalidation)
  - Baseline integration (NEW/FIXED detection)
  - Suppression integration (rules, expiration)
  - Git integration (diff-aware scanning)
- Performance Test Cases (5 tests):
  - Scan throughput (1000 files target)
  - Cache performance (<1ms lookup)
  - Memory usage under load
  - API latency
- Security Test Cases (7 tests):
  - Credential sanitization (API keys, passwords)
  - Input validation (path traversal, command injection)
  - Denial of service (large files, binary files)
- Usability Test Cases (5 tests):
  - Error messages, colored output, progress indicators
- Compatibility Test Cases (6 tests):
  - Linux, macOS, Windows
  - GitHub Actions, GitLab CI, Docker
- Regression Test Cases (3 tests)
- Release Readiness Criteria

**Test Case Example**:
```
TC-SCAN-001: Basic Quick Scan
Priority: Critical
Why: Most common use case. Must work correctly.

Steps:
1. Create test project with sample MCP server code
2. Run: mcp-sentinel scan ./test-project
3. Verify scan completes without errors

Expected Result:
- Scan completes in <10 seconds
- Terminal shows vulnerability summary
- Exit code 0

Status: [ ] Pass / [ ] Fail / [ ] Blocked
```

**When to Read**: Pre-release testing, release validation, QA processes

---

#### [RELEASE_PROCESS.md](./RELEASE_PROCESS.md) (~1,000 lines)
**Purpose**: Complete release process documentation with performance delta tracking

**Contents**:
- Release Workflow Overview (8-phase process: dev → QA → PR → merge → tag → release → verify → announce)
- Pre-Release Requirements:
  - Quality assurance checklist
  - Documentation updates
  - Code sanitization & cleanup guide
- Performance Delta Documentation:
  - Metrics to track (scan time, throughput, memory, binary size)
  - Benchmarking process
  - Performance comparison table format
  - AI provider cost tracking
- Creating a Release:
  - Git tagging workflow
  - Annotated tag requirements
  - GitHub Release creation
  - Release description template
- Post-Release Verification:
  - Installation testing
  - Documentation link updates
  - Announcement protocol
- Release Checklist Template (copy-paste for each release)
- Automation Scripts (benchmarking, release creation, comparison)
- Version Numbering Guidelines (semantic versioning)
- Release Cadence Recommendations
- Rollback Procedures

**Release Tag Message Template**:
```
vX.Y.Z: Feature Name

Major Features:
- Feature 1 with "why" explanation
- Feature 2 with "why" explanation

Performance: X% faster, Y% less memory
Documentation: X lines added
Tests: X new tests

Breaking Changes: None/List
```

**Why This Matters**: Standardized release process ensures:
- Consistent quality across releases
- Performance tracking shows continuous improvement
- Users understand what changed and why to upgrade
- Contributors can reproduce the process

**When to Read**: Before creating any release, updating release automation, understanding versioning

---

## 📖 Reading Guide

### For Users

**Getting Started**:
1. Start with [CLI_REFERENCE.md](./CLI_REFERENCE.md) - Installation and basic usage
2. Review workflow examples for your use case (dev, CI/CD, audit)
3. Check troubleshooting section if you encounter issues

**Common Tasks**:
- **Run a scan**: CLI_REFERENCE.md → Scan Command
- **Integrate with CI/CD**: CLI_REFERENCE.md → CI/CD Integration
- **Configure settings**: CLI_REFERENCE.md → Configuration Files
- **Understand exit codes**: CLI_REFERENCE.md → Exit Codes

---

### For Contributors

**Understanding the Codebase**:
1. Read [ARCHITECTURE.md](./ARCHITECTURE.md) - System design and rationale
2. Read [NETWORK_DIAGRAMS.md](./NETWORK_DIAGRAMS.md) - Communication patterns
3. Review [TEST_STRATEGY.md](./TEST_STRATEGY.md) - Testing approach

**Adding Features**:
1. Understand existing architecture (ARCHITECTURE.md)
2. Follow testing strategy (TEST_STRATEGY.md)
3. Add tests following templates (TEST_STRATEGY.md → Writing New Tests)
4. Update documentation (all relevant docs)

**Writing Tests**:
1. Read [TEST_STRATEGY.md](./TEST_STRATEGY.md) → Writing New Tests
2. Follow template (Arrange/Act/Assert)
3. Document "why" (user requirement)
4. Run QA checklist before PR

---

### For QA/Testers

**Pre-Release Testing**:
1. Follow [QA_CHECKLIST.md](./QA_CHECKLIST.md) completely
2. Execute all Critical and High priority test cases
3. Document results in Test Execution Log
4. Report issues with test case IDs

**Test Automation**:
1. Reference [TEST_STRATEGY.md](./TEST_STRATEGY.md) for test types
2. Use test case IDs from [QA_CHECKLIST.md](./QA_CHECKLIST.md)
3. Follow CI/CD integration guide

---

### For Security Auditors

**Security Review**:
1. [ARCHITECTURE.md](./ARCHITECTURE.md) → Security Architecture
   - Threat model with 5 threats and mitigations
   - Security boundaries (3 zones)
   - Data sanitization pipeline
2. [NETWORK_DIAGRAMS.md](./NETWORK_DIAGRAMS.md) → Security Boundaries
   - Data flow security (encryption, validation)
   - Credential sanitization
3. [QA_CHECKLIST.md](./QA_CHECKLIST.md) → Security Test Cases
   - 7 security-focused test cases
   - Credential protection verification

---

## 🏗️ Architecture Quick Reference

### System Layers

```
CLI Interface → Static Analysis → AI Analysis → Providers → Storage → Integration → Output
```

### Key Components

| Component            | Purpose                          | Key Files                  |
|----------------------|----------------------------------|----------------------------|
| CLI                  | User interface                   | src/cli/                   |
| Scanner              | Orchestrate scanning             | src/scanner.rs             |
| Detectors            | Pattern matching                 | src/detectors/             |
| AI Engine            | LLM-powered analysis             | src/engines/ai_analysis.rs |
| Providers            | LLM API integrations             | src/providers/             |
| Cache                | Performance optimization         | src/storage/cache.rs       |
| Baseline             | Regression detection             | src/storage/baseline.rs    |
| Suppression          | False positive management        | src/suppression/           |
| Git Integration      | Diff-aware scanning              | src/utils/git.rs           |

### Data Flow (Quick Scan)

```
1. User runs CLI
2. Scanner discovers files
3. Static analysis (regex, AST)
4. Aggregate results
5. Output formatter (terminal/JSON/SARIF)
```

### Data Flow (Deep Scan)

```
1-3. Same as quick scan
4. For each file:
   a. Check cache (SHA-256 hash)
   b. If miss: Sanitize code
   c. Call LLM provider (rate limited)
   d. Parse AI findings
   e. Store in cache
5. Merge static + AI results
6. Apply suppressions
7. Output formatter
```

---

## 🔧 Common Workflows

### Development Workflow

```bash
# 1. Quick feedback during coding
mcp-sentinel scan . --verbose

# 2. Watch for changes
mcp-sentinel monitor . --watch --alert-on medium

# 3. Pre-commit check
mcp-sentinel scan . --fail-on medium
```

### CI/CD Workflow

```bash
# GitHub Actions
mcp-sentinel scan . \
  --mode deep \
  --llm-provider ollama \
  --fail-on high \
  --output sarif \
  --output-file results.sarif
```

### Security Audit Workflow

```bash
# Comprehensive analysis
mcp-sentinel audit . \
  --comprehensive \
  --llm-provider openai \
  --llm-model gpt-4o \
  --output json \
  --output-file audit-report.json
```

---

## 📊 Key Metrics

### Performance Targets

| Metric                  | Target        | Why                             |
|-------------------------|---------------|---------------------------------|
| Quick scan throughput   | 1000 files/s  | Dev loop (instant feedback)     |
| Cache lookup            | <1ms          | Checked per file (must be fast) |
| Cache hit speedup       | 100x          | Justify caching complexity      |
| AI provider timeout     | <30s          | Prevent hanging                 |
| Baseline comparison     | <100ms        | Low overhead per scan           |

### Test Coverage Goals

| Module Type        | Target | Why                                 |
|--------------------|--------|-------------------------------------|
| Critical path      | 100%   | Security, data integrity            |
| Core modules       | 90%+   | Main functionality                  |
| Utilities          | 80%+   | Support code                        |

---

## 🐛 Troubleshooting

### Common Issues

| Issue                         | Solution                                | Doc Reference            |
|-------------------------------|-----------------------------------------|--------------------------|
| "Target path does not exist"  | Check path is correct                   | CLI_REFERENCE.md         |
| "Missing API key"             | Set MCP_SENTINEL_API_KEY env var        | CLI_REFERENCE.md → Env   |
| "Ollama connection refused"   | Start Ollama: `ollama serve`            | CLI_REFERENCE.md         |
| Scan too slow                 | Use quick mode or local LLM             | CLI_REFERENCE.md → Perf  |
| False positives               | Use whitelist or suppression            | CLI_REFERENCE.md         |

---

## 📝 Contributing

### Before Contributing

1. Read [ARCHITECTURE.md](./ARCHITECTURE.md) - Understand system design
2. Read [TEST_STRATEGY.md](./TEST_STRATEGY.md) - Testing requirements
3. Review existing code patterns

### Contribution Checklist

- [ ] Code follows existing patterns (see ARCHITECTURE.md)
- [ ] Tests added (see TEST_STRATEGY.md templates)
- [ ] All tests pass (`cargo test`)
- [ ] No clippy warnings (`cargo clippy`)
- [ ] Code formatted (`cargo fmt`)
- [ ] Documentation updated (if public API changed)
- [ ] CHANGELOG.md updated (if user-facing change)

---

## 🔗 External Resources

- **GitHub Repository**: https://github.com/mcpsentinel/mcp-sentinel
- **Issue Tracker**: https://github.com/mcpsentinel/mcp-sentinel/issues
- **Discussions**: https://github.com/mcpsentinel/mcp-sentinel/discussions
- **Changelog**: ../CHANGELOG.md
- **Contributing Guide**: ../CONTRIBUTING.md

---

## 📅 Version History

### v2.0.0 (Current)
- Complete architecture documentation
- Comprehensive CLI reference
- Network diagrams and data flows
- Test strategy with documented rationale
- QA checklist with 62 test cases
- **Key Addition**: "Why" documentation for all design decisions (user requirement)

### v1.6.0 (Phase 1)
- SARIF output support
- Configuration files
- MCP config scanning
- Progress indicators
- Enhanced exit codes

---

## 📄 Documentation Statistics

| Document               | Lines | Purpose                                    |
|------------------------|-------|--------------------------------------------|
| ARCHITECTURE.md        | ~1000 | System design and rationale                |
| CLI_REFERENCE.md       | ~500  | Complete command reference                 |
| NETWORK_DIAGRAMS.md    | ~800  | Network flows and communication            |
| TEST_STRATEGY.md       | ~900  | Testing approach and documentation         |
| QA_CHECKLIST.md        | ~700  | Pre-release validation (62 test cases)     |
| RELEASE_PROCESS.md     | ~1000 | Release workflow and performance tracking  |
| **Total**              | **~4900** | **Comprehensive documentation package**|

---

## 🎯 Documentation Principles

1. **"Why" First**: Every decision explained with rationale (user requirement)
2. **Examples Everywhere**: Real-world usage examples throughout
3. **Complete Context**: No assumptions about reader knowledge
4. **Visual Aids**: ASCII diagrams for architecture, data flows, networks
5. **Actionable**: Clear steps, commands, and solutions
6. **Traceable**: Cross-references between documents
7. **Maintainable**: Version tracked, last updated dates

---

## 🙏 Acknowledgments

This documentation was created to meet the specific requirement:
> "Make sure all tests are well documented along with scope and the reasons behind why for everything we do. I am assuming architecture and network diagrams are also well documented along with qa and unit test cases and cli command syntax documentation."

Every document in this package explicitly addresses the **"why"** behind design decisions, test cases, and architectural choices.

---

## 📧 Support

- **Questions**: Open a GitHub Discussion
- **Bug Reports**: File a GitHub Issue with QA checklist test case ID
- **Feature Requests**: Open a GitHub Issue with use case and rationale
- **Security Issues**: Email security@mcpsentinel.com (do not file public issue)

---

**Last Updated**: 2025-10-26
**Documentation Version**: 2.0.0
**MCP Sentinel Version**: 2.0.0
