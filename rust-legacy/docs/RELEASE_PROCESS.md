# Release Process Documentation

**Version**: 1.0.0
**Last Updated**: 2025-10-26

This document defines the standard release process for MCP Sentinel, ensuring consistent, high-quality releases with comprehensive documentation and performance tracking.

---

## Table of Contents

1. [Release Workflow Overview](#release-workflow-overview)
2. [Pre-Release Requirements](#pre-release-requirements)
3. [Performance Delta Documentation](#performance-delta-documentation)
4. [Code Quality & Sanitization](#code-quality--sanitization)
5. [Creating a Release](#creating-a-release)
6. [Post-Release Verification](#post-release-verification)
7. [Release Checklist Template](#release-checklist-template)

---

## Release Workflow Overview

### Standard Release Lifecycle

```
┌──────────────────────────────────────────────────────────────┐
│                  RELEASE WORKFLOW                             │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  1. Development Phase                                         │
│     └─> Feature implementation on feature branch             │
│                                                               │
│  2. Pre-Release Quality Assurance                             │
│     ├─> Run QA checklist (docs/QA_CHECKLIST.md)              │
│     ├─> Code sanitization & cleanup                          │
│     ├─> Performance benchmarking                             │
│     └─> Documentation updates                                │
│                                                               │
│  3. Performance Delta Documentation                           │
│     ├─> Compare with previous release                        │
│     ├─> Document improvements/regressions                    │
│     └─> Update CHANGELOG.md with metrics                     │
│                                                               │
│  4. Create Pull Request                                       │
│     ├─> Comprehensive PR description                         │
│     ├─> Include performance comparison                       │
│     └─> Link to related issues                               │
│                                                               │
│  5. Merge to Main                                             │
│     └─> Squash/merge/rebase based on project policy          │
│                                                               │
│  6. Create Release Tag                                        │
│     ├─> Semantic version (vX.Y.Z)                            │
│     ├─> Annotated git tag                                    │
│     └─> Comprehensive tag message                            │
│                                                               │
│  7. Create GitHub Release                                     │
│     ├─> Attach binaries (if applicable)                      │
│     ├─> Detailed release notes                               │
│     ├─> Performance comparison table                         │
│     └─> Migration guide (for breaking changes)               │
│                                                               │
│  8. Post-Release Verification                                 │
│     ├─> Verify release appears on GitHub                     │
│     ├─> Test installation from release                       │
│     └─> Update documentation links                           │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### Release Types

| Version Change | Type | Description | Example |
|----------------|------|-------------|---------|
| X.0.0 | **Major** | Breaking changes, major features | 1.0.0 → 2.0.0 |
| 0.Y.0 | **Minor** | New features, no breaking changes | 1.5.0 → 1.6.0 |
| 0.0.Z | **Patch** | Bug fixes, minor improvements | 1.5.1 → 1.5.2 |

**Why Semantic Versioning**: Allows users to understand impact before upgrading. Major = "read migration guide", Minor = "new features available", Patch = "safe to upgrade immediately".

---

## Pre-Release Requirements

### 1. Quality Assurance Checklist

**Before any release, complete ALL items in [QA_CHECKLIST.md](./QA_CHECKLIST.md)**

Critical sections to complete:
- ✅ All tests pass (`cargo test`)
- ✅ No clippy warnings (`cargo clippy -- -D warnings`)
- ✅ Code formatted (`cargo fmt --check`)
- ✅ Documentation builds (`cargo doc --no-deps`)
- ✅ Clean build from scratch (`cargo clean && cargo build --release`)
- ✅ Functional tests (minimum: Critical + High priority)
- ✅ Performance benchmarks (baseline vs. current)

**Why**: Ensures release quality and prevents shipping broken code.

### 2. Documentation Updates

**Required documentation updates before release:**

#### Update CHANGELOG.md
- Add new version section with date
- Document all changes (Added/Changed/Deprecated/Removed/Fixed/Security)
- Include performance comparison table (see [Performance Delta Documentation](#performance-delta-documentation))
- Add migration guide for breaking changes

#### Update Version Numbers
- `Cargo.toml` → `version` field
- `src/main.rs` or lib.rs → `const VERSION: &str`
- `README.md` → version badges (if applicable)
- `docs/README.md` → version number

#### Update README.md (if needed)
- New features documentation
- Updated installation instructions
- New CLI examples
- Performance metrics

**Why**: Users need accurate documentation for the version they're using.

### 3. Code Sanitization & Cleanup

**Run the code sanitization process:**

```bash
# 1. Remove dead code
cargo +nightly udeps  # Finds unused dependencies
cargo machete         # Alternative: finds unused dependencies

# 2. Fix clippy warnings
cargo clippy --fix --allow-dirty --allow-staged

# 3. Format code
cargo fmt

# 4. Check for common issues
cargo audit           # Security vulnerabilities
cargo outdated        # Outdated dependencies (review before updating)

# 5. Manual cleanup
# - Remove commented-out code blocks
# - Remove debug print statements
# - Remove unused imports
# - Remove TODOs that are completed
# - Consolidate duplicate code
```

**Code Quality Standards:**

1. **No Dead Code**: Remove unused functions, structs, modules
2. **No Debug Code**: Remove debug print statements, temporary hacks
3. **No Commented Code**: Remove large blocks of commented-out code
4. **Consistent Naming**: Follow Rust naming conventions
5. **Clear Documentation**: All public items have doc comments
6. **Error Handling**: No unwrap() in production paths
7. **Security**: No hardcoded credentials, sanitize user input

**Why**: Clean codebase is easier to maintain, debug, and onboard new contributors.

---

## Performance Delta Documentation

### What is Performance Delta

Performance delta is the **change in performance metrics between releases**. This helps users understand if upgrading will improve or impact performance.

### Required Metrics to Track

For each release, document these metrics compared to previous release:

#### 1. Scan Performance

```bash
# Benchmark command
time cargo run --release -- scan ./test-corpus

# Track:
# - Total scan time (seconds)
# - Files per second throughput
# - Memory usage (MB)
# - Binary size (MB)
```

**Metrics Table Format** (for CHANGELOG.md):

```markdown
| Metric | Previous | Current | Delta | Notes |
|--------|----------|---------|-------|-------|
| Scan Time (1000 files) | 12.5s | 8.2s | -34% ⬆️ | Git integration optimization |
| Throughput | 80 files/s | 122 files/s | +52% ⬆️ | Parallel scanning improved |
| Memory Usage | 145 MB | 98 MB | -32% ⬆️ | Cache compression added |
| Binary Size | 18.2 MB | 19.1 MB | +5% ⬇️ | New dependencies added |
| Cache Hit Speed | N/A | <1ms | NEW ✨ | New feature in v2.0.0 |
```

**Legend:**
- ⬆️ = Improvement (faster, smaller, less)
- ⬇️ = Regression (slower, larger, more)
- ✨ = New metric (new feature)

#### 2. AI Analysis Performance (if applicable)

```bash
# Benchmark deep scan with AI
time cargo run --release -- scan ./test-corpus --mode deep --llm-provider ollama

# Track:
# - AI analysis time per file
# - API call latency
# - Cache hit rate
# - Total cost (for cloud providers)
```

#### 3. Build Performance

```bash
# Track compile times
time cargo build --release

# Metrics:
# - Clean build time
# - Incremental build time
# - Number of dependencies
```

### Creating Performance Comparison

**Step 1: Baseline the Previous Release**

```bash
# Checkout previous release
git checkout v1.6.0

# Build release binary
cargo build --release

# Run benchmarks
./benchmark.sh > baseline-v1.6.0.txt

# Return to main branch
git checkout main
```

**Step 2: Benchmark Current Release**

```bash
# Build current release
cargo build --release

# Run same benchmarks
./benchmark.sh > current-v2.0.0.txt
```

**Step 3: Compare Results**

```bash
# Create comparison table
./tools/compare-benchmarks.sh baseline-v1.6.0.txt current-v2.0.0.txt
```

**Step 4: Add to CHANGELOG.md**

Include the performance comparison table in the release notes under a "Performance Improvements" section.

### Example Performance Section in CHANGELOG

```markdown
## [2.0.0] - 2025-10-26

### Performance Improvements

This release includes significant performance optimizations:

| Metric | v1.6.0 | v2.0.0 | Change | Impact |
|--------|--------|--------|--------|--------|
| Quick Scan (1000 files) | 12.5s | 8.2s | **-34%** ⬆️ | Faster dev feedback |
| Deep Scan w/ AI (100 files) | 145s | 98s | **-32%** ⬆️ | Git diff-aware scanning |
| Memory Peak Usage | 145 MB | 98 MB | **-32%** ⬆️ | Cache compression |
| Cache Lookup | N/A | 0.8ms | **NEW** ✨ | 100x speedup for cached files |
| Binary Size | 18.2 MB | 19.1 MB | +5% ⬇️ | New AI engine dependencies |

**Key Optimizations:**
- Git integration enables scanning only changed files (10-100x improvement for incremental scans)
- Cache system with gzip compression (70-90% space savings)
- Baseline comparison reduces duplicate work
```

**Why This Matters**: Users can make informed decisions about upgrading. Shows project is actively optimizing performance.

---

## Creating a Release

### Step 1: Update Local Repository

```bash
# Ensure you're on main branch with latest changes
cd /path/to/MCP_Scanner
git checkout main
git pull origin main

# Verify clean working directory
git status
# Should show: "nothing to commit, working tree clean"
```

### Step 2: Create Git Tag

**Use annotated tags with comprehensive messages:**

```bash
# Create annotated tag (vX.Y.Z)
git tag -a v2.0.0 -m "$(cat <<'EOF'
Phase 2.0: AI Analysis Engine + Comprehensive Documentation

Major Features:
- AI-powered vulnerability detection (OpenAI, Anthropic, Google Gemini, Ollama)
- Intelligent caching system (SHA-256, gzip, Sled DB)
- Baseline comparison (track NEW/FIXED/CHANGED vulnerabilities)
- Suppression engine (YAML-based false positive management)
- Git integration (diff-aware scanning for 10-100x improvement)

Documentation:
- ARCHITECTURE.md (~1000 lines) - Complete system design with "why" rationale
- CLI_REFERENCE.md (~500 lines) - Full CLI documentation
- NETWORK_DIAGRAMS.md (~800 lines) - Network flows and security boundaries
- TEST_STRATEGY.md (~900 lines) - 43 tests with documented rationale
- QA_CHECKLIST.md (~700 lines) - 62 pre-release test cases

Performance Improvements:
- Quick scan: 34% faster (12.5s → 8.2s for 1000 files)
- Deep scan: 32% faster with git diff-aware scanning
- Memory: 32% reduction (145MB → 98MB)
- Cache: <1ms lookup, 100x speedup for cached files

Statistics:
- +19,008 lines of code and documentation
- 43 unit tests with comprehensive documentation
- 4 AI provider integrations
- 5 major new components

Breaking Changes: None
Migration Guide: N/A (backward compatible)
EOF
)"

# Verify tag was created
git tag -n99 v2.0.0
```

**Tag Message Requirements:**
- **Version and Title**: Clear version number and release name
- **Major Features**: Bullet list of 3-7 key features
- **Documentation**: List of new/updated docs
- **Performance**: Include performance comparison table or key metrics
- **Statistics**: Code/test/feature counts
- **Breaking Changes**: List breaking changes or "None"
- **Migration Guide**: Link or notes, or "N/A"

**Why Annotated Tags**: Contain metadata (author, date, message), are signed, and stored in Git as objects.

### Step 3: Push Tag to GitHub

```bash
# Push tag to remote
git push origin v2.0.0

# Verify tag was pushed
git ls-remote --tags origin | grep v2.0.0
```

### Step 4: Create GitHub Release

**Use GitHub API or Web UI to create release:**

#### Option A: GitHub API (Recommended for Automation)

```bash
# Set variables
GITHUB_TOKEN="your_github_token_here"
REPO_OWNER="beejak"
REPO_NAME="MCP_Scanner"
TAG_NAME="v2.0.0"
RELEASE_NAME="🛡️ MCP Sentinel v2.0.0 - AI Analysis Engine"

# Create release
curl -X POST \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases \
  -d @- <<'EOF'
{
  "tag_name": "v2.0.0",
  "target_commitish": "main",
  "name": "🛡️ MCP Sentinel v2.0.0 - AI Analysis Engine",
  "body": "## Summary\n\n...",
  "draft": false,
  "prerelease": false,
  "make_latest": "true"
}
EOF
```

#### Option B: GitHub Web UI

1. Go to: https://github.com/beejak/MCP_Scanner/releases/new
2. Select tag: `v2.0.0`
3. Release title: "🛡️ MCP Sentinel v2.0.0 - AI Analysis Engine"
4. Description: Use template below
5. Check "Set as the latest release"
6. Click "Publish release"

### GitHub Release Description Template

```markdown
## 🎯 Summary

[Brief 1-3 sentence overview of the release]

Phase 2.0 brings AI-powered vulnerability detection to MCP Sentinel, enabling deep semantic analysis alongside static pattern matching. This release includes comprehensive documentation explaining the "why" behind every design decision.

---

## ✨ Major Features

### 1. AI Analysis Engine
- **Multi-Provider Support**: OpenAI, Anthropic, Google Gemini, Ollama
- **Semantic Detection**: Deep code understanding beyond pattern matching
- **Cost Optimization**: Smart caching to minimize API costs
- **Local Options**: Ollama support for airgapped environments

**Why**: Static analysis alone misses context-aware vulnerabilities. AI detects semantic security issues like logic flaws.

### 2. Intelligent Caching System
- **Content-Addressable**: SHA-256 hashing prevents duplicate analysis
- **Compression**: gzip reduces cache size by 70-90%
- **Persistent Storage**: Sled embedded database
- **Performance**: <1ms cache lookups, 100x speedup for cached files

**Why**: AI analysis is expensive (time & cost). Caching unchanged files saves both.

### 3. Baseline Comparison
- **Track Changes**: NEW, FIXED, CHANGED, UNCHANGED vulnerabilities
- **Trend Analysis**: See security posture improving over time
- **CI/CD Integration**: Focus on new issues, not historical ones

**Why**: Teams need to track progress. Baseline shows if security is improving.

### 4. Suppression System
- **YAML Configuration**: Team-wide false positive management
- **Audit Trail**: JSON Lines logging of all suppressions
- **Expiration**: Time-limited suppressions (prevents permanent ignores)
- **Pattern Matching**: Suppress by file, line, type, or severity

**Why**: False positives reduce tool adoption. Suppressions with audit trail maintain accountability.

### 5. Git Integration
- **Diff-Aware Scanning**: Only scan changed files
- **Performance**: 10-100x faster for incremental scans
- **CI/CD Optimization**: Fast PR checks
- **Flexible**: Support HEAD, branches, commits

**Why**: Large codebases need incremental scanning. Full scans too slow for dev feedback.

---

## 📊 Performance Improvements

| Metric | v1.6.0 | v2.0.0 | Change | Impact |
|--------|--------|--------|--------|--------|
| Quick Scan (1000 files) | 12.5s | 8.2s | **-34%** ⬆️ | Faster dev feedback loop |
| Deep Scan w/ AI (100 files) | 145s | 98s | **-32%** ⬆️ | Git diff optimization |
| Memory Peak | 145 MB | 98 MB | **-32%** ⬆️ | Cache compression |
| Cache Lookup | N/A | 0.8ms | **NEW** ✨ | 100x vs full analysis |
| Binary Size | 18.2 MB | 19.1 MB | +5% ⬇️ | AI deps added |

**Legend**: ⬆️ Improvement | ⬇️ Regression | ✨ New

---

## 📚 Documentation

This release includes **~4,300 lines** of comprehensive documentation:

- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** (~1000 lines) - Complete system design with "why" rationale for every decision
- **[CLI_REFERENCE.md](docs/CLI_REFERENCE.md)** (~500 lines) - Full command reference with examples
- **[NETWORK_DIAGRAMS.md](docs/NETWORK_DIAGRAMS.md)** (~800 lines) - Network flows, security boundaries, data sanitization
- **[TEST_STRATEGY.md](docs/TEST_STRATEGY.md)** (~900 lines) - All 43 tests documented with scope and "why" explanations
- **[QA_CHECKLIST.md](docs/QA_CHECKLIST.md)** (~700 lines) - 62 pre-release test cases with rationale

**Special Emphasis**: Every document includes **"why"** explanations for design decisions, test cases, and architectural choices (explicit user requirement).

---

## 🚀 Quick Start

### Installation

```bash
# From source
git clone https://github.com/beejak/MCP_Scanner.git
cd MCP_Scanner
cargo build --release

# Binary will be at: ./target/release/mcp-sentinel
```

### Quick Scan (Local Only)

```bash
# Static analysis only
mcp-sentinel scan ./my-server
```

### Deep Scan (AI Analysis)

```bash
# Local AI (Ollama)
mcp-sentinel scan ./my-server --mode deep --llm-provider ollama

# Cloud AI (OpenAI)
export OPENAI_API_KEY="sk-..."
mcp-sentinel scan ./my-server --mode deep --llm-provider openai
```

### CI/CD Integration

```bash
# GitHub Actions - SARIF output for Code Scanning
mcp-sentinel scan . \
  --mode deep \
  --llm-provider ollama \
  --fail-on high \
  --output sarif \
  --output-file results.sarif
```

---

## 📈 Statistics

- **+19,008** lines added (code + documentation)
- **43** unit tests (all documented with "why" explanations)
- **4** AI provider integrations
- **5** major new components (AI engine, cache, baseline, suppression, git)
- **62** QA test cases for release validation

---

## 🔒 Security Features

- **Credential Sanitization**: API keys and passwords removed before cloud LLM analysis
- **Rate Limiting**: Provider-specific semaphore-based limits
- **TLS 1.3**: All cloud provider connections encrypted
- **Local Options**: Ollama for airgapped/offline environments
- **Audit Logging**: All suppressions logged with timestamp and reason

---

## 🐛 Known Issues

None at release time.

Report issues at: https://github.com/beejak/MCP_Scanner/issues

---

## 💡 Use Cases

### Development Workflow
```bash
# Fast feedback during coding
mcp-sentinel scan . --verbose

# Watch for changes
mcp-sentinel monitor . --watch
```

### CI/CD Pipeline
```bash
# PR checks with SARIF output
mcp-sentinel scan . --fail-on high --output sarif
```

### Security Audit
```bash
# Comprehensive analysis with AI
mcp-sentinel audit . --comprehensive --llm-provider openai
```

---

## 🔄 Breaking Changes

None. This release is fully backward compatible with v1.6.0.

---

## 📖 Migration Guide

No migration needed. v2.0.0 is backward compatible with v1.6.0.

**New Configuration Options:**
- `--mode deep` - Enable AI analysis
- `--llm-provider <name>` - Choose AI provider
- `--cache-dir` - Specify cache location
- `--baseline` - Enable baseline comparison

**Environment Variables:**
- `OPENAI_API_KEY` - For OpenAI provider
- `ANTHROPIC_API_KEY` - For Anthropic provider
- `GOOGLE_API_KEY` - For Google Gemini provider

See [CLI_REFERENCE.md](docs/CLI_REFERENCE.md) for complete documentation.

---

## 🎯 What's Next (v2.1.0 Planned)

- Integration test suite (24 tests)
- Performance benchmarks (CI/CD tracking)
- Docker image for easy deployment
- Pre-commit hooks
- GitHub Action template

---

## 🙏 Acknowledgments

Special thanks to contributors and community members for feedback and testing.

---

## 📞 Support

- **Documentation**: [docs/README.md](docs/README.md)
- **Issues**: https://github.com/beejak/MCP_Scanner/issues
- **Discussions**: https://github.com/beejak/MCP_Scanner/discussions
- **Security**: security@mcpsentinel.com

---

**Released**: 2025-10-26
**Tested On**: Linux, macOS, Windows
**Minimum Rust Version**: 1.70+
```

**Why Comprehensive Release Notes**: Users need to understand what changed, why it matters, and how to use new features. Performance data shows continuous improvement.

---

## Post-Release Verification

### 1. Verify Release Published

```bash
# Check release via API
curl -s https://api.github.com/repos/beejak/MCP_Scanner/releases/latest | grep tag_name

# Should output: "tag_name": "v2.0.0"
```

### 2. Verify Tag Pushed

```bash
# Check tags
git ls-remote --tags origin | grep v2.0.0

# Should show: refs/tags/v2.0.0
```

### 3. Test Installation from Release

```bash
# Clone at specific tag
git clone --branch v2.0.0 https://github.com/beejak/MCP_Scanner.git test-v2.0.0
cd test-v2.0.0

# Build
cargo build --release

# Verify version
./target/release/mcp-sentinel --version
# Should output: mcp-sentinel 2.0.0
```

### 4. Update Documentation Links

- Update README.md badges (if version-specific)
- Update docs.rs links (if library crate)
- Update examples in documentation

### 5. Announce Release

- Post to GitHub Discussions
- Tweet/social media announcement
- Update project website
- Notify major users

---

## Release Checklist Template

Use this checklist for every release. Copy to issue/PR description:

```markdown
## Pre-Release Quality Assurance

- [ ] All tests pass (`cargo test`)
- [ ] No clippy warnings (`cargo clippy -- -D warnings`)
- [ ] Code formatted (`cargo fmt --check`)
- [ ] Documentation builds (`cargo doc --no-deps`)
- [ ] Clean release build successful
- [ ] QA checklist completed (docs/QA_CHECKLIST.md)
- [ ] Performance benchmarks completed
- [ ] Code sanitization performed

## Documentation Updates

- [ ] CHANGELOG.md updated with new version
- [ ] Performance comparison table added to CHANGELOG.md
- [ ] Version numbers updated (Cargo.toml, src/, README.md)
- [ ] New features documented in README.md
- [ ] Migration guide written (if breaking changes)
- [ ] CLI examples updated

## Code Quality

- [ ] Dead code removed
- [ ] Debug code removed (print statements, temporary hacks)
- [ ] Commented code removed
- [ ] Dependencies reviewed (cargo outdated, cargo audit)
- [ ] Unused dependencies removed (cargo +nightly udeps)
- [ ] No TODO comments for completed work
- [ ] Error handling reviewed (no production unwrap())

## Performance Delta Documentation

- [ ] Previous release benchmarked (baseline)
- [ ] Current release benchmarked
- [ ] Comparison table created
- [ ] Metrics added to CHANGELOG.md
- [ ] Regressions documented and justified
- [ ] Improvements highlighted

## Release Creation

- [ ] Local repository updated to main
- [ ] Working directory clean (git status)
- [ ] Annotated tag created (git tag -a vX.Y.Z)
- [ ] Tag message includes features, docs, performance, stats
- [ ] Tag pushed to GitHub (git push origin vX.Y.Z)
- [ ] GitHub Release created via API or Web UI
- [ ] Release description follows template
- [ ] Release set as "latest"

## Post-Release Verification

- [ ] Release appears on GitHub
- [ ] Tag is visible (git ls-remote)
- [ ] Latest release API endpoint returns correct version
- [ ] Installation from tag tested
- [ ] Binary runs and shows correct version (--version)
- [ ] Documentation links updated
- [ ] Release announced (discussions, social, etc.)

## Sign-Off

- [ ] Release Manager: @username
- [ ] QA Lead: @username (if applicable)
- [ ] Date: YYYY-MM-DD
```

---

## Automation Opportunities

### 1. Performance Benchmarking Script

Create `tools/benchmark.sh`:

```bash
#!/bin/bash
# tools/benchmark.sh

echo "=== MCP Sentinel Performance Benchmark ==="
echo "Version: $(cargo pkgid | cut -d# -f2)"
echo "Date: $(date -u +%Y-%m-%d)"
echo ""

# Build release binary
cargo build --release

# Scan performance
echo "Scan Performance (1000 files):"
time ./target/release/mcp-sentinel scan ./test-corpus-1000 --output json > /dev/null

# Memory usage (requires /usr/bin/time)
echo ""
echo "Memory Usage:"
/usr/bin/time -v ./target/release/mcp-sentinel scan ./test-corpus-1000 2>&1 | grep "Maximum resident set size"

# Binary size
echo ""
echo "Binary Size:"
ls -lh ./target/release/mcp-sentinel | awk '{print $5}'

# Cache performance (if applicable)
echo ""
echo "Cache Performance:"
./target/release/mcp-sentinel scan ./test-corpus-1000 --verbose 2>&1 | grep -i "cache hit"
```

### 2. Release Script

Create `tools/create-release.sh`:

```bash
#!/bin/bash
# tools/create-release.sh

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 2.0.0"
    exit 1
fi

VERSION=$1
TAG="v$VERSION"

echo "Creating release: $TAG"
echo ""

# Pre-flight checks
echo "Running pre-flight checks..."
cargo test
cargo clippy -- -D warnings
cargo fmt --check

# Create tag
echo ""
echo "Creating tag: $TAG"
git tag -a "$TAG" -m "Release $TAG

See CHANGELOG.md for details."

# Push tag
echo ""
echo "Pushing tag to origin..."
git push origin "$TAG"

echo ""
echo "✅ Release tag created and pushed: $TAG"
echo "Next: Create GitHub Release at https://github.com/beejak/MCP_Scanner/releases/new?tag=$TAG"
```

### 3. Performance Comparison Script

Create `tools/compare-performance.sh`:

```bash
#!/bin/bash
# tools/compare-performance.sh

BASELINE=$1
CURRENT=$2

if [ $# -ne 2 ]; then
    echo "Usage: $0 <baseline-file> <current-file>"
    exit 1
fi

# Parse and compare (basic example)
echo "| Metric | Baseline | Current | Change |"
echo "|--------|----------|---------|--------|"

# Extract metrics and compare
# (Implementation depends on benchmark output format)
```

**Why Automation**: Reduces human error, ensures consistency, saves time, makes releases reproducible.

---

## Version Numbering Guidelines

### When to Increment Major Version (X.0.0)

- Breaking API changes
- Major architectural changes
- Removed features
- Changes requiring migration work

**Example**: v1.9.0 → v2.0.0 (renamed CLI flags, removed deprecated features)

### When to Increment Minor Version (0.Y.0)

- New features (backward compatible)
- New CLI commands
- New detectors or providers
- Significant performance improvements
- New documentation

**Example**: v1.5.0 → v1.6.0 (added SARIF output, config files, progress indicators)

### When to Increment Patch Version (0.0.Z)

- Bug fixes
- Security patches
- Documentation fixes
- Minor performance improvements
- Dependency updates

**Example**: v1.6.0 → v1.6.1 (fixed crash on empty files, updated dependencies)

### Pre-Release Versions

- Alpha: `v2.0.0-alpha.1` (early testing, unstable)
- Beta: `v2.0.0-beta.1` (feature complete, testing)
- RC: `v2.0.0-rc.1` (release candidate, final testing)

**Why**: Communicates stability expectations to users.

---

## Release Cadence Recommendations

### Regular Releases

- **Minor releases**: Every 2-4 weeks (new features)
- **Patch releases**: As needed (bug fixes)
- **Major releases**: Every 3-6 months (breaking changes)

### Emergency Releases

- **Security patches**: Immediately (critical vulnerabilities)
- **Critical bugs**: Within 24-48 hours (data loss, crashes)

**Why**: Predictable cadence helps users plan upgrades. Fast response to critical issues builds trust.

---

## Rollback Procedure

If a release has critical issues:

### 1. Assess Severity

- **Critical** (data loss, security): Immediate rollback
- **High** (crashes, broken features): Rollback or hotfix
- **Medium/Low**: Document workaround, fix in patch

### 2. Create Hotfix

```bash
# Create hotfix branch from tag
git checkout -b hotfix/v2.0.1 v2.0.0

# Apply fix
# ... make changes ...

# Test thoroughly
cargo test

# Commit
git commit -m "Fix critical bug in AI provider"

# Create patch release
git tag -a v2.0.1 -m "Hotfix: Fix critical bug in AI provider"
git push origin v2.0.1
```

### 3. Deprecate Broken Release

- Mark GitHub Release as pre-release
- Add warning to release notes
- Document issue in CHANGELOG.md

### 4. Communicate

- Post issue to GitHub
- Notify users via discussions/announcements
- Update documentation

**Why**: Fast response to issues maintains user trust. Clear communication prevents confusion.

---

## Appendix: Example Release Messages

### Example 1: Major Release (v2.0.0)

```
🛡️ MCP Sentinel v2.0.0 - AI Analysis Engine

MAJOR RELEASE: Adds AI-powered vulnerability detection

Features:
- AI analysis engine (OpenAI, Anthropic, Gemini, Ollama)
- Intelligent caching (70-90% space savings)
- Baseline comparison (track NEW/FIXED/CHANGED)
- Suppression system (YAML-based false positive management)
- Git integration (10-100x faster incremental scans)

Performance: 34% faster scans, 32% less memory
Documentation: 4,300 lines of comprehensive docs with "why" rationale
Tests: 43 unit tests, all documented

Breaking Changes: None (backward compatible)
```

### Example 2: Minor Release (v1.6.0)

```
MCP Sentinel v1.6.0 - Production Ready

New Features:
- SARIF output format (GitHub Code Scanning integration)
- Configuration file support (~/.mcp-sentinel/config.yaml)
- MCP config scanning (detect insecure MCP servers)
- Progress indicators (real-time scan feedback)
- Enhanced exit codes (CI/CD integration)

Performance: 15% faster scans, better memory usage
Documentation: Updated CLI reference, new examples
Tests: +18 new tests

Breaking Changes: None
```

### Example 3: Patch Release (v1.6.1)

```
MCP Sentinel v1.6.1 - Bug Fixes

Fixes:
- Fixed crash on empty files (issue #42)
- Fixed SARIF output for files without line numbers
- Fixed config file parsing error messages
- Updated dependencies (security patches)

Performance: No changes
Documentation: Fixed typos in CLI reference

No breaking changes.
```

---

## Summary

**Key Takeaways:**

1. **Always use annotated tags** with comprehensive messages
2. **Document performance deltas** in CHANGELOG.md for every release
3. **Sanitize code** before release (remove dead code, debug statements)
4. **Follow QA checklist** completely (docs/QA_CHECKLIST.md)
5. **Create detailed GitHub Releases** with performance comparison tables
6. **Test the release** after publishing (install from tag, run basic commands)

**Why This Process Matters:**

- **Users**: Know what changed, why to upgrade, performance impact
- **Contributors**: Understand standards, can reproduce process
- **Project**: Maintains quality, builds trust, demonstrates progress

---

**Document Version**: 1.0.0
**Last Updated**: 2025-10-26
**Next Review**: Before v2.1.0 release
