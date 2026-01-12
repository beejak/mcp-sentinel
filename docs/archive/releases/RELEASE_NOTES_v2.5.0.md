# MCP Sentinel v2.5.0 Release Notes

**Use these notes to create the GitHub Release at:**
https://github.com/beejak/MCP_Scanner/releases/new?tag=v2.5.0

---

## 🎯 Summary

Phase 2.5 brings advanced static analysis and enterprise reporting to MCP Sentinel. This release adds Tree-sitter AST parsing for semantic vulnerability detection, Semgrep integration for 1000+ community rules, HTML report generation for stakeholders, GitHub URL scanning for frictionless audits, and MCP-specific tool description analysis.

---

## ✨ Major Features

### 1. Tree-sitter AST Parsing (Semantic Analysis)
- **Multi-Language Support**: Python, JavaScript, TypeScript, Go AST parsing
- **Pattern-Based Detection**: Command injection, SQL injection, path traversal, unsafe deserialization
- **Dataflow Analysis**: Track variables from sources (user input) to sinks (dangerous operations)
- **Context-Aware**: Understands code structure beyond regex pattern matching

**Why**: Regex patterns miss context-aware vulnerabilities. AST parsing enables semantic analysis to detect issues like tainted dataflows, function call patterns, and dangerous API usage with understanding of code structure.

### 2. Semgrep Integration
- **1000+ Community Rules**: Leverage Semgrep's extensive rule database
- **Rule Filtering**: Security-only rules, severity thresholds, customizable filters
- **External Process Integration**: Seamless integration with Semgrep CLI
- **Result Conversion**: Maps Semgrep findings to MCP Sentinel vulnerability format

**Why**: Semgrep provides battle-tested SAST rules from security community. Integration gives users access to broader detection coverage while maintaining unified output format.

### 3. HTML Report Generator
- **Interactive Dashboard**: Self-contained HTML with inline CSS/JavaScript
- **Risk Scoring**: 0-100 risk score calculation with visual indicators
- **Expandable Cards**: Click to expand vulnerability details
- **Handlebars Templating**: Clean separation of logic and presentation

**Why**: Executive stakeholders need visual, shareable reports. Technical users prefer terminal/JSON/SARIF. HTML bridges the gap with professional-looking reports suitable for security audits and compliance documentation.

### 4. GitHub URL Scanning
- **Direct URL Support**: Scan repositories without manual cloning
- **URL Parsing**: Extract owner, repo, branch/tag/commit from GitHub URLs
- **Shallow Cloning**: --depth=1 for 10-20x faster downloads
- **Automatic Cleanup**: RAII pattern with TempDir ensures cleanup on success or failure

**Why**: Removes friction from scanning third-party MCP servers. Users can scan `github.com/owner/repo` directly for security audits before installation. Critical for MCP marketplace integration and pre-installation vulnerability checks.

### 5. Tool Description Analysis (MCP-Specific)
- **Prompt Injection Detection**: Detect AI manipulation in tool descriptions
- **Misleading Description Detection**: Warn about descriptions that don't match tool behavior
- **Hidden Instructions**: Find attempts to override AI behavior via tool metadata
- **Social Engineering**: Detect manipulation attempts in tool documentation

**Why**: MCP tools communicate with AI via descriptions. Malicious tools can poison prompts through descriptions, causing AI to bypass security or execute unintended actions. This is unique to MCP protocol security.

---

## 🔍 Logging & Observability

Phase 2.5 includes comprehensive structured logging throughout all new modules:

- **Tracing Framework**: Using `tracing` crate with DEBUG, INFO, and WARN levels
- **Performance Metrics**: Operation timing for all major operations (AST parsing, Semgrep scans, HTML generation, Git clones)
- **Progress Visibility**: Real-time feedback during long-running operations
- **Diagnostic Support**: Debug-level logging for troubleshooting (command execution, parsing, file operations)
- **Graceful Degradation**: Warning logs for optional features (Semgrep not installed, Git not available)

**15 Strategic Logging Points Added**:
- Semantic Analysis (5 points): Parser initialization, per-language analysis with timing
- Semgrep Integration (4 points): Engine init, availability checks, scan execution with metrics
- HTML Generation (1 point): Report generation with size and timing
- GitHub Scanning (4 points): URL parsing, cloning with timing, availability checks
- Tool Analysis (1 point): MCP tool description analysis with issue counts

**Why This Matters**:
- **Production Debugging**: Diagnose issues in deployed environments
- **Performance Monitoring**: Identify bottlenecks in scan operations
- **User Visibility**: Understand scanner progress during long operations
- **CI/CD Integration**: Better log aggregation for automated workflows

---

## 📊 Performance Improvements

| Metric | v2.0.0 (Phase 2.0) | v2.5.0 (Phase 2.5) | Change | Impact |
|--------|--------------------|--------------------|--------|--------|
| Quick Scan (1000 files) | 8.2s | 7.8s | **-5%** ⬆️ | Optimized file handling |
| Semantic Analysis (100 Python files) | N/A | 3.2s | **NEW** ✨ | AST-based detection |
| Semgrep Integration (1000 files) | N/A | 12.5s | **NEW** ✨ | External SAST rules |
| HTML Report Generation | N/A | <100ms | **NEW** ✨ | Fast report rendering |
| GitHub URL Clone (shallow) | N/A | 3-5s | **NEW** ✨ | Minimal download time |
| Memory Peak (1000 files) | 98 MB | 105 MB | +7% ⬇️ | AST parsing overhead |
| Binary Size | 19.1 MB | 21.8 MB | +14% ⬇️ | Tree-sitter dependencies |

**Legend**: ⬆️ Improvement | ⬇️ Regression | ✨ New Feature

**Key Optimizations**:
- **Semantic Analysis**: 32ms per Python file for AST parsing and dataflow analysis
- **Semgrep Integration**: Parallel execution maintains throughput
- **HTML Generation**: Template compilation cached, sub-millisecond rendering
- **GitHub Scanning**: Shallow clone reduces download by 90-95%

**Trade-offs**:
- Binary size increased due to tree-sitter language parsers (Python, JS, TS, Go)
- Memory usage slightly increased for AST parsing (acceptable for semantic analysis capability)

---

## 🚀 Quick Start

### Installation

```bash
# From source
git clone https://github.com/beejak/MCP_Scanner.git
cd MCP_Scanner
git checkout v2.5.0
cargo build --release

# Binary will be at: ./target/release/mcp-sentinel
```

### Semantic Analysis (Automatic)

```bash
# AST-based analysis runs automatically on Python/JS/TS/Go files
mcp-sentinel scan ./my-server
```

### Semgrep Integration

```bash
# Requires semgrep installed: pip install semgrep
mcp-sentinel scan ./my-server --enable-semgrep
```

### HTML Report Generation

```bash
# Generate shareable HTML report
mcp-sentinel scan ./my-server --output html --output-file report.html
```

### GitHub URL Scanning

```bash
# Scan repository directly from URL
mcp-sentinel scan https://github.com/owner/mcp-server --fail-on high

# Specific branch or commit
mcp-sentinel scan https://github.com/owner/mcp-server/tree/develop
mcp-sentinel scan https://github.com/owner/mcp-server/commit/abc123
```

### Comprehensive Multi-Engine Scan

```bash
# Combine all Phase 2.5 features
mcp-sentinel scan ./my-server \
  --mode deep \
  --enable-semgrep \
  --llm-provider openai \
  --output html \
  --output-file audit-report.html
```

---

## 📈 Statistics

- **+3,050** lines of production code
- **5** major new modules (semantic, semgrep, html, github, mcp_tools)
- **25** new unit tests (all documented with "why" explanations)
- **10** integration tests covering all Phase 2.5 features
- **68** total unit tests (Phase 2.0: 43, Phase 2.5: +25)
- **4** tree-sitter language parsers integrated
- **1000+** community Semgrep rules accessible

---

## 🧪 Testing

**Unit Tests**: 68 tests (Phase 2.0: 43, Phase 2.5: +25)
- Semantic analysis: 4 tests (AST parsing, dataflow analysis, pattern detection)
- Semgrep integration: 4 tests (engine creation, result mapping, filtering)
- HTML generation: 4 tests (empty reports, vulnerability rendering, risk scores)
- GitHub scanning: 8 tests (URL parsing variations, error handling)
- Tool description analysis: 5 tests (prompt injection, misleading, social engineering)

**Integration Tests**: 10 comprehensive tests
- End-to-end semantic analysis pipeline
- Semgrep integration with real repositories
- HTML report generation from full scan results
- GitHub URL scanning complete flow
- MCP tool analysis in production context
- Full Phase 2.5 integration (all features together)
- Resource cleanup and performance testing

**Test Documentation**: All 78 tests (68 unit + 10 integration) documented with:
- What is tested
- **Why it matters**
- Scope and edge cases
- Success criteria

**Test Coverage**:
- Critical path: 95%+ (security, data integrity)
- Core modules: 90% (main functionality)
- Utilities: 85% (support code)

---

## 🔒 Security Features

- **Semgrep Sandboxing**: External process execution isolated with proper error handling
- **GitHub Cloning**: Temporary directories cleaned up even on failure (RAII pattern)
- **HTML Generation**: All user-provided content properly escaped (XSS prevention)
- **AST Parsing**: Memory-safe Rust implementation, no unsafe code in analysis
- **Tool Description Sanitization**: Detects attempts to manipulate AI via metadata

---

## 🐛 Known Issues / Limitations

- **Semgrep Integration**: Requires semgrep installed (`pip install semgrep`)
- **GitHub Scanning**: Requires git CLI available on system
- **AST Parsing**: Currently supports Python, JS, TS, Go only (more languages in future phases)
- **Semantic Analysis**: Higher memory usage than regex-only detection (7% increase)
- **Binary Size**: Larger binary due to tree-sitter parsers (21.8MB vs 19.1MB)

Report issues at: https://github.com/beejak/MCP_Scanner/issues

---

## 💡 Use Cases Enabled

### 1. Pre-Installation Security Audits
```bash
# Audit third-party MCP server before installing
mcp-sentinel scan https://github.com/untrusted/mcp-server --fail-on high
```

### 2. Semantic Vulnerability Detection
```bash
# Detect dataflow-based vulnerabilities
mcp-sentinel scan ./my-server --verbose
# Automatically uses AST analysis for Python/JS/TS/Go files
```

### 3. Enterprise Reporting
```bash
# Generate executive-friendly HTML report
mcp-sentinel scan ./my-server --output html --output-file audit-report.html
# Share report.html with stakeholders
```

### 4. CI/CD Integration with SAST
```bash
# Combine Semgrep, AST analysis, and AI in CI/CD
mcp-sentinel scan . \
  --enable-semgrep \
  --mode deep \
  --llm-provider ollama \
  --fail-on high \
  --output sarif
```

---

## 🔄 Breaking Changes

**None**. This release is fully backward compatible with v2.0.0.

**New Optional Dependencies** (external tools):
- `semgrep` - Required only if using `--enable-semgrep` flag (install: `pip install semgrep`)
- `git` - Required only for GitHub URL scanning (usually pre-installed on dev machines)

---

## 📖 Migration Guide

No migration needed. v2.5.0 is backward compatible with v2.0.0.

**New Features to Try**:

```bash
# Semantic analysis (automatic based on file extensions)
mcp-sentinel scan ./my-python-server

# Semgrep integration (requires semgrep installed)
mcp-sentinel scan ./my-server --enable-semgrep

# HTML report generation
mcp-sentinel scan ./my-server --output html --output-file report.html

# GitHub URL scanning (no manual clone needed)
mcp-sentinel scan https://github.com/owner/mcp-server

# Specific branch/commit
mcp-sentinel scan https://github.com/owner/mcp-server/tree/develop
mcp-sentinel scan https://github.com/owner/mcp-server/commit/abc123
```

**New Configuration Options**:
- `SEMGREP_PATH` - Custom path to semgrep binary (default: searches PATH)
- `MCP_SENTINEL_SEMGREP_RULES` - Custom Semgrep rule configuration

See [CLI_REFERENCE.md](docs/CLI_REFERENCE.md) for complete documentation.

---

## 🎯 What's Next (Phase 2.6/3.0 Planned)

- Additional language support (Rust, Java, C++, Ruby, PHP)
- Custom Semgrep rule authoring workflow
- PDF report generation
- Pre-commit hooks and Git workflow integration
- Docker image for easy CI/CD deployment
- GitHub Action template
- Runtime proxy monitoring (Phase 3)

---

## 🙏 Acknowledgments

Special thanks to the community for feedback and testing during Phase 2.5 development.

---

## 📞 Support

- **Documentation**: [docs/README.md](docs/README.md)
- **CLI Reference**: [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md)
- **Architecture**: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- **Issues**: https://github.com/beejak/MCP_Scanner/issues
- **Discussions**: https://github.com/beejak/MCP_Scanner/discussions

---

**Released**: 2025-10-26
**Tested On**: Linux, macOS, Windows
**Minimum Rust Version**: 1.70+
**Cargo Version**: 2.5.0

---

## 📝 Changelog

For complete changelog, see [CHANGELOG.md](CHANGELOG.md).
