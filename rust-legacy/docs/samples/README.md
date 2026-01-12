# Sample Scan Reports - MCP Sentinel v2.5.0

This directory contains comprehensive sample outputs demonstrating MCP Sentinel v2.5.0 capabilities.

## 📁 Available Samples

### 1. Terminal Output (Comprehensive Multi-Engine Scan)
**File:** [`terminal_output_comprehensive.txt`](terminal_output_comprehensive.txt)

A complete terminal output showing all 5 analysis engines working together:
- 🌳 Semantic Analysis (Tree-sitter)
- 🔍 Semgrep SAST (1000+ rules)
- 🤖 AI Analysis (Ollama)
- ⚡ Static Analysis
- 🛡️ MCP Tool Description Analysis

**Features shown:**
- GitHub URL scanning (direct repository clone)
- Multi-phase analysis with timing
- 29 vulnerabilities across 4 severity levels
- 3 detailed vulnerability cards with remediation steps
- Engine statistics and performance metrics
- Risk scoring and recommendations

**Size:** ~22 KB, 200+ lines
**Example command:**
```bash
mcp-sentinel scan https://github.com/example-org/mcp-server \
  --mode deep \
  --enable-semgrep \
  --llm-provider ollama \
  --output html \
  --output-file audit.html
```

---

### 2. JSON Output (Structured Vulnerability Data)
**File:** [`scan_results.json`](scan_results.json)

Complete JSON structure for CI/CD integration and programmatic analysis.

**Contents:**
- Scan metadata (timestamp, engines, duration)
- Summary with risk scoring (78/100)
- 5 detailed vulnerability objects:
  - **VULN-001:** Hardcoded API key (critical)
  - **VULN-002:** Command injection with dataflow analysis (critical)
  - **VULN-003:** Prompt injection in MCP tool description (critical)
  - **VULN-004:** Path traversal vulnerability (high)
  - **VULN-005:** SQL injection via string concatenation (high)
- Engine statistics for all 5 engines
- Remediation recommendations
- Risk reduction estimates

**Size:** ~11 KB
**Example command:**
```bash
mcp-sentinel scan ./server --enable-semgrep --output json --output-file results.json
```

**Use cases:**
- Parse in CI/CD pipelines
- Generate custom reports
- Track vulnerabilities over time
- Integration with security dashboards

---

## 🔗 Direct Links

If the relative links above don't work, use these direct GitHub URLs:

- **Terminal Output:** https://github.com/beejak/MCP_Scanner/blob/main/docs/samples/terminal_output_comprehensive.txt
- **JSON Output:** https://github.com/beejak/MCP_Scanner/blob/main/docs/samples/scan_results.json

---

## 🎬 Want to See It in Action?

### Generate Your Own Scan

```bash
# Install MCP Sentinel
cargo install mcp-sentinel  # or download from releases

# Quick scan
mcp-sentinel scan ./your-mcp-server

# Comprehensive scan with all engines
mcp-sentinel scan ./your-mcp-server \
  --mode deep \
  --enable-semgrep \
  --llm-provider ollama \
  --output html \
  --output-file my-audit.html
```

### Record a Demo GIF

Follow the [GIF Recording Guide](../GIF_RECORDING_GUIDE.md) to create visual demonstrations.

---

## 📊 What These Samples Demonstrate

### v2.5.0 Features in Action

| Feature | Demonstrated In |
|---------|----------------|
| 🌳 Tree-sitter AST parsing | Terminal output (Phase 4) |
| 🔍 Semgrep SAST integration | Terminal output (Phase 5), JSON engine_statistics |
| 📊 Risk scoring algorithm | Terminal output (78/100), JSON summary |
| 🐙 GitHub URL scanning | Terminal output (Phase 1 cloning) |
| 🛡️ Tool description analysis | Terminal output (Phase 7) |
| 🧬 Dataflow analysis | JSON VULN-002 (source → sink paths) |
| 🤖 AI-powered confirmation | Terminal output (Phase 6), JSON detected_by |
| 📋 Structured JSON output | scan_results.json (full structure) |

### Detection Capabilities

**From these samples, you can see MCP Sentinel detecting:**
- ✅ Hardcoded secrets (API keys, tokens)
- ✅ Command injection vulnerabilities
- ✅ Path traversal attacks
- ✅ SQL injection
- ✅ Prompt injection in tool descriptions
- ✅ Dataflow vulnerabilities (source to sink)
- ✅ Insecure deserialization
- ✅ Missing authentication
- ✅ Weak cryptography
- ✅ SSRF vulnerabilities

---

## 🤝 Contributing

Found these samples helpful? Consider:
- ⭐ Starring the repository
- 🎬 Recording demo GIFs (see [recording guide](../GIF_RECORDING_GUIDE.md))
- 📝 Submitting additional sample outputs
- 🐛 Reporting issues

---

## 📚 Additional Resources

- [Main README](../../README.md) - Project overview and quick start
- [CLI Reference](../CLI_REFERENCE.md) - Complete command documentation
- [Architecture](../ARCHITECTURE_PHASE_2_5.md) - Technical design details
- [Release Notes](../../RELEASE_NOTES_v2.5.0.md) - v2.5.0 changelog

---

**Questions?** Open an issue: https://github.com/beejak/MCP_Scanner/issues
