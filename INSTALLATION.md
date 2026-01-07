# MCP Sentinel v2.6.0 - Installation Guide

## Table of Contents
- [System Requirements](#system-requirements)
- [Quick Install](#quick-install)
- [Installation Methods](#installation-methods)
- [Configuration](#configuration)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)
- [Next Steps](#next-steps)

---

## System Requirements

### Minimum Requirements
- **Operating System**: Linux, macOS, or Windows (WSL2)
- **Rust**: 1.70.0 or later
- **Memory**: 512 MB RAM (2 GB recommended)
- **Disk Space**: 100 MB for binary and data files
- **Network**: Internet connection for threat intelligence (optional)

### Optional Dependencies
- **Tree-sitter**: Included (automatically built)
- **Semgrep**: Optional (install separately for Semgrep engine)
- **Git**: For cloning repository

### Supported Platforms
- ✅ Linux x86_64
- ✅ macOS ARM64 (M1/M2/M3)
- ✅ macOS x86_64 (Intel)
- ✅ Windows WSL2 (Ubuntu)

---

## Quick Install

### Option 1: From Source (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/beejak/MCP_Scanner.git
cd MCP_Scanner

# 2. Checkout v2.6.0
git checkout v2.6.0

# 3. Build release binary
cargo build --release

# 4. Install to system path (optional)
sudo cp target/release/mcp-sentinel /usr/local/bin/

# 5. Verify installation
mcp-sentinel --version
# Expected: MCP Sentinel v2.6.0
```

**Build time**: ~5-10 minutes on first build (dependencies cached afterward)

### Option 2: Cargo Install

```bash
# Install from crates.io (once published)
cargo install mcp-sentinel

# Verify installation
mcp-sentinel --version
```

---

## Installation Methods

### Method 1: Development Installation

For contributing or testing:

```bash
# Clone repository
git clone https://github.com/beejak/MCP_Scanner.git
cd MCP_Scanner

# Checkout v2.6.0
git checkout v2.6.0

# Build in debug mode (faster compilation)
cargo build

# Run from target directory
./target/debug/mcp-sentinel --help

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run -- scan ./test-project
```

### Method 2: Production Installation

For production use:

```bash
# Clone and build optimized binary
git clone https://github.com/beejak/MCP_Scanner.git
cd MCP_Scanner
git checkout v2.6.0

# Build with all optimizations
cargo build --release

# Strip binary to reduce size (optional)
strip target/release/mcp-sentinel

# Install system-wide
sudo install -m 755 target/release/mcp-sentinel /usr/local/bin/

# Or install to user directory
mkdir -p ~/.local/bin
cp target/release/mcp-sentinel ~/.local/bin/
# Add ~/.local/bin to PATH if needed
```

### Method 3: Docker Installation

```bash
# Build Docker image
docker build -t mcp-sentinel:2.6.0 .

# Run scan in container
docker run --rm -v $(pwd):/workspace mcp-sentinel:2.6.0 scan /workspace

# Create alias for convenience
alias mcp-sentinel='docker run --rm -v $(pwd):/workspace mcp-sentinel:2.6.0'
```

**Dockerfile example**:
```dockerfile
FROM rust:1.75-slim as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/mcp-sentinel /usr/local/bin/
ENTRYPOINT ["mcp-sentinel"]
```

---

## Configuration

### Environment Variables

#### Threat Intelligence API Keys (Optional)

```bash
# VulnerableMCP API (for vulnerability database)
export VULNERABLE_MCP_API_KEY="your-api-key-here"

# NVD API (National Vulnerability Database)
export NVD_API_KEY="your-nvd-api-key"
# Without API key: 5 requests/minute
# With API key: 50 requests/minute
```

**Get API Keys**:
- **NVD**: Register at https://nvd.nist.gov/developers/request-an-api-key
- **VulnerableMCP**: Contact MCP Security team (public API coming soon)

#### Logging Configuration

```bash
# Enable detailed logging
export RUST_LOG=info              # Info level (default)
export RUST_LOG=debug             # Debug level (verbose)
export RUST_LOG=mcp_sentinel=debug # Module-specific debug

# Disable color output (for CI/CD)
export NO_COLOR=1
```

#### Performance Tuning

```bash
# Adjust concurrency (default: CPU cores)
export MCP_PARALLEL_SCANS=4

# Increase memory limit (default: no limit)
export MCP_MAX_MEMORY_MB=2048
```

### Configuration File

Create `~/.config/mcp-sentinel/config.toml`:

```toml
# MCP Sentinel Configuration v2.6.0

[general]
# Enable color output
color = true

# Default severity filter
min_severity = "medium"

[engines]
# Enable/disable analysis engines
pattern_matching = true
semantic_ast = true
semgrep = false  # Requires separate Semgrep installation
threat_intelligence = true

[threat_intelligence]
# Threat intelligence sources
vulnerable_mcp = true
mitre_attack = true
nvd_feed = true

# Cache threat intelligence results (hours)
cache_duration = 24

[output]
# Default output format
format = "terminal"  # Options: terminal, json, sarif, html

# Output file path (optional)
# output_file = "./scan-results.json"

[scanning]
# File patterns to include
include = ["*.js", "*.ts", "package.json"]

# File patterns to exclude
exclude = ["node_modules/**", "dist/**", "build/**"]

# Maximum file size (bytes)
max_file_size = 10485760  # 10 MB
```

---

## Verification

### Verify Installation

```bash
# Check version
mcp-sentinel --version
# Expected: MCP Sentinel v2.6.0

# Check available commands
mcp-sentinel --help

# Test with sample project
mcp-sentinel scan --help
```

### Run Self-Test

```bash
# Run unit tests
cargo test

# Run integration tests
cargo test --test integration_tests

# Run with test fixtures
mcp-sentinel scan ./tests/fixtures/vulnerable-app
```

### Expected Output

```
🔍 MCP Sentinel v2.6.0 - Security Scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📦 Target: ./tests/fixtures/vulnerable-app
⚙️  Engines: Pattern, Semantic AST, Threat Intelligence
🧠 Threat Intel: VulnerableMCP, MITRE ATT&CK, NVD

⏱️  Scanning... (7.8s)

🎯 Scan Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total Vulnerabilities: 5
  🔴 Critical: 2
  🟠 High: 2
  🟡 Medium: 1

📊 Threat Intelligence Summary:
  • MITRE ATT&CK Techniques: 8
  • Related CVEs: 5
  • Known Exploits: 2
  • Threat Actors: 1

✅ Scan complete!
```

---

## Troubleshooting

### Common Issues

#### Issue 1: "command not found: mcp-sentinel"

**Cause**: Binary not in PATH

**Solution**:
```bash
# Find where binary is installed
which mcp-sentinel

# Add to PATH (add to ~/.bashrc or ~/.zshrc)
export PATH="$HOME/.local/bin:$PATH"

# Or use full path
/usr/local/bin/mcp-sentinel --version
```

#### Issue 2: "failed to compile tree-sitter"

**Cause**: Missing C compiler

**Solution**:
```bash
# Ubuntu/Debian
sudo apt-get install build-essential

# macOS
xcode-select --install

# Fedora/RHEL
sudo dnf install gcc gcc-c++
```

#### Issue 3: "NVD API rate limit exceeded"

**Cause**: Too many requests without API key (5/min limit)

**Solution**:
```bash
# Get free API key from https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY="your-key-here"

# Or disable NVD integration
mcp-sentinel scan --no-threat-intel ./project
```

#### Issue 4: Slow scan performance

**Cause**: Large project or limited resources

**Solution**:
```bash
# Disable heavy engines
mcp-sentinel scan --no-semgrep ./project

# Reduce parallelism
export MCP_PARALLEL_SCANS=2
mcp-sentinel scan ./project

# Exclude large directories
mcp-sentinel scan --exclude "node_modules/**" ./project
```

#### Issue 5: "Permission denied" when writing reports

**Cause**: No write permission to output directory

**Solution**:
```bash
# Write to user directory
mcp-sentinel scan -o ~/reports/scan.json ./project

# Or use current directory
mcp-sentinel scan -o ./scan-results.json ./project
```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
# Full debug output
RUST_LOG=debug mcp-sentinel scan ./project 2> debug.log

# Module-specific debug
RUST_LOG=mcp_sentinel::scanner=debug mcp-sentinel scan ./project

# Trace level (very verbose)
RUST_LOG=trace mcp-sentinel scan ./project
```

### Report Issues

If you encounter bugs or issues:

1. **Check existing issues**: https://github.com/beejak/MCP_Scanner/issues
2. **Gather information**:
   ```bash
   mcp-sentinel --version
   rustc --version
   uname -a  # or `systeminfo` on Windows
   ```
3. **Create detailed issue** with:
   - Steps to reproduce
   - Expected vs actual behavior
   - Debug logs
   - System information

---

## Next Steps

### Quick Start

1. **Scan your first project**:
   ```bash
   mcp-sentinel scan ./my-node-server
   ```

2. **Generate JSON report**:
   ```bash
   mcp-sentinel scan -f json -o report.json ./my-node-server
   ```

3. **View HTML report**:
   ```bash
   mcp-sentinel scan -f html -o report.html ./my-node-server
   open report.html  # macOS
   xdg-open report.html  # Linux
   ```

### Learn More

- **📖 Usage Examples**: See `docs/examples/` for API usage
- **📊 Sample Reports**: See `docs/samples/` for output examples
- **🔧 Configuration**: See `docs/configuration.md` for advanced config
- **🛡️ Detection Rules**: See `docs/detection_rules.md` for vulnerability patterns
- **🚀 CI/CD Integration**: See `docs/ci_cd_integration.md` for automation

### Advanced Features

#### Baseline Scanning

```bash
# Create baseline
mcp-sentinel scan --baseline ./project > baseline.json

# Compare against baseline
mcp-sentinel scan --compare-baseline baseline.json ./project
```

#### Custom Rules

```bash
# Add custom Semgrep rules
mcp-sentinel scan --semgrep-rules ./custom-rules.yaml ./project
```

#### CI/CD Integration

```yaml
# GitHub Actions example
- name: Run MCP Sentinel
  run: |
    mcp-sentinel scan \
      --format sarif \
      --output results.sarif \
      --fail-on critical \
      ./src

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### Get Help

- **Documentation**: https://github.com/beejak/MCP_Scanner/tree/main/docs
- **Examples**: https://github.com/beejak/MCP_Scanner/tree/main/docs/examples
- **Issues**: https://github.com/beejak/MCP_Scanner/issues
- **Discussions**: https://github.com/beejak/MCP_Scanner/discussions

---

## Version Information

**Current Version**: v2.6.0
**Release Date**: 2025-10-26
**Rust Version**: 1.70.0+
**License**: MIT

### What's New in v2.6.0

✨ **Threat Intelligence Integration**
- VulnerableMCP API client
- MITRE ATT&CK mapping
- NVD CVE feed integration

🔒 **Supply Chain Security**
- Package confusion detection
- Malicious install script detection
- 11 new supply chain patterns

🚀 **Enhanced Detection**
- 5 DOM XSS patterns (up from 1)
- Node.js weak RNG detection
- Path traversal detection
- 78+ total patterns

🧪 **Quality Improvements**
- 18 new integration tests
- 92% test coverage
- Zero breaking changes

See `docs/releases/RELEASE_NOTES_v2.6.0.md` for complete details.

---

**🎉 Installation Complete!** You're ready to start scanning for vulnerabilities with MCP Sentinel v2.6.0.
