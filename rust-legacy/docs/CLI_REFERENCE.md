# MCP Sentinel - CLI Reference

**Version**: 2.5.0
**Purpose**: Complete command-line reference with examples, use cases, and design rationale

---

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Global Flags](#global-flags)
4. [Commands](#commands)
   - [scan](#scan---vulnerability-scanning)
   - [proxy](#proxy---runtime-monitoring)
   - [monitor](#monitor---continuous-scanning)
   - [audit](#audit---comprehensive-analysis)
   - [init](#init---initialize-configuration)
   - [whitelist](#whitelist---manage-trusted-items)
   - [rules](#rules---manage-guardrails)
5. [Exit Codes](#exit-codes)
6. [Environment Variables](#environment-variables)
7. [Configuration Files](#configuration-files)
8. [Workflow Examples](#workflow-examples)
9. [Troubleshooting](#troubleshooting)

---

## Overview

MCP Sentinel is a comprehensive security scanner for Model Context Protocol (MCP) servers. It combines:

- **Static Analysis**: Pattern-based vulnerability detection (regex, AST, semantic analysis)
- **Semantic Analysis**: Tree-sitter AST parsing for Python, JS, TS, Go (Phase 2.5)
- **SAST Integration**: Semgrep integration with 1000+ community rules (Phase 2.5)
- **AI Analysis**: LLM-powered contextual understanding (GPT-4, Claude, Gemini, Ollama)
- **Enterprise Reporting**: HTML report generation with interactive dashboards (Phase 2.5)
- **GitHub Scanning**: Direct repository URL scanning with shallow cloning (Phase 2.5)
- **Runtime Monitoring**: Transparent proxy for live traffic inspection
- **Continuous Scanning**: File watching with automatic rescans

**Why This CLI Design?**

1. **Unix Philosophy**: Single-purpose commands that do one thing well
2. **Exit Codes**: Integrate with CI/CD pipelines via exit code semantics
3. **Multiple Output Formats**: Terminal, JSON, SARIF for humans and machines
4. **Fail-Fast & Threshold-Based**: `--fail-on` enables automated quality gates
5. **Progressive Enhancement**: Quick → Deep → Audit for increasing thoroughness

---

## Installation

```bash
# From source
cargo install --path .

# From crates.io (when published)
cargo install mcp-sentinel

# From GitHub releases
wget https://github.com/mcpsentinel/mcp-sentinel/releases/latest/download/mcp-sentinel-linux-amd64
chmod +x mcp-sentinel-linux-amd64
sudo mv mcp-sentinel-linux-amd64 /usr/local/bin/mcp-sentinel

# Verify installation
mcp-sentinel --version
```

---

## Global Flags

These flags apply to **all commands**.

### `--verbose` / `-v`

Enable verbose logging (debug-level tracing).

**Why**: Diagnose issues, understand scan behavior, debug configuration problems.

**Example**:
```bash
# See detailed scanning steps
mcp-sentinel scan ./server --verbose

# Output shows:
# DEBUG Loaded config: mode=Quick, min_severity=Low, workers=4
# DEBUG Processing file: src/tools/file_access.py
# DEBUG Matched pattern: unsafe_file_read at line 42
```

**When to Use**:
- Scan not finding expected vulnerabilities
- Configuration not loading correctly
- Unexpected behavior or errors

---

### `--no-color`

Disable ANSI color codes in output.

**Why**: CI/CD logs, redirected output, terminals without color support.

**Example**:
```bash
# Plain text output for CI logs
mcp-sentinel scan ./server --no-color > scan.log

# Useful in:
# - Jenkins/GitLab CI logs (some don't support colors)
# - Redirected output to files
# - Accessibility tools (screen readers)
```

---

## Commands

## `scan` - Vulnerability Scanning

**Purpose**: Analyze MCP server code for security vulnerabilities.

**Syntax**:
```bash
mcp-sentinel scan <TARGET> [OPTIONS]
```

**Alias**: `s` (shorthand: `mcp-sentinel s ./server`)

**Why This Command Exists**: Core functionality - most common use case is one-time scans for vulnerability detection.

---

### Arguments

#### `<TARGET>`

Path to MCP server directory **or GitHub URL** to scan (Phase 2.5+).

**Why Required**: No sane default - user must explicitly specify what to scan.

**Supported Formats**:
1. **Local Directory**: `/path/to/mcp-server`
2. **GitHub URL**: `https://github.com/owner/repo` (Phase 2.5+)
   - With branch: `https://github.com/owner/repo/tree/branch-name`
   - With tag: `https://github.com/owner/repo/tree/v1.0.0`
   - With commit: `https://github.com/owner/repo/commit/abc123`

**Examples**:
```bash
# Scan local directory
mcp-sentinel scan .
mcp-sentinel scan ~/projects/my-mcp-server
mcp-sentinel scan ../backend/mcp-server

# Scan GitHub repository (Phase 2.5+)
mcp-sentinel scan https://github.com/owner/mcp-server

# Scan specific branch (Phase 2.5+)
mcp-sentinel scan https://github.com/owner/mcp-server/tree/develop

# Scan specific commit (Phase 2.5+)
mcp-sentinel scan https://github.com/owner/mcp-server/commit/abc123

# Scan specific tag (Phase 2.5+)
mcp-sentinel scan https://github.com/owner/mcp-server/tree/v2.0.0
```

**GitHub URL Scanning** (Phase 2.5):
- **How It Works**: Shallow clone (`--depth=1`) to temporary directory, scan, cleanup
- **Performance**: 3-5 seconds for clone + scan time
- **Requirements**: Git CLI must be installed
- **Cleanup**: Automatic (even on failure)
- **Privacy**: Clone happens locally, no data sent to MCP Sentinel servers

**Validation**:
- Local path: Must exist, be a directory, be readable (exit code 2 if not)
- GitHub URL: Must be valid GitHub URL, git must be available (exit code 2 if not)

---

### Scanning Options

#### `--mode <MODE>`

Scanning mode: `quick` (default) or `deep`.

**Why Two Modes**: Tradeoff between speed and thoroughness.

| Mode    | Speed     | Engines            | Use Case                      |
|---------|-----------|-------------------|-------------------------------|
| `quick` | ~10 sec   | Static analysis   | Local development, CI checks  |
| `deep`  | ~2-5 min  | Static + AI       | Pre-release, security audits  |

**Examples**:
```bash
# Quick scan (default) - pattern matching only
mcp-sentinel scan ./server
mcp-sentinel scan ./server --mode quick

# Deep scan - includes AI analysis
mcp-sentinel scan ./server --mode deep --llm-provider ollama
```

**Performance**:
- **Quick**: 1,000-5,000 files/second (pure regex + AST)
- **Deep**: 50-200 files/second (adds LLM API calls with 100-500ms latency)

**Why Quick is Default**: Most scans are in development where speed matters. Deep mode is opt-in for when thoroughness trumps speed.

---

#### `--llm-provider <PROVIDER>`

LLM provider for deep mode analysis.

**Options**: `openai`, `anthropic`, `gemini`, `ollama` (local)

**Why This Flag**: Different providers offer cost/speed/quality tradeoffs.

| Provider   | Cost/1K tokens | Speed      | Quality      | Privacy       |
|------------|---------------|------------|--------------|---------------|
| `ollama`   | FREE          | Fast       | Good         | Full (local)  |
| `openai`   | $0.01-0.03    | Very Fast  | Excellent    | Partial       |
| `anthropic`| $0.015-0.075  | Fast       | Excellent    | Partial       |
| `gemini`   | $0.001-0.015  | Fast       | Very Good    | Partial       |

**Examples**:
```bash
# Local Ollama (free, private)
mcp-sentinel scan ./server --mode deep --llm-provider ollama

# OpenAI GPT-4 (best quality, costs money)
mcp-sentinel scan ./server --mode deep --llm-provider openai

# Anthropic Claude 3 Opus (balanced)
mcp-sentinel scan ./server --mode deep --llm-provider anthropic

# Google Gemini (cheapest cloud option)
mcp-sentinel scan ./server --mode deep --llm-provider gemini
```

**Default**: If `--mode deep` specified without `--llm-provider`, defaults to `ollama` (assumes local installation).

**Authentication**: Uses `--llm-api-key` or `MCP_SENTINEL_API_KEY` environment variable (not needed for Ollama).

---

#### `--llm-model <MODEL>`

Specific model name to use (optional).

**Why This Flag**: Providers offer multiple models with different capabilities.

**Provider-Specific Models**:

```bash
# OpenAI
--llm-provider openai --llm-model gpt-4o          # Latest GPT-4 (best)
--llm-provider openai --llm-model gpt-4-turbo     # Faster GPT-4
--llm-provider openai --llm-model gpt-3.5-turbo   # Cheapest

# Anthropic
--llm-provider anthropic --llm-model claude-3-opus-20240229    # Highest quality
--llm-provider anthropic --llm-model claude-3-sonnet-20240229  # Balanced
--llm-provider anthropic --llm-model claude-3-haiku-20240307   # Fastest

# Google Gemini
--llm-provider gemini --llm-model gemini-1.5-pro   # Best quality
--llm-provider gemini --llm-model gemini-1.5-flash # Faster

# Ollama (local)
--llm-provider ollama --llm-model llama3.2:8b      # 8B parameter model
--llm-provider ollama --llm-model codestral:22b    # Code-specialized
--llm-provider ollama --llm-model qwen2.5-coder:7b # Alternative
```

**Defaults** (if not specified):
- `openai`: `gpt-4o`
- `anthropic`: `claude-3-sonnet-20240229` (balanced cost/quality)
- `gemini`: `gemini-1.5-pro`
- `ollama`: `llama3.2:8b`

**Example**:
```bash
# Use specific model for cost optimization
mcp-sentinel scan ./server --mode deep \
  --llm-provider openai \
  --llm-model gpt-3.5-turbo  # 10x cheaper than GPT-4
```

---

#### `--llm-api-key <KEY>`

API key for cloud LLM providers.

**Why This Flag**: Explicit authentication (alternative to environment variable).

**Examples**:
```bash
# Inline API key (not recommended - visible in shell history)
mcp-sentinel scan ./server --mode deep \
  --llm-provider openai \
  --llm-api-key sk-abc123...

# Better: Use environment variable
export MCP_SENTINEL_API_KEY=sk-abc123...
mcp-sentinel scan ./server --mode deep --llm-provider openai

# Or: Store in config file (~/.mcp-sentinel/config.yaml)
# api_keys:
#   openai: sk-abc123...
mcp-sentinel scan ./server --mode deep --llm-provider openai
```

**Priority Order**:
1. `--llm-api-key` flag (highest)
2. `MCP_SENTINEL_API_KEY` environment variable
3. Config file `~/.mcp-sentinel/config.yaml`
4. Error if none found (exit code 3)

**Security Note**: Never commit API keys to Git. Use environment variables or config files with proper permissions (chmod 600).

---

#### `--enable-semgrep`

Enable Semgrep integration for SAST analysis (Phase 2.5).

**Why This Flag**: Leverage 1000+ community Semgrep rules for broader vulnerability coverage beyond built-in pattern matching.

**Requirements**:
- Semgrep CLI must be installed (`pip install semgrep`)
- Gracefully degrades if not available (warning logged, scan continues)

**How It Works**:
1. Runs Semgrep CLI as external process
2. Applies security-focused rule filtering
3. Converts Semgrep findings to MCP Sentinel format
4. Merges with other detection results

**Examples**:
```bash
# Enable Semgrep integration
mcp-sentinel scan ./server --enable-semgrep

# Combine with deep mode and AI analysis
mcp-sentinel scan ./server --mode deep --enable-semgrep --llm-provider ollama

# CI/CD with multiple analysis engines
mcp-sentinel scan . --enable-semgrep --fail-on high --output sarif

# GitHub URL scanning with Semgrep
mcp-sentinel scan https://github.com/owner/mcp-server --enable-semgrep
```

**Performance**: Adds 5-15 seconds to scan time depending on codebase size (external process overhead).

**Rule Coverage**:
- Security patterns (injection, XSS, crypto issues)
- Best practices violations
- Language-specific vulnerabilities
- Automatically filtered to security-relevant rules only

**Environment Variables**:
- `SEMGREP_PATH`: Custom path to semgrep binary (default: searches PATH)
- `MCP_SENTINEL_SEMGREP_RULES`: Custom Semgrep rule configuration

---

### Output Options

#### `--output <FORMAT>` / `-o <FORMAT>`

Output format for scan results.

**Options**: `terminal` (default), `json`, `sarif`, `html`, `pdf`

**Why Multiple Formats**: Different consumers need different formats.

| Format     | Use Case                           | Consumer        |
|------------|------------------------------------|-----------------|
| `terminal` | Human-readable, colored output     | Developers      |
| `json`     | Machine-readable, structured data  | Scripts, tools  |
| `sarif`    | Static Analysis Results format     | GitHub, IDEs    |
| `html`     | Rich report with charts            | Reports, docs   |
| `pdf`      | Shareable audit reports            | Compliance      |

**Examples**:
```bash
# Default: Terminal output (colored, formatted)
mcp-sentinel scan ./server

# JSON for programmatic consumption
mcp-sentinel scan ./server --output json > report.json

# SARIF for GitHub code scanning
mcp-sentinel scan ./server --output sarif --output-file results.sarif

# HTML for stakeholder reports (Phase 2.5)
mcp-sentinel scan ./server --output html --output-file report.html

# PDF for compliance audits (Phase 3 - planned)
mcp-sentinel scan ./server --output pdf --output-file audit-report.pdf
```

**Terminal Output Example**:
```
🛡️  MCP Sentinel v2.0.0

📂 Scanning: ./server
⏱️  Scan completed in 2.3s

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SCAN RESULTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 CRITICAL (2)
🟠 HIGH (5)
🟡 MEDIUM (12)
🟢 LOW (3)

Total: 22 vulnerabilities found

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**JSON Output Structure**:
```json
{
  "summary": {
    "critical": 2,
    "high": 5,
    "medium": 12,
    "low": 3,
    "total": 22
  },
  "vulnerabilities": [
    {
      "id": "e8f3a2b1...",
      "type": "secrets_leakage",
      "severity": "critical",
      "location": {
        "file": "src/config.py",
        "line": 42,
        "column": 15
      },
      "description": "Hardcoded API key detected",
      "recommendation": "Use environment variables..."
    }
  ],
  "metadata": {
    "scan_duration_ms": 2341,
    "files_scanned": 156,
    "timestamp": "2025-10-26T12:34:56Z"
  }
}
```

**HTML Output** (Phase 2.5):

Interactive report with visual dashboards, perfect for stakeholders and security audits.

**Features**:
- **Risk Scoring**: 0-100 risk score with color-coded indicators
- **Interactive Cards**: Click to expand vulnerability details
- **Self-Contained**: Single HTML file with inline CSS/JavaScript (no external dependencies)
- **Professional Design**: Enterprise-ready for presentations and compliance audits
- **Filtering**: Client-side filtering by severity
- **Summary Statistics**: Visual breakdown of vulnerability counts

**Example Usage**:
```bash
# Generate HTML report
mcp-sentinel scan ./server --output html --output-file report.html

# Comprehensive scan with HTML output
mcp-sentinel scan ./server \
  --mode deep \
  --enable-semgrep \
  --llm-provider ollama \
  --output html \
  --output-file security-audit-2025-10-26.html

# GitHub URL scanning with HTML report
mcp-sentinel scan https://github.com/owner/mcp-server \
  --enable-semgrep \
  --output html \
  --output-file third-party-audit.html
```

**Report Structure**:
- Header with scan metadata (timestamp, target, duration)
- Risk score dashboard with visual indicator (green/yellow/orange/red)
- Severity breakdown chart (critical/high/medium/low counts)
- Expandable vulnerability cards with:
  - Severity badge
  - Vulnerability type and description
  - File location and line numbers
  - Impact assessment
  - Remediation recommendations
  - CWE/CVE references (if applicable)

**SARIF Output**: Conforms to [SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) for GitHub Code Scanning integration.

---

#### `--output-file <PATH>`

Save output to file instead of stdout.

**Why This Flag**: Persist results for later analysis, CI artifacts.

**Examples**:
```bash
# Save JSON report
mcp-sentinel scan ./server --output json --output-file report.json

# Save SARIF for GitHub upload
mcp-sentinel scan ./server --output sarif --output-file results.sarif

# CI/CD: Upload as artifact
mcp-sentinel scan ./server --output json --output-file scan-results.json
artifact upload scan-results.json
```

**Behavior**:
- Overwrites existing file (no prompt)
- Creates parent directories if needed
- Prints confirmation: `✅ Report saved to: report.json`
- Terminal format: Still prints to stdout, file option ignored (terminal is for humans)

---

### Filtering Options

#### `--severity <LEVEL>`

Minimum severity to report.

**Levels**: `low` (default), `medium`, `high`, `critical`

**Why This Flag**: Reduce noise by filtering low-priority issues.

**Examples**:
```bash
# Show all vulnerabilities (default)
mcp-sentinel scan ./server --severity low

# Show only medium and above (filter out low)
mcp-sentinel scan ./server --severity medium

# Show only critical issues
mcp-sentinel scan ./server --severity critical
```

**Use Cases**:
- **Development**: `--severity low` (see everything)
- **PR Checks**: `--severity medium` (focus on real issues)
- **Production**: `--severity high` (only serious problems)
- **Incident Response**: `--severity critical` (urgent only)

**Performance**: Filtering happens during scan (not post-processing), so higher thresholds = faster scans.

---

#### `--fail-on <LEVEL>`

Exit with code 1 if vulnerabilities at or above this level are found.

**Levels**: `low`, `medium`, `high`, `critical`

**Why This Flag**: Enable CI/CD pipeline quality gates.

**Examples**:
```bash
# Fail if ANY vulnerabilities found
mcp-sentinel scan ./server --fail-on low

# Fail only on medium or above (tolerate low-severity)
mcp-sentinel scan ./server --fail-on medium

# Fail only on critical (emergency stop)
mcp-sentinel scan ./server --fail-on critical
```

**CI/CD Integration**:
```yaml
# GitHub Actions
- name: Security Scan
  run: mcp-sentinel scan . --fail-on medium --output sarif --output-file results.sarif
  # Fails the build if medium+ vulnerabilities found

# GitLab CI
security_scan:
  script:
    - mcp-sentinel scan . --fail-on high
  allow_failure: false  # Block merge if scan fails
```

**Exit Code Behavior**:
| Result                                | Exit Code | CI Behavior  |
|---------------------------------------|-----------|--------------|
| No vulnerabilities                    | 0         | ✅ Pass      |
| Vulnerabilities below threshold       | 0         | ✅ Pass      |
| Vulnerabilities at/above threshold    | 1         | ❌ Fail      |
| Scan error (target not found)         | 2         | ❌ Fail      |
| Usage error (invalid arguments)       | 3         | ❌ Fail      |

**Example**:
```bash
# Scan with threshold
$ mcp-sentinel scan ./server --fail-on medium
🛡️  Found 2 critical, 3 high, 5 medium vulnerabilities
❌ Found vulnerabilities at or above Medium level
$ echo $?
1

# Below threshold = success
$ mcp-sentinel scan ./clean-server --fail-on medium
🛡️  Found 1 low vulnerability
✅ Scan completed successfully
$ echo $?
0
```

---

### Configuration Options

#### `--config <PATH>` / `-c <PATH>`

Path to custom configuration file.

**Why This Flag**: Per-project scan settings, team-wide configuration.

**Default Locations** (searched in order):
1. `--config` flag value
2. `.mcp-sentinel.yaml` (current directory)
3. `~/.mcp-sentinel/config.yaml` (user config)
4. Built-in defaults

**Example**:
```bash
# Use project-specific config
mcp-sentinel scan ./server --config .mcp-sentinel.yaml

# Use team-wide config
mcp-sentinel scan ./server --config /etc/mcp-sentinel/team-config.yaml
```

**Config File Format** (`.mcp-sentinel.yaml`):
```yaml
version: "1.0"

# Scan settings
mode: quick  # quick | deep
min_severity: low  # low | medium | high | critical
parallel_workers: 4  # Concurrent file processing

# LLM settings (for deep mode)
llm:
  provider: ollama  # ollama | openai | anthropic | gemini
  model: llama3.2:8b
  # api_key: sk-...  # Or use environment variable

# File patterns
include:
  - "**/*.py"
  - "**/*.ts"
  - "**/*.js"
exclude:
  - "node_modules/**"
  - "**/*.test.py"
  - "tests/**"

# Vulnerability detection
patterns:
  secrets:
    enabled: true
    confidence_threshold: 0.8
  unsafe_file_ops:
    enabled: true
  command_injection:
    enabled: true
```

**CLI Overrides**: CLI arguments take precedence over config file values.

```bash
# Config says mode=quick, but CLI overrides to deep
mcp-sentinel scan ./server --mode deep --config config.yaml
```

---

### Complete Scan Examples

**Basic Scan**:
```bash
# Quick scan with terminal output
mcp-sentinel scan ./server
```

**Development Workflow**:
```bash
# Show all issues, verbose logging
mcp-sentinel scan . --severity low --verbose
```

**Pre-Commit Hook**:
```bash
# Fail on medium+ issues, JSON output
mcp-sentinel scan . --fail-on medium --output json
```

**CI/CD Pipeline**:
```bash
# Deep scan, SARIF output, fail on high+
mcp-sentinel scan . \
  --mode deep \
  --llm-provider ollama \
  --fail-on high \
  --output sarif \
  --output-file results.sarif
```

**Security Audit**:
```bash
# Comprehensive scan with GPT-4
mcp-sentinel scan ./server \
  --mode deep \
  --llm-provider openai \
  --llm-model gpt-4o \
  --severity low \
  --output json \
  --output-file audit-report.json
```

**Cost-Optimized Cloud Scan**:
```bash
# Use cheapest model
mcp-sentinel scan ./server \
  --mode deep \
  --llm-provider gemini \
  --llm-model gemini-1.5-flash \
  --output json
```

---

## `proxy` - Runtime Monitoring

**Purpose**: Run as transparent MCP proxy to monitor live traffic and enforce guardrails.

**Syntax**:
```bash
mcp-sentinel proxy [OPTIONS]
```

**Why This Command**: Static analysis can't detect runtime-only vulnerabilities (e.g., malicious prompts, data exfiltration attempts, dynamic code execution).

**Architecture**:
```
Claude Desktop ──> MCP Sentinel Proxy ──> MCP Server
     (client)          (inspect)            (backend)
                          │
                          ├─> Analyze traffic
                          ├─> Apply guardrails
                          ├─> Log violations
                          └─> Block/Allow
```

---

### Proxy Options

#### `--config <PATH>` / `-c <PATH>`

MCP configuration file to proxy.

**Why**: Automatically discovers and proxies MCP servers from Claude Desktop config.

**Example**:
```bash
# Proxy Claude Desktop's MCP servers
mcp-sentinel proxy --config ~/.config/claude/claude_desktop_config.json

# Proxy custom MCP config
mcp-sentinel proxy --config ./mcp-config.json
```

**Config File Format** (Claude Desktop):
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "node",
      "args": ["/path/to/filesystem-server/index.js"]
    },
    "database": {
      "command": "python",
      "args": ["/path/to/db-server/main.py"]
    }
  }
}
```

**Proxy Behavior**: Sentinel intercepts connections to these servers transparently.

---

#### `--port <PORT>` / `-p <PORT>`

Proxy listen port.

**Default**: `8080`

**Why This Flag**: Avoid port conflicts, multi-proxy setups.

**Example**:
```bash
# Run on custom port
mcp-sentinel proxy --port 9000

# Multiple proxies (different servers)
mcp-sentinel proxy --config server1.json --port 8080 &
mcp-sentinel proxy --config server2.json --port 8081 &
```

---

#### `--guardrails <PATH>` / `-g <PATH>`

Path to custom guardrails rules (YAML).

**Why**: Define security policies for runtime enforcement.

**Example**:
```bash
# Apply custom guardrails
mcp-sentinel proxy --guardrails ./guardrails.yaml
```

**Guardrails File Format** (`guardrails.yaml`):
```yaml
version: "1.0"

rules:
  # Block access to sensitive paths
  - id: "block-sensitive-paths"
    type: "path_access"
    action: "block"
    patterns:
      - "/etc/passwd"
      - "/etc/shadow"
      - "~/.ssh/*"
    message: "Access to sensitive system files denied"

  # Rate limit file operations
  - id: "rate-limit-file-ops"
    type: "rate_limit"
    max_requests: 10
    window_seconds: 60
    action: "throttle"

  # Block SQL injection patterns
  - id: "sql-injection-prevention"
    type: "content_filter"
    patterns:
      - "(?i)(union|select|insert|update|delete).*from"
    action: "block"
    message: "Potential SQL injection detected"

  # Prompt injection detection
  - id: "prompt-injection"
    type: "ai_guardrail"
    action: "alert"
    llm_check: true
    message: "Potential prompt injection attempt"
```

---

#### `--log-traffic`

Log all MCP traffic to file.

**Why**: Audit trail, debugging, replay attacks.

**Example**:
```bash
# Enable traffic logging
mcp-sentinel proxy --log-traffic --log-file traffic.jsonl

# Logs every request/response pair in JSON Lines format
```

**Log Format** (JSON Lines):
```json
{"timestamp":"2025-10-26T12:34:56Z","direction":"request","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd"}}}
{"timestamp":"2025-10-26T12:34:56Z","direction":"response","status":"blocked","reason":"Sensitive path access denied"}
```

---

#### `--log-file <PATH>`

Traffic log file destination.

**Default**: `~/.mcp-sentinel/logs/proxy-traffic.jsonl`

**Example**:
```bash
# Custom log location
mcp-sentinel proxy --log-traffic --log-file /var/log/mcp-sentinel/traffic.log
```

---

#### `--block-on-risk <LEVEL>`

Block requests at or above risk level.

**Levels**: `low`, `medium`, `high`, `critical`

**Why**: Enforce security policy automatically.

**Example**:
```bash
# Block high-risk requests
mcp-sentinel proxy --block-on-risk high

# Behavior:
# - Low risk: Allow
# - Medium risk: Allow + Log
# - High risk: Block + Alert
# - Critical risk: Block + Alert + Webhook
```

---

#### `--alert-webhook <URL>`

Send alerts to webhook URL.

**Why**: Integrate with Slack, PagerDuty, email notifications.

**Example**:
```bash
# Send alerts to Slack
mcp-sentinel proxy --alert-webhook https://hooks.slack.com/services/T00/B00/xxx

# Alert payload (JSON POST):
{
  "timestamp": "2025-10-26T12:34:56Z",
  "risk_level": "high",
  "violation": "Sensitive path access",
  "details": {
    "method": "read_file",
    "path": "/etc/passwd",
    "blocked": true
  }
}
```

---

#### `--dashboard` / `-d`

Launch web dashboard for live monitoring.

**Why**: Visual monitoring, real-time statistics, team collaboration.

**Example**:
```bash
# Start proxy with dashboard
mcp-sentinel proxy --dashboard

# Opens dashboard at: http://localhost:8080/dashboard
```

**Dashboard Features**:
- Live traffic graph
- Request/response viewer
- Guardrail violations
- Risk score trends
- Export logs

---

### Complete Proxy Examples

**Basic Proxy**:
```bash
# Proxy Claude Desktop MCP servers
mcp-sentinel proxy --config ~/.config/claude/claude_desktop_config.json
```

**Production Deployment**:
```bash
# Full monitoring with alerts
mcp-sentinel proxy \
  --config production-mcp.json \
  --port 8080 \
  --guardrails ./guardrails.yaml \
  --log-traffic \
  --log-file /var/log/mcp-sentinel/traffic.jsonl \
  --block-on-risk high \
  --alert-webhook https://hooks.slack.com/services/xxx \
  --dashboard
```

**Development Proxy**:
```bash
# Log everything, no blocking
mcp-sentinel proxy \
  --config dev-mcp.json \
  --port 9000 \
  --log-traffic \
  --dashboard
```

---

## `monitor` - Continuous Scanning

**Purpose**: Watch directory for changes and automatically rescan.

**Syntax**:
```bash
mcp-sentinel monitor <TARGET> [OPTIONS]
```

**Why This Command**: Continuous security feedback during active development.

**Architecture**:
```
File Watcher (inotify/FSEvents)
      │
      ├─> Detect file change
      ├─> Wait for file stability (debounce)
      ├─> Run incremental scan
      ├─> Alert if new vulnerabilities
      └─> Update dashboard
```

---

### Monitor Options

#### `<TARGET>`

Path to MCP server directory to monitor.

**Required**.

**Example**:
```bash
# Monitor current project
mcp-sentinel monitor .

# Monitor specific directory
mcp-sentinel monitor ~/projects/mcp-server
```

---

#### `--interval <SECONDS>`

Rescan interval in seconds (for periodic rescans).

**Default**: `300` (5 minutes)

**Why**: Periodic rescans catch changes even if file watching fails.

**Example**:
```bash
# Rescan every 30 seconds (fast feedback)
mcp-sentinel monitor . --interval 30

# Rescan every hour (less frequent)
mcp-sentinel monitor . --interval 3600
```

---

#### `--watch` / `-w`

Enable file system watching (immediate rescans on change).

**Why**: Instant feedback when files are saved.

**Example**:
```bash
# Watch for file changes
mcp-sentinel monitor . --watch

# Behavior:
# 1. Developer saves file
# 2. Sentinel detects change immediately
# 3. Waits 500ms (debounce)
# 4. Runs incremental scan
# 5. Alerts if new issues
```

**Debouncing**: Multiple rapid changes trigger one scan (avoid scan storm).

---

#### `--daemon` / `-d`

Run as background daemon.

**Why**: Persistent monitoring without tying up terminal.

**Example**:
```bash
# Start daemon
mcp-sentinel monitor . --daemon --pid-file /var/run/mcp-sentinel.pid

# Check daemon status
ps aux | grep mcp-sentinel

# Stop daemon
kill $(cat /var/run/mcp-sentinel.pid)
```

---

#### `--pid-file <PATH>`

PID file location for daemon.

**Default**: `~/.mcp-sentinel/monitor.pid`

**Why**: Enable daemon management (stop, status check).

**Example**:
```bash
# Custom PID file
mcp-sentinel monitor . --daemon --pid-file /tmp/mcp-monitor.pid

# Stop daemon
kill $(cat /tmp/mcp-monitor.pid)
```

---

#### `--alert-on <LEVEL>`

Alert when vulnerabilities at or above level are found.

**Levels**: `low`, `medium`, `high`, `critical`

**Why**: Filter noise, focus on important issues.

**Example**:
```bash
# Alert only on high+ vulnerabilities
mcp-sentinel monitor . --watch --alert-on high

# Alerts sent via:
# - Desktop notification
# - System log
# - Webhook (if configured)
```

---

### Complete Monitor Examples

**Development Workflow**:
```bash
# Watch files, alert on medium+
mcp-sentinel monitor . --watch --alert-on medium
```

**Background Monitoring**:
```bash
# Run as daemon with periodic rescans
mcp-sentinel monitor ~/projects/mcp-server \
  --daemon \
  --interval 600 \
  --alert-on high \
  --pid-file /var/run/mcp-sentinel.pid
```

**CI/CD Pre-Push Hook**:
```bash
# Run quick scan before git push
mcp-sentinel monitor . --interval 0  # One-time scan
```

---

## `audit` - Comprehensive Analysis

**Purpose**: Run all security checks (static + AI + runtime if requested).

**Syntax**:
```bash
mcp-sentinel audit <TARGET> [OPTIONS]
```

**Why This Command**: Most thorough analysis for pre-release security audits.

**What It Does**:
1. Static analysis (all engines)
2. AI analysis (deep mode)
3. Configuration analysis
4. Dependency scanning
5. (Optional) Runtime analysis via temporary proxy

**Use Cases**:
- Pre-release security sign-off
- Quarterly security audits
- Compliance requirements (SOC2, ISO 27001)
- Third-party security reviews

---

### Audit Options

#### `<TARGET>`

Path to MCP server directory to audit.

**Required**.

---

#### `--include-proxy`

Include runtime analysis via temporary proxy.

**Why**: Detect runtime-only vulnerabilities.

**Example**:
```bash
# Full audit with runtime analysis
mcp-sentinel audit ./server --include-proxy --duration 600
```

**How It Works**:
1. Start temporary proxy
2. Manual testing period (user interacts with MCP server)
3. Proxy logs all traffic
4. Analyze traffic for vulnerabilities
5. Generate comprehensive report

---

#### `--duration <SECONDS>`

Proxy duration for runtime analysis.

**Default**: `300` (5 minutes)

**Why**: Give time for manual testing.

**Example**:
```bash
# 10-minute runtime analysis window
mcp-sentinel audit ./server --include-proxy --duration 600

# Output:
# 🛡️  Starting runtime analysis proxy...
# ⏱️  Test your MCP server for the next 10 minutes
# 📡 Proxy listening on: http://localhost:8080
# [waits 10 minutes]
# ✅ Runtime analysis complete
```

---

#### `--comprehensive` / `-c`

Enable maximum depth analysis (slower, more thorough).

**Why**: Find edge cases, low-confidence vulnerabilities.

**Example**:
```bash
# Maximum thoroughness
mcp-sentinel audit ./server --comprehensive

# Enables:
# - Deep AST analysis
# - Dataflow analysis
# - Symbolic execution
# - All AI models (ensemble)
# - Extended timeout (30min)
```

**Performance**: 10-100x slower than quick scan.

---

#### LLM Options

Same as `scan` command:
- `--llm-provider`
- `--llm-model`
- `--llm-api-key`

---

#### Output Options

Same as `scan` command:
- `--output`
- `--output-file`

---

### Complete Audit Examples

**Basic Audit**:
```bash
# Comprehensive static + AI analysis
mcp-sentinel audit ./server
```

**Full Audit with Runtime**:
```bash
# Include runtime analysis
mcp-sentinel audit ./server \
  --include-proxy \
  --duration 600 \
  --comprehensive \
  --llm-provider openai \
  --llm-model gpt-4o \
  --output json \
  --output-file audit-report.json
```

**Compliance Audit**:
```bash
# Generate PDF report for auditors
mcp-sentinel audit ./server \
  --comprehensive \
  --output pdf \
  --output-file SOC2-Security-Audit-2025-10.pdf
```

---

## `init` - Initialize Configuration

**Purpose**: Create default configuration file.

**Syntax**:
```bash
mcp-sentinel init [OPTIONS]
```

**Why This Command**: Bootstrap configuration, onboarding.

---

### Init Options

#### `--config-path <PATH>`

Config file location.

**Default**: `~/.mcp-sentinel/config.yaml`

**Example**:
```bash
# Initialize default config
mcp-sentinel init

# Initialize project-specific config
mcp-sentinel init --config-path .mcp-sentinel.yaml
```

**Generated Config**:
```yaml
version: "1.0"

# Default scan settings
mode: quick
min_severity: low
parallel_workers: 4

# LLM settings (for deep mode)
llm:
  provider: ollama
  model: llama3.2:8b

# File patterns
include:
  - "**/*.py"
  - "**/*.ts"
  - "**/*.js"
exclude:
  - "node_modules/**"
  - "**/*.test.*"
  - "tests/**"
  - ".git/**"

# Vulnerability detection
patterns:
  secrets:
    enabled: true
    confidence_threshold: 0.8
  unsafe_file_ops:
    enabled: true
  command_injection:
    enabled: true
  ssrf:
    enabled: true
  prompt_injection:
    enabled: true
```

---

## `whitelist` - Manage Trusted Items

**Purpose**: Maintain whitelist of trusted tools/servers to suppress false positives.

**Syntax**:
```bash
mcp-sentinel whitelist <SUBCOMMAND>
```

**Why This Command**: Reduce noise from known-safe code.

---

### Whitelist Subcommands

#### `add`

Add item to whitelist.

**Syntax**:
```bash
mcp-sentinel whitelist add <TYPE> <NAME> <HASH>
```

**Example**:
```bash
# Whitelist a tool
mcp-sentinel whitelist add tool file_reader abc123def456...

# Whitelist a server
mcp-sentinel whitelist add server filesystem-server xyz789abc...
```

**Hash Calculation**:
```bash
# Calculate hash of tool
sha256sum tool-implementation.py | cut -d' ' -f1
```

---

#### `remove`

Remove item from whitelist.

**Syntax**:
```bash
mcp-sentinel whitelist remove <HASH>
```

**Example**:
```bash
# Remove whitelisted item
mcp-sentinel whitelist remove abc123def456...
```

---

#### `list`

Show all whitelisted items.

**Example**:
```bash
$ mcp-sentinel whitelist list

Whitelisted Items:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Type    Name                Hash
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
tool    file_reader         abc123def456...
server  filesystem-server   xyz789abc...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total: 2 items
```

---

#### `export`

Export whitelist to JSON.

**Example**:
```bash
# Export for sharing with team
mcp-sentinel whitelist export whitelist.json
```

**Format**:
```json
{
  "version": "1.0",
  "items": [
    {
      "type": "tool",
      "name": "file_reader",
      "hash": "abc123def456...",
      "added": "2025-10-26T12:34:56Z"
    }
  ]
}
```

---

#### `import`

Import whitelist from JSON.

**Example**:
```bash
# Import team's whitelist
mcp-sentinel whitelist import whitelist.json
```

---

## `rules` - Manage Guardrails

**Purpose**: Manage runtime guardrails rules.

**Syntax**:
```bash
mcp-sentinel rules <SUBCOMMAND>
```

**Why This Command**: Validate, test, and manage security policies.

---

### Rules Subcommands

#### `validate`

Validate guardrails syntax.

**Syntax**:
```bash
mcp-sentinel rules validate <PATH>
```

**Example**:
```bash
# Check if rules are valid
$ mcp-sentinel rules validate guardrails.yaml

✅ Guardrails validation passed
   - 12 rules loaded
   - 0 errors
   - 0 warnings
```

---

#### `list`

List available rule templates.

**Example**:
```bash
$ mcp-sentinel rules list

Available Rule Templates:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Template              Description
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
sensitive-paths       Block access to system files
rate-limiting         Throttle excessive requests
sql-injection         Detect SQL injection patterns
prompt-injection      Detect prompt manipulation
data-exfiltration     Prevent large data transfers
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

#### `test`

Test rules against sample traffic.

**Syntax**:
```bash
mcp-sentinel rules test <RULES> <TRAFFIC>
```

**Example**:
```bash
# Test rules against traffic log
mcp-sentinel rules test guardrails.yaml traffic-sample.jsonl

# Output:
# ✅ 15/20 requests passed
# ❌ 5/20 requests blocked
#
# Blocked Requests:
# 1. read_file("/etc/passwd") - Rule: sensitive-paths
# 2. SQL query with UNION - Rule: sql-injection
# ...
```

---

## Exit Codes

MCP Sentinel uses semantic exit codes for CI/CD integration.

| Code | Meaning                          | Example Causes                        |
|------|----------------------------------|---------------------------------------|
| `0`  | Success                          | No vulnerabilities, or below threshold|
| `1`  | Vulnerabilities found            | Issues at or above `--fail-on` level |
| `2`  | Scan error                       | Target not found, permission denied  |
| `3`  | Usage error                      | Invalid arguments, missing API key   |

**Examples**:
```bash
# Success
$ mcp-sentinel scan ./clean-server
✅ No vulnerabilities found
$ echo $?
0

# Vulnerabilities found
$ mcp-sentinel scan ./vulnerable-server --fail-on medium
❌ Found 3 medium vulnerabilities
$ echo $?
1

# Scan error
$ mcp-sentinel scan /nonexistent
❌ Target path does not exist: '/nonexistent'
$ echo $?
2

# Usage error
$ mcp-sentinel scan ./server --mode deep --llm-provider openai
❌ Missing API key for OpenAI
$ echo $?
3
```

---

## Environment Variables

| Variable                     | Purpose                          | Example                  |
|------------------------------|----------------------------------|--------------------------|
| `MCP_SENTINEL_API_KEY`       | LLM provider API key             | `sk-abc123...`           |
| `MCP_SENTINEL_CONFIG`        | Default config file path         | `~/.mcp-sentinel/config` |
| `MCP_SENTINEL_LOG_LEVEL`     | Logging level                    | `debug`, `info`, `warn`  |
| `NO_COLOR`                   | Disable colored output           | `1`                      |
| `RUST_LOG`                   | Override tracing filter          | `mcp_sentinel=trace`     |

**Examples**:
```bash
# Set API key
export MCP_SENTINEL_API_KEY=sk-abc123...

# Enable debug logging
export MCP_SENTINEL_LOG_LEVEL=debug

# Disable colors
export NO_COLOR=1
```

---

## Configuration Files

### Location Priority

1. `--config <path>` (CLI flag)
2. `.mcp-sentinel.yaml` (current directory)
3. `~/.mcp-sentinel/config.yaml` (user config)
4. `/etc/mcp-sentinel/config.yaml` (system-wide)
5. Built-in defaults

---

### Config File Structure

**Full Example** (`.mcp-sentinel.yaml`):
```yaml
version: "1.0"

# Scan settings
mode: quick  # quick | deep
min_severity: low  # low | medium | high | critical
parallel_workers: 4  # Number of concurrent workers

# LLM settings (for deep mode)
llm:
  provider: ollama  # ollama | openai | anthropic | gemini
  model: llama3.2:8b
  api_key: ${MCP_SENTINEL_API_KEY}  # Environment variable
  max_tokens: 4096
  temperature: 0.0  # Deterministic
  timeout_seconds: 30

# File inclusion/exclusion
include:
  - "**/*.py"
  - "**/*.ts"
  - "**/*.js"
  - "**/*.go"
  - "**/*.rs"
exclude:
  - "node_modules/**"
  - "**/*.test.*"
  - "**/*.spec.*"
  - "tests/**"
  - ".git/**"
  - "__pycache__/**"
  - "*.pyc"

# Vulnerability detection patterns
patterns:
  # Secret detection
  secrets:
    enabled: true
    confidence_threshold: 0.8
    patterns:
      - name: "AWS Access Key"
        regex: 'AKIA[0-9A-Z]{16}'
      - name: "API Key"
        regex: 'api[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9_\-]{32,}'

  # File operation safety
  unsafe_file_ops:
    enabled: true
    check_path_traversal: true
    check_permissions: true

  # Command injection
  command_injection:
    enabled: true
    check_shell_execution: true

  # SSRF
  ssrf:
    enabled: true
    check_url_generation: true

  # Prompt injection
  prompt_injection:
    enabled: true
    use_ai_detection: true

# Output settings
output:
  default_format: terminal  # terminal | json | sarif
  color: auto  # auto | always | never

# Proxy settings (for runtime monitoring)
proxy:
  port: 8080
  log_traffic: false
  block_on_risk: high

# Monitoring settings
monitor:
  interval: 300  # seconds
  watch_enabled: true
  alert_on: medium
```

---

## Workflow Examples

### Local Development

```bash
# 1. Initialize config
mcp-sentinel init --config-path .mcp-sentinel.yaml

# 2. Quick scan during development
mcp-sentinel scan .

# 3. Watch for changes
mcp-sentinel monitor . --watch --alert-on medium

# 4. Pre-commit: Fail on medium+
mcp-sentinel scan . --fail-on medium
```

---

### CI/CD Pipeline

**GitHub Actions** (`.github/workflows/security.yml`):
```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install MCP Sentinel
        run: |
          wget https://github.com/mcpsentinel/mcp-sentinel/releases/latest/download/mcp-sentinel-linux-amd64
          chmod +x mcp-sentinel-linux-amd64
          sudo mv mcp-sentinel-linux-amd64 /usr/local/bin/mcp-sentinel

      - name: Security Scan
        run: |
          mcp-sentinel scan . \
            --fail-on medium \
            --output sarif \
            --output-file results.sarif

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

**GitLab CI** (`.gitlab-ci.yml`):
```yaml
security_scan:
  stage: test
  image: rust:latest
  script:
    - cargo install mcp-sentinel
    - mcp-sentinel scan . --fail-on high --output json --output-file report.json
  artifacts:
    reports:
      codequality: report.json
  allow_failure: false
```

---

### Pre-Release Audit

```bash
# 1. Comprehensive audit
mcp-sentinel audit ./server \
  --comprehensive \
  --include-proxy \
  --duration 600 \
  --llm-provider openai \
  --llm-model gpt-4o \
  --output json \
  --output-file audit-$(date +%Y%m%d).json

# 2. Generate PDF report for stakeholders
mcp-sentinel audit ./server \
  --output pdf \
  --output-file Security-Audit-Report.pdf

# 3. Review whitelist
mcp-sentinel whitelist list

# 4. Export whitelist for records
mcp-sentinel whitelist export whitelist-snapshot.json
```

---

### Production Monitoring

```bash
# 1. Start proxy with guardrails
mcp-sentinel proxy \
  --config production-mcp.json \
  --port 8080 \
  --guardrails production-guardrails.yaml \
  --log-traffic \
  --log-file /var/log/mcp-sentinel/traffic.jsonl \
  --block-on-risk high \
  --alert-webhook $SLACK_WEBHOOK \
  --dashboard

# 2. Start background monitor
mcp-sentinel monitor /opt/mcp-server \
  --daemon \
  --interval 600 \
  --alert-on high \
  --pid-file /var/run/mcp-sentinel.pid

# 3. View logs
tail -f /var/log/mcp-sentinel/traffic.jsonl | jq .
```

---

### Phase 2.5 Advanced Features

**Phase 2.5 introduces powerful enterprise capabilities**: Semantic analysis, SAST integration, HTML reporting, and GitHub URL scanning.

#### Multi-Engine Comprehensive Scan

Combine all Phase 2.5 features for maximum coverage:

```bash
# Local project with all engines
mcp-sentinel scan ./server \
  --mode deep \
  --enable-semgrep \
  --llm-provider ollama \
  --output html \
  --output-file comprehensive-audit.html
```

**What this does**:
- Tree-sitter semantic analysis (Python, JS, TS, Go)
- Semgrep SAST with 1000+ community rules
- AI-powered analysis via Ollama
- Professional HTML report with risk scoring

---

#### Third-Party Repository Audit

Scan GitHub repositories directly for security evaluation:

```bash
# Audit third-party MCP server before installing
mcp-sentinel scan https://github.com/vendor/mcp-server \
  --enable-semgrep \
  --severity medium \
  --output html \
  --output-file vendor-security-audit.html

# Scan specific release tag
mcp-sentinel scan https://github.com/vendor/mcp-server/tree/v1.2.3 \
  --enable-semgrep \
  --output json \
  --output-file vendor-v1.2.3-audit.json
```

**Use cases**:
- Evaluating third-party MCP servers before installation
- Auditing dependencies for supply chain security
- Compliance verification of external code
- Security due diligence for vendor selection

---

#### CI/CD with Phase 2.5 Features

**Enhanced GitHub Actions workflow**:

```yaml
name: Enhanced Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install dependencies
        run: |
          wget https://github.com/mcpsentinel/mcp-sentinel/releases/latest/download/mcp-sentinel-linux-amd64
          chmod +x mcp-sentinel-linux-amd64
          sudo mv mcp-sentinel-linux-amd64 /usr/local/bin/mcp-sentinel
          pip install semgrep

      - name: Multi-Engine Security Scan
        run: |
          mcp-sentinel scan . \
            --enable-semgrep \
            --fail-on high \
            --output sarif \
            --output-file results.sarif

      - name: Generate HTML Report
        if: always()
        run: |
          mcp-sentinel scan . \
            --enable-semgrep \
            --output html \
            --output-file security-report.html

      - name: Upload HTML Report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.html

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

---

#### Enterprise Security Dashboard

Generate executive-friendly HTML reports:

```bash
# Weekly security dashboard for stakeholders
mcp-sentinel scan ./production-server \
  --mode deep \
  --enable-semgrep \
  --llm-provider openai \
  --llm-model gpt-4o \
  --output html \
  --output-file weekly-security-dashboard-$(date +%Y-%m-%d).html

# Quarterly compliance audit
mcp-sentinel scan ./server \
  --enable-semgrep \
  --severity low \
  --output html \
  --output-file Q4-2025-Security-Audit.html
```

**Report features**:
- Risk score (0-100) with color-coded indicators
- Severity breakdown charts
- Vulnerability cards with full context
- Self-contained (works offline, no external dependencies)
- Professional design for presentations

---

#### GitHub URL Scanning Workflows

**Continuous dependency monitoring**:

```bash
#!/bin/bash
# monitor-dependencies.sh
# Scan all MCP server dependencies weekly

DEPENDENCIES=(
  "https://github.com/vendor-a/filesystem-mcp"
  "https://github.com/vendor-b/database-mcp"
  "https://github.com/vendor-c/api-mcp"
)

for repo in "${DEPENDENCIES[@]}"; do
  echo "Scanning $repo..."
  mcp-sentinel scan "$repo" \
    --enable-semgrep \
    --severity medium \
    --output json \
    --output-file "audit-$(basename $repo)-$(date +%Y%m%d).json"
done

# Aggregate results
jq -s 'map(.vulnerabilities) | add' audit-*.json > combined-vulnerabilities.json
```

**Pre-installation security check**:

```bash
# Before: npm install @modelcontextprotocol/server-filesystem
# Do: Security audit first

mcp-sentinel scan https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem \
  --enable-semgrep \
  --fail-on high \
  --output html \
  --output-file pre-install-audit.html

# Review report, then install if clean
```

---

#### Semgrep Integration Examples

**Custom Semgrep rules path**:

```bash
# Use organization's custom Semgrep rules
export MCP_SENTINEL_SEMGREP_RULES=/etc/security/semgrep-rules.yaml

mcp-sentinel scan ./server --enable-semgrep
```

**Semgrep + AI ensemble analysis**:

```bash
# Maximum coverage: Semgrep + AI + Tree-sitter
mcp-sentinel scan ./server \
  --mode deep \
  --enable-semgrep \
  --llm-provider anthropic \
  --llm-model claude-3-opus-20240229 \
  --severity low \
  --output json \
  --output-file maximum-coverage-audit.json
```

---

#### HTML Report Customization

**Generate reports for different audiences**:

```bash
# Developer-focused (all severities)
mcp-sentinel scan ./server \
  --enable-semgrep \
  --severity low \
  --output html \
  --output-file dev-full-report.html

# Executive summary (critical/high only)
mcp-sentinel scan ./server \
  --enable-semgrep \
  --severity high \
  --output html \
  --output-file executive-summary.html

# Compliance audit (with AI verification)
mcp-sentinel scan ./server \
  --mode deep \
  --enable-semgrep \
  --llm-provider openai \
  --output html \
  --output-file compliance-audit-$(date +%Y-%m-%d).html
```

---

#### Semantic Analysis Use Cases

Tree-sitter semantic analysis automatically activates for supported languages (Python, JavaScript, TypeScript, Go):

```bash
# Deep semantic analysis for Python MCP server
mcp-sentinel scan ./python-mcp-server \
  --mode deep \
  --llm-provider ollama \
  --output html \
  --output-file python-semantic-audit.html

# TypeScript MCP server with full analysis
mcp-sentinel scan ./typescript-mcp-server \
  --enable-semgrep \
  --output html \
  --output-file typescript-audit.html
```

**What semantic analysis detects**:
- Dataflow vulnerabilities (taint analysis)
- SQL injection in query builders
- Path traversal in file operations
- Unsafe deserialization
- Command injection patterns
- Context-aware security issues

---

### Performance Benchmarks (Phase 2.5)

| Feature Combination | Scan Time (1000 files) | Vulnerability Coverage |
|---------------------|------------------------|------------------------|
| Quick mode only | ~10 seconds | Baseline (100%) |
| + Semgrep | ~25 seconds | +40% coverage |
| + Semantic analysis | ~15 seconds | +25% coverage |
| + AI (Ollama) | ~2 minutes | +60% coverage |
| All features | ~3 minutes | +85% coverage |

**Recommendation**: Use `--enable-semgrep` by default in CI/CD for best coverage/speed tradeoff.

---

## Troubleshooting

### Common Issues

#### "Target path does not exist"

**Cause**: Invalid path provided to `scan` or `monitor`.

**Solution**:
```bash
# Check path exists
ls -la ./server

# Use absolute path
mcp-sentinel scan $(pwd)/server
```

---

#### "Missing API key for OpenAI"

**Cause**: Deep mode requires API key for cloud providers.

**Solution**:
```bash
# Set environment variable
export MCP_SENTINEL_API_KEY=sk-abc123...

# Or use flag
mcp-sentinel scan . --mode deep --llm-api-key sk-abc123...

# Or use local provider (no key needed)
mcp-sentinel scan . --mode deep --llm-provider ollama
```

---

#### "Ollama connection refused"

**Cause**: Ollama not running on localhost:11434.

**Solution**:
```bash
# Start Ollama
ollama serve

# Or specify custom endpoint
export OLLAMA_HOST=http://remote-server:11434
```

---

#### "Permission denied" errors

**Cause**: Insufficient permissions to read target files.

**Solution**:
```bash
# Check permissions
ls -la ./server

# Run with appropriate permissions
sudo mcp-sentinel scan ./server  # Not recommended

# Or fix permissions
chmod -R u+r ./server
```

---

#### Scan is too slow

**Causes**:
1. Deep mode with cloud LLM (network latency)
2. Large codebase
3. Too many workers

**Solutions**:
```bash
# 1. Use quick mode
mcp-sentinel scan . --mode quick  # 10-100x faster

# 2. Use local LLM
mcp-sentinel scan . --mode deep --llm-provider ollama

# 3. Reduce workers
mcp-sentinel scan . --config config.yaml  # Set parallel_workers: 2

# 4. Exclude unnecessary files
# Add to .mcp-sentinel.yaml:
# exclude:
#   - "docs/**"
#   - "examples/**"
```

---

#### False positives

**Solution 1**: Adjust confidence threshold
```yaml
# .mcp-sentinel.yaml
patterns:
  secrets:
    confidence_threshold: 0.9  # Higher = fewer false positives
```

**Solution 2**: Use whitelist
```bash
# Whitelist known-safe code
mcp-sentinel whitelist add tool safe_tool abc123...
```

**Solution 3**: Use severity filter
```bash
# Hide low-severity issues
mcp-sentinel scan . --severity medium
```

---

### Debug Mode

```bash
# Enable verbose logging
mcp-sentinel scan . --verbose

# Full trace logging
export RUST_LOG=mcp_sentinel=trace
mcp-sentinel scan .

# Check config loading
mcp-sentinel scan . --verbose --config .mcp-sentinel.yaml 2>&1 | grep -i config
```

---

### Getting Help

```bash
# General help
mcp-sentinel --help

# Command-specific help
mcp-sentinel scan --help
mcp-sentinel proxy --help

# Version info
mcp-sentinel --version

# File bug reports
# https://github.com/mcpsentinel/mcp-sentinel/issues
```

---

## Summary

**Key Takeaways**:

1. **`scan`**: Primary command for vulnerability detection (quick or deep)
2. **`proxy`**: Runtime monitoring with guardrails enforcement
3. **`monitor`**: Continuous scanning with file watching
4. **`audit`**: Most comprehensive analysis (static + AI + runtime)
5. **Exit Codes**: Enable CI/CD integration (`--fail-on` threshold)
6. **Output Formats**: Terminal (human), JSON (machine), SARIF (GitHub)
7. **LLM Providers**: Ollama (free/local), OpenAI, Anthropic, Gemini
8. **Configuration**: YAML files with CLI override capability

**Quick Reference**:
```bash
# Quick scan
mcp-sentinel scan .

# Deep scan (AI)
mcp-sentinel scan . --mode deep --llm-provider ollama

# CI/CD scan
mcp-sentinel scan . --fail-on medium --output sarif

# Runtime monitoring
mcp-sentinel proxy --config mcp.json --dashboard

# Continuous scanning
mcp-sentinel monitor . --watch --alert-on high

# Full audit
mcp-sentinel audit . --comprehensive
```

For more information, see:
- [Architecture Documentation](./ARCHITECTURE.md)
- [GitHub Repository](https://github.com/mcpsentinel/mcp-sentinel)
- [Issue Tracker](https://github.com/mcpsentinel/mcp-sentinel/issues)
