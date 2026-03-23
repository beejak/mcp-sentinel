# MCP Sentinel User Guide

**Version**: 0.2.0
**Last Updated**: 2026-03-23

MCP Sentinel is a static security scanner for MCP servers. Pattern-based detection, no external binaries, no network calls, no data leaves your machine.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [Detectors Reference](#detectors-reference)
5. [Output Formats](#output-formats)
6. [Severity Filtering](#severity-filtering)
7. [Configuration](#configuration)
8. [Integration with CI/CD](#integration-with-cicd)
9. [Programmatic Usage](#programmatic-usage)
10. [Troubleshooting](#troubleshooting)
11. [FAQ](#faq)

---

## Quick Start

```bash
# Install from source
git clone https://github.com/beejak/mcp-sentinel.git
cd mcp-sentinel
pip install -e .

# Scan a directory
mcp-sentinel scan /path/to/your/mcp-server

# Scan current directory, show only critical and high
mcp-sentinel scan . --severity critical --severity high

# Export SARIF for GitHub Code Scanning
mcp-sentinel scan . --output sarif --json-file results.sarif

# Export JSON
mcp-sentinel scan . --output json --json-file results.json
```

---

## Installation

### Prerequisites

- Python 3.11+
- pip

### From Source

```bash
git clone https://github.com/beejak/mcp-sentinel.git
cd mcp-sentinel
pip install -e .

# Or with dev dependencies
pip install -e ".[dev]"
```

### Verify Installation

```bash
mcp-sentinel --version
mcp-sentinel --help
```

---

## Basic Usage

### Scan a Directory

```bash
# Scan the current directory
mcp-sentinel scan .

# Scan a specific path
mcp-sentinel scan /path/to/mcp-server

# Suppress progress bar (useful in scripts)
mcp-sentinel scan . --no-progress
```

### Understanding the Output

When you run a scan, MCP Sentinel:

1. **Discovers files** — Python, JavaScript, TypeScript, Go, Java, YAML, JSON, config files
2. **Runs 9 detectors** — each applicable to the file type being scanned
3. **Generates a report** — severity breakdown, per-finding details, code snippets, remediation guidance

**Terminal output includes:**
- Scan summary (files scanned, vulnerabilities found, duration)
- Severity breakdown (Critical, High, Medium, Low, Info)
- Detailed findings with file:line locations and code snippets
- Risk score (0–100 scale, weighted by severity and confidence)

---

## Detectors Reference

Nine detectors run against each file. Each detector is scoped to applicable file types (e.g., `NetworkBindingDetector` also runs against `.env` and YAML config files).

### SecretsDetector
Hardcoded credentials — AWS keys, AI provider keys (`sk-...`), GitHub tokens (`ghp_`), JWT tokens, private key PEM blocks, database connection strings with embedded passwords.

### CodeInjectionDetector
Command and code execution sinks: `os.system()`, `subprocess(shell=True)`, `eval()`, `exec()`, `child_process.exec()`, SQL string formatting with f-strings.

Uses Python stdlib `ast` for multi-line `subprocess(shell=True)` detection (no external dependencies).

### PromptInjectionDetector
Embedded instructions that manipulate agent behavior: role reassignment (`"you are now"`), jailbreak phrases (`"DAN mode"`, `"developer mode"`), override directives (`"ignore previous instructions"`).

### ToolPoisoningDetector
Malicious content in MCP tool schemas targeting AI agents:

| Category | Description |
|---|---|
| Invisible Unicode | 17 character types (zero-width spaces, RTLO, Hangul filler) |
| Sensitive path targeting | `.env`, `.ssh/`, `~/.aws/credentials`, `/etc/passwd`, `id_rsa` → **CRITICAL** |
| Behavior overrides | `ignore previous`, `override instructions`, `[hidden]`, `[secret]` |
| Cross-tool manipulation | "before calling", "global rule", "always call this tool first" |
| Suspicious tool names | `always_run_first`, `override_*`, `hijack`, `__*__` |
| Suspicious param names | `__instruction__`, `system_prompt`, `ai_directive` |
| Anomalous description length | >500 chars → potential payload embedding |

### PathTraversalDetector
Directory traversal: `../` sequences, URL-encoded variants (`%2e%2e%2f`), `zipfile.extractall()` without path validation (Zip Slip), `open()` with unvalidated filename arguments.

### ConfigSecurityDetector
Insecure configuration values: `DEBUG=True`, `CORS_ORIGINS=*`, `SSL_VERIFY=False`, weak secret keys, exposed admin/debug endpoints.

### SSRFDetector _(v0.2)_
Server-side request forgery sinks:

| Pattern | Language | Severity |
|---|---|---|
| `requests.get(url)` with variable | Python | HIGH |
| `fetch(userUrl)` / `axios.get(endpoint)` | JavaScript/TypeScript | HIGH |
| `169.254.169.254` / `metadata.google.internal` | Any | CRITICAL |
| `redirect_uri`, `callback_url` parameters | Any | MEDIUM |
| `http.Get(url)` / `http.NewRequest(..., url, ...)` | Go | HIGH |
| `new URL(var).openConnection()` | Java | HIGH |

### NetworkBindingDetector _(v0.2)_
Servers binding to `0.0.0.0` instead of `127.0.0.1`. Covers Python, JavaScript, Go (`net.Listen(":port")` shorthand also binds to all interfaces), Java, and config files (`.env`, YAML, TOML, ini).

### MissingAuthDetector _(v0.2)_
Routes and endpoints without authentication. Uses a ±5/3-line lookback/lookahead window:

| Pattern | Severity |
|---|---|
| Flask/FastAPI route without `@login_required`/`Depends(...)` | MEDIUM |
| Route with `/admin`, `/debug`, `/internal` path, no auth | HIGH |
| Express route without auth middleware | MEDIUM |
| MCP tool exposing `exec`/`shell`/`system` operation | HIGH |

> **Note:** Global auth middleware applied to all routes at the app level will not be detected statically. These findings are expected to be reviewed and suppressed where appropriate.

---

## Output Formats

### Terminal (default)

```bash
mcp-sentinel scan .
```

Rich-colored table output with severity-coded rows, code snippets, and remediation hints. Best for interactive use and debugging.

### JSON

```bash
mcp-sentinel scan . --output json --json-file results.json
```

Structured export of all findings. Includes metadata, risk scores, MITRE ATT&CK IDs, CWE IDs, and remediation steps. Best for CI/CD pipelines and programmatic processing.

**Structure:**
```json
{
  "target": "/path/to/project",
  "status": "completed",
  "vulnerabilities": [...],
  "statistics": {
    "total_files": 42,
    "scanned_files": 42,
    "total_vulnerabilities": 5,
    "critical_count": 1,
    "high_count": 2,
    "medium_count": 2,
    "low_count": 0
  }
}
```

### SARIF 2.1.0

```bash
mcp-sentinel scan . --output sarif --json-file results.sarif
```

OASIS SARIF 2.1.0 format. Compatible with GitHub Code Scanning, Azure DevOps, and GitLab SAST. Upload to GitHub Security tab for in-PR annotation.

**Upload to GitHub Code Scanning:**
```bash
mcp-sentinel scan . --output sarif --json-file results.sarif
gh api repos/{owner}/{repo}/code-scanning/sarifs -F sarif=@results.sarif
```

---

## Severity Filtering

```bash
# Critical only
mcp-sentinel scan . --severity critical

# Critical and high
mcp-sentinel scan . --severity critical --severity high

# Everything except info
mcp-sentinel scan . --severity critical --severity high --severity medium --severity low
```

**Severity levels:**
| Level | CVSS range | Meaning |
|---|---|---|
| CRITICAL | 9.0–10.0 | Immediate action required — hardcoded secrets, cloud metadata references, sensitive path targeting |
| HIGH | 7.0–8.9 | Serious vulnerability — code injection, SSRF, missing auth on sensitive routes |
| MEDIUM | 4.0–6.9 | Important issue — open CORS, 0.0.0.0 binding, redirect params without validation |
| LOW | 0.1–3.9 | Best practice violation |
| INFO | 0.0 | Informational |

---

## Configuration

Environment variables (can also be set in a `.env` file in the project root):

| Variable | Default | Description |
|---|---|---|
| `ENABLE_STATIC_ANALYSIS` | `true` | Enable/disable the static analysis engine |
| `LOG_LEVEL` | `info` | Verbosity: debug, info, warning, error |
| `MAX_WORKERS` | `4` | Concurrent file scanning workers |
| `CACHE_TTL` | `3600` | Scan result cache TTL in seconds |
| `ENVIRONMENT` | `development` | Environment label |

---

## Integration with CI/CD

### GitHub Actions (recommended)

```yaml
name: MCP Sentinel Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install MCP Sentinel
        run: pip install -e .

      - name: Run scan (SARIF)
        run: mcp-sentinel scan . --output sarif --json-file results.sarif

      - name: Upload to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
        if: always()

      - name: Fail build on critical findings
        run: mcp-sentinel scan . --severity critical --no-progress
```

### GitLab CI

```yaml
security_scan:
  image: python:3.11
  stage: test
  before_script:
    - pip install -e .
  script:
    - mcp-sentinel scan . --output json --json-file gl-security-report.json
  artifacts:
    reports:
      security: gl-security-report.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install -e .'
                sh 'mcp-sentinel scan . --output json --json-file security-report.json'
                archiveArtifacts artifacts: 'security-report.json'
            }
        }
    }
}
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: mcp-sentinel
        name: MCP Sentinel Security Scan
        entry: mcp-sentinel scan
        args: ['--severity', 'critical', '--severity', 'high', '--no-progress']
        language: system
        pass_filenames: false
```

---

## Programmatic Usage

```python
import asyncio
from pathlib import Path
from mcp_sentinel.core import MultiEngineScanner
from mcp_sentinel.engines.base import EngineType
from mcp_sentinel.reporting.generators import SARIFGenerator

async def scan_project():
    scanner = MultiEngineScanner(enabled_engines={EngineType.STATIC})
    result = await scanner.scan_directory("/path/to/project")

    # Export SARIF
    sarif_gen = SARIFGenerator()
    sarif_gen.save_to_file(result, Path("results.sarif"))

    if result.has_critical_findings():
        print(f"Found {result.statistics.critical_count} critical issues!")
        return 1
    return 0

exit_code = asyncio.run(scan_project())
```

Or use individual detectors directly:

```python
import asyncio
from pathlib import Path
from mcp_sentinel.detectors.ssrf import SSRFDetector

async def check_file():
    detector = SSRFDetector()
    content = Path("tool.py").read_text()
    vulns = await detector.detect(Path("tool.py"), content)
    for v in vulns:
        print(f"{v.severity.value.upper()} {v.title} @ line {v.line_number}")

asyncio.run(check_file())
```

---

## Troubleshooting

### "No vulnerabilities found" when you expect some

- Files may be in excluded directories (`node_modules`, `.git`, `venv`, `__pycache__`)
- The file type may not be in the default scan patterns
- The specific pattern variant you have may not be covered yet

Check which files are being discovered:
```bash
mcp-sentinel scan . --no-progress 2>&1 | grep "Files Scanned"
```

### MissingAuthDetector produces false positives for routes covered by global middleware

This is expected. Global middleware applied at the app level cannot be detected statically. Review the findings in context and treat them as informational for fully-authenticated applications.

### Scan is slow on large repositories

```bash
# Reduce workers
MAX_WORKERS=2 mcp-sentinel scan .

# Scan a subdirectory
mcp-sentinel scan src/
```

### Getting Help

- **Issues:** https://github.com/beejak/mcp-sentinel/issues
- **Docs:** https://github.com/beejak/mcp-sentinel/tree/main/docs

---

## FAQ

### What vulnerabilities does MCP Sentinel detect?

Nine detector categories:

1. **Secrets** — hardcoded API keys, tokens, database credentials
2. **Code Injection** — shell execution, eval, SQL injection
3. **Prompt Injection** — instructions manipulating agent behavior
4. **Tool Poisoning** — malicious content in MCP tool schemas (full-schema, Unicode, path targeting)
5. **Path Traversal** — directory traversal, Zip Slip
6. **Config Security** — debug mode, open CORS, TLS disabled, weak secrets
7. **SSRF** — unvalidated URL arguments, cloud metadata endpoint references
8. **Network Binding** — servers bound to 0.0.0.0 instead of 127.0.0.1
9. **Missing Auth** — routes without authentication decorators or middleware

### How accurate is detection?

- Pattern-based detection with context filtering (false-positive suppression)
- Test coverage: 86% overall, up to 97% for some detectors
- Confidence levels (HIGH/MEDIUM/LOW) are set per-finding to communicate certainty
- MissingAuthDetector uses MEDIUM confidence because global middleware cannot be detected statically

### Does MCP Sentinel make network calls or send my code anywhere?

No. All analysis runs locally. No network calls are made. No data leaves your machine.

### Can I use this in commercial projects?

Yes. MIT licensed — commercial use, modification, and distribution are all permitted.

### What's the difference between v0.1 and v0.2?

v0.2 added three MCP-specific detectors (SSRF, network binding, missing auth) and enhanced the tool poisoning detector with full-schema poisoning coverage — all grounded in documented 2025–2026 MCP CVEs and security research. Test count: 248 → 334.

### What's coming next?

**v0.3** — Supply chain detector rebuild: exfiltration patterns in non-network tools, npm `postinstall` shell execution, PyPI typosquatting, encoded payload detection (`eval(atob(...))`).

See [ROADMAP.md](../ROADMAP.md) for the full roadmap.

---

**Happy Scanning.**

For more documentation, see the [docs/](.) directory.
