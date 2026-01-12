# MCP Sentinel User Guide

**Version**: 3.0.0
**Last Updated**: 2026-01-07
**Status**: Phase 3 Complete - Enterprise Ready

Welcome to MCP Sentinel! This guide will help you get started with scanning your MCP servers for security vulnerabilities.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [Output Formats](#output-formats)
5. [Advanced Features](#advanced-features)
6. [Configuration](#configuration)
7. [Integration with CI/CD](#integration-with-cicd)
8. [Docker Deployment](#docker-deployment)
9. [Troubleshooting](#troubleshooting)
10. [FAQ](#faq)

---

## Quick Start

### Install and Run Your First Scan

```bash
# Install with pip
pip install mcp-sentinel

# Run a basic scan
mcp-sentinel scan /path/to/your/project

# Generate an HTML report
mcp-sentinel scan /path/to/your/project --output html --json-file report.html
```

That's it! You now have a comprehensive security report for your MCP server.

---

## Installation

### Prerequisites

- **Python 3.11+** (we use modern Python features)
- **pip** or **Poetry** for package management

### Option 1: Install from PyPI (Recommended)

```bash
pip install mcp-sentinel
```

### Option 2: Install from Source

```bash
# Clone the repository
git clone https://github.com/beejak/mcp-sentinel.git
cd mcp-sentinel/mcp-sentinel-python

# Install with Poetry
poetry install

# Or install with pip
pip install -e .
```

### Option 3: Use Docker

```bash
# Pull the image (when available)
docker pull mcp-sentinel/scanner:latest

# Or build locally
docker build -t mcp-sentinel .
```

### Verify Installation

```bash
mcp-sentinel --version
# Output: mcp-sentinel, version 3.0.0

mcp-sentinel --help
# Shows all available commands
```

---

## Basic Usage

### Scanning a Directory

```bash
# Scan current directory
mcp-sentinel scan .

# Scan a specific directory
mcp-sentinel scan /path/to/mcp/server

# Scan with progress disabled (CI/CD)
mcp-sentinel scan . --no-progress
```

### Understanding the Output

When you run a scan, MCP Sentinel will:

1. **Discover Files**: Finds all relevant code files (Python, JavaScript, TypeScript, etc.)
2. **Run Detectors**: Applies 8 specialized security detectors
3. **Generate Report**: Creates a summary with findings organized by severity

**Terminal Output Includes:**
- Scan summary (files scanned, vulnerabilities found, duration)
- Severity breakdown (Critical, High, Medium, Low, Info)
- Detailed findings with file locations and code snippets
- Risk score (0-100 scale)

---

## Output Formats

MCP Sentinel supports 4 professional output formats:

### 1. Terminal Output (Default)

```bash
mcp-sentinel scan /path/to/project
```

**Features:**
- Rich colored output with tables
- Progress tracking with spinner
- Severity-based color coding
- Code snippet previews

**Best for:** Quick scans, debugging, development

### 2. JSON Format

```bash
mcp-sentinel scan /path/to/project --output json --json-file results.json
```

**Features:**
- Structured data format
- Machine-readable
- Comprehensive vulnerability details
- Scan statistics and metadata

**Best for:** CI/CD pipelines, automation, tooling integration

**JSON Structure:**
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
    ...
  }
}
```

### 3. SARIF 2.1.0 Format (GitHub Code Scanning)

```bash
mcp-sentinel scan /path/to/project --output sarif --json-file results.sarif
```

**Features:**
- Industry-standard format (OASIS SARIF 2.1.0)
- GitHub Code Scanning compatible
- IDE integration ready
- Full location mapping
- Rule definitions included

**Best for:** GitHub Code Scanning, IDE integration, tool interoperability

**Upload to GitHub:**
```bash
# Generate SARIF
mcp-sentinel scan . --output sarif --json-file results.sarif

# Upload to GitHub Code Scanning
gh api repos/{owner}/{repo}/code-scanning/sarifs -F sarif=@results.sarif
```

### 4. HTML Interactive Reports

```bash
mcp-sentinel scan /path/to/project --output html --json-file report.html
```

**Features:**
- Executive dashboard with key metrics
- Risk score visualization
- Animated severity breakdown charts
- Detailed findings with code highlighting
- Self-contained (no external dependencies)
- Professional styling
- Shareable (just send the HTML file)

**Best for:** Executive summaries, team sharing, stakeholder presentations

**Open the Report:**
```bash
# Open in browser
open report.html  # macOS
xdg-open report.html  # Linux
start report.html  # Windows
```

---

## Advanced Features

### Severity Filtering

Filter scan results by severity level:

```bash
# Show only critical vulnerabilities
mcp-sentinel scan . --severity critical

# Show critical and high severity
mcp-sentinel scan . --severity critical --severity high

# Combine with HTML output
mcp-sentinel scan . --severity critical --severity high --output html --json-file critical-issues.html
```

**Severity Levels:**
- **CRITICAL**: Immediate action required (hardcoded secrets, RCE)
- **HIGH**: Serious vulnerabilities (SQL injection, XSS)
- **MEDIUM**: Important issues (missing headers, weak config)
- **LOW**: Minor concerns (best practice violations)
- **INFO**: Informational findings

### Multi-Engine Scanning (Phase 4+)

```bash
# Use specific engines (Phase 4 feature - coming soon)
mcp-sentinel scan . --engines static,sast

# Use all available engines
mcp-sentinel scan . --engines all
```

**Available Engines (Phase 4+):**
- `static` - Pattern-based detection (available now)
- `semantic` - AST and dataflow analysis (Phase 4)
- `sast` - Semgrep + Bandit integration (Phase 4)
- `ai` - AI-powered analysis (Phase 4)

### Programmatic Usage

Use MCP Sentinel in your Python scripts:

```python
import asyncio
from pathlib import Path
from mcp_sentinel.core import MultiEngineScanner
from mcp_sentinel.engines.base import EngineType
from mcp_sentinel.reporting.generators import HTMLGenerator, SARIFGenerator

async def scan_project():
    # Initialize scanner
    scanner = MultiEngineScanner(
        enabled_engines={EngineType.STATIC}
    )

    # Run scan
    result = await scanner.scan_directory("/path/to/project")

    # Generate reports
    html_gen = HTMLGenerator()
    html_gen.save_to_file(result, Path("report.html"))

    sarif_gen = SARIFGenerator()
    sarif_gen.save_to_file(result, Path("results.sarif"))

    # Check results
    if result.has_critical_findings():
        print(f"⚠️  Found {result.statistics.critical_count} critical issues!")
        return 1

    print("✅ No critical issues found")
    return 0

# Run the scan
exit_code = asyncio.run(scan_project())
```

---

## Configuration

### Configuration File

Create a `.mcp-sentinel.yaml` file in your project root:

```bash
# Generate default config
mcp-sentinel init
```

**Example Configuration:**

```yaml
# MCP Sentinel Configuration

# Analysis engines (Phase 3: static only)
engines:
  static: true           # ✅ Available now
  semantic: false        # 🚧 Phase 4
  sast: false            # 🚧 Phase 4
  ai: false              # 🚧 Phase 4

# Report generation
reporting:
  formats: [terminal, html, sarif]
  output_dir: ./reports

  terminal:
    colored: true
    show_code_snippets: true

  html:
    include_executive_summary: true
    show_risk_score: true
    animated_charts: true

  sarif:
    github_code_scanning: true
    include_fixes: true

# Scanning configuration
scan:
  min_severity: low

  include_patterns:
    - "**/*.py"
    - "**/*.js"
    - "**/*.ts"
    - "**/*.go"
    - "**/*.java"

  exclude_patterns:
    - "**/node_modules/**"
    - "**/.git/**"
    - "**/__pycache__/**"
    - "**/venv/**"
    - "**/dist/**"

# Performance
performance:
  max_workers: 10
  cache_enabled: true
  parallel_execution: true
  timeout_seconds: 300
```

### Environment Variables

Configure MCP Sentinel with environment variables:

```bash
# AI Provider Configuration (Phase 4+)
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
export GOOGLE_API_KEY=...

# Logging
export MCP_SENTINEL_LOG_LEVEL=info  # debug, info, warning, error

# Output
export MCP_SENTINEL_OUTPUT_DIR=./reports
```

---

## Integration with CI/CD

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install MCP Sentinel
        run: pip install mcp-sentinel

      - name: Run Security Scan
        run: |
          mcp-sentinel scan . --output sarif --json-file results.sarif

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif

      - name: Fail on Critical Issues
        run: |
          mcp-sentinel scan . --severity critical --no-progress
```

### GitLab CI

```yaml
security_scan:
  image: python:3.11
  stage: test

  before_script:
    - pip install mcp-sentinel

  script:
    - mcp-sentinel scan . --output json --json-file gl-security-report.json

  artifacts:
    reports:
      security: gl-security-report.json

  only:
    - merge_requests
    - main
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any

    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install mcp-sentinel'
                sh 'mcp-sentinel scan . --output html --json-file security-report.html'
                publishHTML([
                    reportDir: '.',
                    reportFiles: 'security-report.html',
                    reportName: 'Security Report'
                ])
            }
        }
    }
}
```

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: mcp-sentinel
        name: MCP Sentinel Security Scan
        entry: mcp-sentinel scan
        args: ['--severity', 'critical', '--severity', 'high']
        language: system
        pass_filenames: false
```

---

## Docker Deployment

### Simple Scanner (Lightweight)

Use for quick scanning without enterprise infrastructure:

```bash
# Build the image
docker-compose -f docker-compose.simple.yml build

# Run a scan
docker-compose -f docker-compose.simple.yml run --rm scanner scan /data

# Generate HTML report
docker-compose -f docker-compose.simple.yml run --rm scanner scan /data \
  --output html --json-file /reports/report.html

# Mount your project
docker-compose -f docker-compose.simple.yml run --rm \
  -v /path/to/your/project:/data:ro \
  scanner scan /data
```

### Enterprise Stack (Full Platform)

For production deployments with PostgreSQL, Redis, and Celery:

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f api

# Access services
# - API: http://localhost:8000
# - Flower: http://localhost:5555
# - MinIO: http://localhost:9001

# Stop services
docker-compose down
```

---

## Troubleshooting

### Common Issues

#### "No vulnerabilities found" when you expect some

**Possible causes:**
- Files are in excluded directories (node_modules, .git, venv)
- File types not supported yet
- Patterns don't match your code style

**Solution:**
```bash
# Check which files are being scanned
mcp-sentinel scan . --no-progress | grep "Files Scanned"

# Customize file patterns in .mcp-sentinel.yaml
scan:
  include_patterns:
    - "**/*.py"
    - "**/*.js"
```

#### "Permission denied" errors

**Solution:**
```bash
# Ensure you have read permissions
chmod -R +r /path/to/project

# Or run with Docker
docker-compose -f docker-compose.simple.yml run --rm scanner scan /data
```

#### Scan takes too long

**Solution:**
```bash
# Reduce max workers
mcp-sentinel scan . --config <(echo "performance: {max_workers: 4}")

# Or exclude large directories
scan:
  exclude_patterns:
    - "**/node_modules/**"
    - "**/vendor/**"
    - "**/dist/**"
```

### Getting Help

- **Documentation**: https://github.com/beejak/mcp-sentinel/tree/main/docs
- **Issues**: https://github.com/beejak/mcp-sentinel/issues
- **Discussions**: https://github.com/beejak/mcp-sentinel/discussions

---

## FAQ

### What types of vulnerabilities does MCP Sentinel detect?

MCP Sentinel includes 8 specialized detectors covering:

1. **Secrets** - Hardcoded API keys, passwords, tokens
2. **Code Injection** - SQL injection, command injection, eval
3. **Prompt Injection** - AI/LLM security attacks
4. **XSS** - Cross-site scripting vulnerabilities
5. **Configuration** - Insecure settings, missing headers
6. **Path Traversal** - Directory traversal, Zip Slip
7. **Tool Poisoning** - Unicode manipulation, hidden instructions
8. **Supply Chain** - Malicious dependencies, typosquatting

### How accurate is the detection?

- **Test Coverage**: ~95% average across all detectors
- **Pattern Count**: 98 vulnerability patterns
- **False Positive Rate**: Low (context-aware detection)
- **Detection Rate**: High (comprehensive pattern coverage)

### Can I use this in commercial projects?

Yes! MCP Sentinel is MIT licensed, which means:
- ✅ Commercial use allowed
- ✅ Modification allowed
- ✅ Distribution allowed
- ✅ Private use allowed

### How does this compare to other security scanners?

MCP Sentinel is specifically designed for MCP servers with:
- **MCP-Specific Detectors**: Prompt injection, tool poisoning
- **AI Security Focus**: LLM-specific attack patterns
- **Modern Stack**: Python 3.11+, async-first architecture
- **Professional Reporting**: SARIF, HTML dashboards
- **100% Open Source**: No commercial upsells

### Will you support more languages?

Phase 4 (Q1 2026) will add semantic analysis with tree-sitter, supporting:
- Python (enhanced)
- JavaScript/TypeScript (enhanced)
- Go
- Java
- More languages based on community demand

### Can I contribute?

Absolutely! See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Code contribution guidelines
- Development setup
- Testing requirements
- Pull request process

### What's the difference between phases?

- **Phase 1**: Foundation (3 detectors)
- **Phase 2**: AI & Supply Chain (5 detectors)
- **Phase 3**: Complete Parity + Reports (8 detectors, 4 formats) ← **Current**
- **Phase 4**: Multi-Engine Platform (Semantic, SAST, AI)
- **Phase 5**: Enterprise Features (API, Database, Task Queue)
- **Phase 6+**: Advanced Integrations & Analytics

---

## Next Steps

1. **Run your first scan**: `mcp-sentinel scan .`
2. **Generate an HTML report**: `--output html --json-file report.html`
3. **Integrate with CI/CD**: See [Integration section](#integration-with-cicd)
4. **Configure for your project**: `mcp-sentinel init`
5. **Join the community**: [GitHub Discussions](https://github.com/beejak/mcp-sentinel/discussions)

---

**Happy Scanning! 🛡️**

For more information, visit the [full documentation](https://github.com/beejak/mcp-sentinel/tree/main/docs).
