# MCP Sentinel — CI/CD Integration Guide

**Version:** v0.2.0

---

## Table of Contents

1. [Overview](#overview)
2. [GitHub Actions](#github-actions)
3. [GitLab CI](#gitlab-ci)
4. [Jenkins](#jenkins)
5. [Azure DevOps](#azure-devops)
6. [CircleCI](#circleci)
7. [Bitbucket Pipelines](#bitbucket-pipelines)
8. [Using Scan Results](#using-scan-results)
9. [Exit Codes](#exit-codes)
10. [Environment Variables](#environment-variables)

---

## Overview

MCP Sentinel integrates into any CI/CD pipeline that can run Python. The key properties that make it CI-friendly:

- **No external binaries** — pure Python, installs with `pip install mcp-sentinel`
- **No network calls** — all analysis runs locally; no API keys, no data leaves the runner
- **Structured output** — SARIF 2.1.0 for GitHub/GitLab/Azure security tabs; JSON for scripting
- **Deterministic** — same input always produces same output; safe to cache
- **Fast** — async scanning with configurable worker pool; typical MCP server scans in <5s

### Installation in any pipeline

```bash
pip install mcp-sentinel          # latest release
pip install mcp-sentinel==0.2.0   # pin to specific version
pip install -e ".[dev]"           # from source with dev deps (for running tests)
```

### Basic scan command

```bash
# Terminal output (human-readable)
mcp-sentinel scan /path/to/server

# SARIF for security dashboards
mcp-sentinel scan /path/to/server --output sarif --json-file results.sarif

# JSON for scripting
mcp-sentinel scan /path/to/server --output json --json-file results.json

# Filter by severity
mcp-sentinel scan /path/to/server --severity critical --severity high
```

---

## GitHub Actions

Ready-to-use workflow at `.github/workflows/python-ci.yml` (included in this repo).

For scanning your own MCP server, copy and adapt:

```yaml
# .github/workflows/mcp-sentinel-scan.yml
name: MCP Sentinel Security Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Install MCP Sentinel
        run: pip install mcp-sentinel

      - name: Scan
        run: |
          mcp-sentinel scan . \
            --output sarif \
            --json-file results.sarif \
            --no-progress

      - name: Upload to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
          category: mcp-sentinel
```

Findings appear in **Security → Code scanning alerts** on the repository page.

---

## GitLab CI

Copy `ci/gitlab-ci.yml` to `.gitlab-ci.yml` in your repository root. GitLab natively understands SARIF via the `reports: sast:` artifact key.

```yaml
# Minimal example
security-scan:
  image: python:3.11-slim
  script:
    - pip install mcp-sentinel
    - mcp-sentinel scan . --output sarif --json-file gl-sast-report.sarif --no-progress || true
  artifacts:
    reports:
      sast: gl-sast-report.sarif
```

Results appear in the **Security** tab of the merge request.

Full config: [`ci/gitlab-ci.yml`](../ci/gitlab-ci.yml)

---

## Jenkins

### What is Jenkins?

Jenkins is a self-hosted open-source automation server. Unlike GitHub Actions or GitLab CI (which run on the provider's infrastructure), Jenkins runs on your own servers — either bare metal, VMs, or Kubernetes pods. It is widely used in enterprises with on-premise infrastructure or strict data residency requirements.

Jenkins pipelines are defined in a `Jenkinsfile` using a Groovy-based DSL (declarative or scripted syntax). The `Jenkinsfile` lives at the repository root and is checked into version control alongside your code.

### Why Jenkins + MCP Sentinel is a good fit

MCP Sentinel has no external dependencies and makes no network calls. This aligns directly with Jenkins' typical deployment context: air-gapped networks, internal package mirrors, and strict data isolation requirements. The scan runs entirely on the Jenkins agent — no code leaves the build environment.

### Prerequisites

| Requirement | Notes |
|---|---|
| Jenkins 2.387+ | Any modern LTS version works |
| Python 3.9+ | Must be on the Jenkins agent PATH, or install via the Python plugin |
| `pip` | Available with Python |
| Pipeline plugin | Built into Jenkins; enables `Jenkinsfile` support |
| JUnit plugin (optional) | Renders test results as a graph in the Jenkins UI |
| Warnings Next Generation plugin (optional) | Renders SARIF findings inline in PRs |

### Using the included Jenkinsfile

This repository includes a production-ready `Jenkinsfile` at the root. To use it:

1. **Create a new Pipeline job** in Jenkins:
   - Jenkins dashboard → **New Item** → **Pipeline**
   - Name it (e.g., `mcp-sentinel`)

2. **Configure the pipeline source**:
   - Scroll to **Pipeline** section
   - Definition: **Pipeline script from SCM**
   - SCM: **Git**
   - Repository URL: your repo URL
   - Branch: `*/master` (or your default branch)
   - Script Path: `Jenkinsfile` (default)

3. **Save and build**:
   - Click **Save**, then **Build Now**
   - The first build installs dependencies and runs all stages

### What the Jenkinsfile does

```
Install      → creates .venv, pip install -e ".[dev]"
Lint         → ruff check + mypy (non-blocking)
Test         → pytest with JUnit XML + coverage output
Security Scan → mcp-sentinel scan on src/ → SARIF + JSON artifacts
```

### Viewing results

- **Test results**: After the first run, the job page shows a test trend graph (requires JUnit plugin)
- **SARIF/JSON artifacts**: Available under **Build Artifacts** on each build
- **Inline findings**: Install the Warnings Next Generation plugin and uncomment in the Jenkinsfile:
  ```groovy
  recordIssues tools: [sarif(pattern: 'reports/sentinel.sarif')]
  ```

### Scanning a different target

To scan your own MCP server code (not this repo itself), update the Security Scan stage:

```groovy
stage('Security Scan') {
    steps {
        sh """
            . .venv/bin/activate
            mcp-sentinel scan /path/to/your/mcp-server \
                --output sarif \
                --json-file reports/sentinel.sarif \
                --no-progress
        """
    }
}
```

### Failing the build on critical findings

The Jenkinsfile runs the scan with `|| true` so it never fails the build. To fail on critical/high findings:

```groovy
sh """
    . .venv/bin/activate
    mcp-sentinel scan src/ \
        --output json \
        --json-file reports/sentinel.json \
        --no-progress

    python3 -c "
import json, sys
with open('reports/sentinel.json') as f:
    data = json.load(f)
critical = sum(1 for v in data.get('vulnerabilities', []) if v['severity'] == 'critical')
high     = sum(1 for v in data.get('vulnerabilities', []) if v['severity'] == 'high')
if critical > 0:
    print(f'FAIL: {critical} critical findings')
    sys.exit(1)
print(f'OK: {critical} critical, {high} high findings')
"
"""
```

### Multi-branch pipeline

To scan all branches automatically, use a **Multibranch Pipeline** job instead of a plain Pipeline job. Jenkins will discover all branches with a `Jenkinsfile` and run them automatically on push.

### Agent-specific Python paths

If your Jenkins agent has Python at a non-standard path:

```groovy
environment {
    PYTHON = '/opt/python311/bin/python3'
    PIP    = '/opt/python311/bin/pip3'
}
```

Or use the **Python Plugin** for Jenkins to manage Python installations per-job.

---

## Azure DevOps

Copy `ci/azure-pipelines.yml` to `azure-pipelines.yml` in your repository root.

SARIF results are published to the **Security** tab when the **Microsoft Security DevLabs** extension is installed. Without the extension, results are available as build artifacts.

Full config: [`ci/azure-pipelines.yml`](../ci/azure-pipelines.yml)

---

## CircleCI

Copy `ci/circleci-config.yml` to `.circleci/config.yml` in your repository root.

Full config: [`ci/circleci-config.yml`](../ci/circleci-config.yml)

---

## Bitbucket Pipelines

Copy `ci/bitbucket-pipelines.yml` to `bitbucket-pipelines.yml` in your repository root.

Full config: [`ci/bitbucket-pipelines.yml`](../ci/bitbucket-pipelines.yml)

---

## Using Scan Results

### Parsing JSON output

```python
import json

with open("results.json") as f:
    results = json.load(f)

for vuln in results.get("vulnerabilities", []):
    print(f"{vuln['severity'].upper():8} {vuln['title']}")
    print(f"         {vuln['file']}:{vuln['line']}")
```

### Parsing SARIF output

SARIF 2.1.0 is the standard format for security tool output. It is natively understood by:

- GitHub Security tab (Code Scanning)
- GitLab Security reports
- Azure DevOps Security Code Scanning
- SonarQube (via SARIF import)
- VS Code with the SARIF Viewer extension

```python
import json

with open("results.sarif") as f:
    sarif = json.load(f)

for run in sarif.get("runs", []):
    for result in run.get("results", []):
        rule_id  = result.get("ruleId", "")
        message  = result.get("message", {}).get("text", "")
        location = result["locations"][0]["physicalLocation"]
        file     = location["artifactLocation"]["uri"]
        line     = location["region"]["startLine"]
        print(f"{rule_id}: {file}:{line} — {message}")
```

### Severity counts for build gates

```bash
# Count critical findings from JSON output
CRITICAL=$(python3 -c "
import json, sys
with open('results.json') as f:
    data = json.load(f)
print(sum(1 for v in data.get('vulnerabilities', []) if v['severity'] == 'critical'))
")

if [ "$CRITICAL" -gt "0" ]; then
    echo "Build failed: $CRITICAL critical findings"
    exit 1
fi
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; findings may exist (check the output) |
| `1` | Scan error (file not found, permission denied, etc.) |

MCP Sentinel does not currently use exit code `1` to signal findings. Use the JSON output and a post-scan script to gate on severity (see example above).

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ENABLE_STATIC_ANALYSIS` | `true` | Enable/disable scanning engine |
| `LOG_LEVEL` | `info` | Logging verbosity |
| `MAX_WORKERS` | `4` | Concurrent file scanning workers |
| `CACHE_TTL` | `3600` | Cache TTL in seconds (0 to disable) |

These can be set in the pipeline environment to control scan behavior without modifying the command line.
