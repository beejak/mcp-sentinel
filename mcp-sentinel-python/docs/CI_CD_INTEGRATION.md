# MCP Sentinel Python - CI/CD Integration Guide

**Version**: 1.0.0  
**Purpose**: Complete guide to integrating Python edition into CI/CD pipelines

---

## Table of Contents

1. [Overview](#overview)
2. [GitHub Actions](#github-actions)
3. [GitLab CI](#gitlab-ci)
4. [Jenkins](#jenkins)
5. [Azure Pipelines](#azure-pipelines)
6. [Exit Codes](#exit-codes)
7. [Best Practices](#best-practices)
8. [Performance Optimization](#performance-optimization)

---

## Overview

MCP Sentinel Python integrates seamlessly into CI/CD pipelines with async-first architecture optimized for speed and reliability.

### Key Features for CI/CD

- **Async Processing**: ~3x faster than sequential scanning
- **Multiple Output Formats**: JSON, SARIF, HTML, terminal
- **Configurable Exit Codes**: Fail builds on Critical/High severities
- **Poetry Integration**: Native dependency management
- **SARIF Support**: Native GitHub Security tab integration
- **Caching**: Poetry cache + scan result caching

### Integration Strategy

```
┌─────────────┐
│   Commit    │
└──────┬──────┘
       │
┌──────▼──────────────────────────────────┐
│  CI/CD Pipeline Triggered               │
├─────────────────────────────────────────┤
│  1. Checkout code                       │
│  2. Setup Python + Poetry              │
│  3. Install dependencies                │
│  4. Run security scan                   │
│  5. Upload results (SARIF/HTML)         │
│  6. Fail if Critical/High found         │
└──────┬──────────────────────────────────┘
       │
┌──────▼──────┐
│   Deploy    │  (only if scan passes)
└─────────────┘
```

---

## GitHub Actions

### Basic Integration

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install Poetry
        uses: snok/install-poetry@v1
        with:
          version: latest
          virtualenvs-create: true
          virtualenvs-in-project: true
      
      - name: Load cached venv
        id: cached-poetry-dependencies
        uses: actions/cache@v3
        with:
          path: .venv
          key: venv-${{ runner.os }}-${{ hashFiles('**/poetry.lock') }}
      
      - name: Install dependencies
        if: steps.cached-poetry-dependencies.outputs.cache-hit != 'true'
        run: poetry install --no-interaction --no-root
      
      - name: Install project
        run: poetry install --no-interaction
      
      - name: Run security scan
        run: |
          poetry run mcp-sentinel scan . \
            --output sarif \
            --output-file security-results.sarif \
            --severity-threshold HIGH
      
      - name: Upload SARIF results
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: security-results.sarif
          category: mcp-sentinel
```

### Advanced Configuration

```yaml
name: Advanced Security Scan
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'  # Weekly Monday 2 AM

jobs:
  security-scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.8, 3.9, 3.10, 3.11]
    
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for baseline comparison
      
      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python-version }}
      
      - name: Install Poetry
        uses: snok/install-poetry@v1
      
      - name: Cache dependencies
        uses: actions/cache@v3
        with:
          path: |
            ~/.cache/pypoetry
            .venv
          key: ${{ runner.os }}-poetry-${{ hashFiles('**/poetry.lock') }}
          restore-keys: |
            ${{ runner.os }}-poetry-
      
      - name: Install dependencies
        run: poetry install
      
      - name: Run baseline comparison scan
        if: github.event_name == 'pull_request'
        run: |
          # Scan only changed files in PR
          CHANGED_FILES=$(git diff --name-only origin/main...HEAD | grep -E '\.(py|js|ts|json|yaml|yml)$' || true)
          
          if [ -n "$CHANGED_FILES" ]; then
            echo "$CHANGED_FILES" | tr '\n' ' ' | xargs poetry run mcp-sentinel scan \
              --output sarif \
              --output-file pr-changes.sarif \
              --baseline main
          fi
      
      - name: Run full scan
        if: github.event_name != 'pull_request'
        run: |
          poetry run mcp-sentinel scan . \
            --output sarif \
            --output-file full-scan.sarif \
            --output html \
            --output-file full-scan.html \
            --severity-threshold MEDIUM
      
      - name: Upload SARIF results
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: ${{ github.event_name == 'pull_request' && 'pr-changes.sarif' || 'full-scan.sarif' }}
      
      - name: Upload HTML report
        if: always() && github.event_name != 'pull_request'
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: full-scan.html
          retention-days: 30
      
      - name: Comment PR with results
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const sarif = JSON.parse(fs.readFileSync('pr-changes.sarif', 'utf8'));
            
            const issues = sarif.runs[0].results || [];
            const criticalCount = issues.filter(i => i.level === 'error').length;
            const highCount = issues.filter(i => i.level === 'warning').length;
            
            const body = `## 🔒 MCP Sentinel Security Scan Results
            
            **Scan Type**: Pull Request Changes
            **Files Scanned**: ${sarif.runs[0].invocations[0].executionSuccessful ? '✅' : '❌'}
            
            | Severity | Count |
            |----------|-------|
            | Critical | ${criticalCount} |
            | High | ${highCount} |
            | Medium | ${issues.filter(i => i.level === 'note').length} |
            
            ${criticalCount > 0 ? '⚠️ **Critical issues found - review required**' : '✅ No critical issues detected'}
            `;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: body
            });
```

---

## GitLab CI

### `.gitlab-ci.yml` Configuration

```yaml
stages:
  - test
  - security
  - deploy

variables:
  POETRY_CACHE_DIR: "$CI_PROJECT_DIR/.cache/poetry"
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

cache:
  paths:
    - .cache/poetry
    - .cache/pip
    - .venv

before_script:
  - pip install poetry
  - poetry config virtualenvs.in-project true
  - poetry install --no-interaction

security-scan:
  stage: security
  image: python:3.11
  script:
    - poetry run mcp-sentinel scan . \
        --output sarif \
        --output-file security-results.sarif \
        --severity-threshold HIGH
  artifacts:
    reports:
      sast: security-results.sarif
    paths:
      - security-results.sarif
    expire_in: 1 week
  only:
    - merge_requests
    - main
    - develop

# Advanced pipeline with multiple scans
security-matrix:
  stage: security
  parallel:
    matrix:
      - PYTHON_VERSION: ["3.8", "3.9", "3.10", "3.11"]
  image: python:${PYTHON_VERSION}
  script:
    - poetry install
    - |
      if [ "$CI_PIPELINE_SOURCE" == "merge_request_event" ]; then
        # PR scan - only changed files
        poetry run mcp-sentinel scan \
          --output sarif \
          --output-file mr-scan-${PYTHON_VERSION}.sarif \
          $(git diff --name-only $CI_MERGE_REQUEST_DIFF_BASE_SHA...$CI_COMMIT_SHA)
      else
        # Full scan
        poetry run mcp-sentinel scan . \
          --output sarif \
          --output-file full-scan-${PYTHON_VERSION}.sarif \
          --output html \
          --output-file full-scan-${PYTHON_VERSION}.html
      fi
  artifacts:
    reports:
      sast: 
        - mr-scan-${PYTHON_VERSION}.sarif
        - full-scan-${PYTHON_VERSION}.sarif
    paths:
      - full-scan-${PYTHON_VERSION}.html
    expire_in: 30 days
```

---

## Jenkins

### Jenkinsfile Configuration

```groovy
pipeline {
    agent any
    
    environment {
        POETRY_CACHE_DIR = "${WORKSPACE}/.cache/poetry"
        PIP_CACHE_DIR = "${WORKSPACE}/.cache/pip"
    }
    
    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timeout(time: 30, unit: 'MINUTES')
    }
    
    stages {
        stage('Setup') {
            steps {
                script {
                    // Setup Python with multiple version support
                    def pythonVersions = ['3.8', '3.9', '3.10', '3.11']
                    def parallelStages = [:]
                    
                    pythonVersions.each { version ->
                        parallelStages["Python ${version}"] = {
                            node {
                                checkout scm
                                
                                sh """
                                    python${version} -m pip install poetry
                                    python${version} -m poetry config virtualenvs.in-project true
                                    python${version} -m poetry install
                                """
                                
                                sh """
                                    python${version} -m poetry run mcp-sentinel scan . \
                                        --output sarif \
                                        --output-file security-results-${version}.sarif \
                                        --severity-threshold HIGH
                                """
                                
                                archiveArtifacts artifacts: "security-results-${version}.sarif"
                                publishHTML([
                                    allowMissing: false,
                                    alwaysLinkToLastBuild: true,
                                    keepAll: true,
                                    reportDir: '.',
                                    reportFiles: "security-results-${version}.sarif",
                                    reportName: "Security Report Python ${version}"
                                ])
                            }
                        }
                    }
                    
                    parallel parallelStages
                }
            }
        }
        
        stage('Security Gate') {
            steps {
                script {
                    // Fail build if critical issues found
                    def sarifFiles = findFiles(glob: 'security-results-*.sarif')
                    def totalIssues = 0
                    
                    sarifFiles.each { file ->
                        def sarifContent = readJSON file: file.path
                        def issues = sarifContent.runs[0].results ?: []
                        totalIssues += issues.size()
                    }
                    
                    if (totalIssues > 0) {
                        currentBuild.result = 'UNSTABLE'
                        echo "Found ${totalIssues} security issues"
                    }
                }
            }
        }
    }
    
    post {
        always {
            cleanWs()
        }
        failure {
            emailext (
                subject: "Security Scan Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: "The security scan found critical issues. Check the build logs for details.",
                to: "${env.CHANGE_AUTHOR_EMAIL}"
            )
        }
    }
}
```

---

## Azure Pipelines

### `azure-pipelines.yml` Configuration

```yaml
trigger:
  branches:
    include:
      - main
      - develop
  paths:
    exclude:
      - docs/**
      - README.md

pr:
  branches:
    include:
      - main

variables:
  pythonVersion: '3.11'
  poetryVersion: '1.6.1'

stages:
- stage: SecurityScan
  displayName: 'Security Scan'
  jobs:
  - job: ScanPythonVersions
    displayName: 'Scan Multiple Python Versions'
    strategy:
      matrix:
        Python38:
          python.version: '3.8'
        Python39:
          python.version: '3.9'
        Python310:
          python.version: '3.10'
        Python311:
          python.version: '3.11'
    
    steps:
    - task: UsePythonVersion@0
      inputs:
        versionSpec: '$(python.version)'
      displayName: 'Use Python $(python.version)'
    
    - script: |
        pip install poetry==$(poetryVersion)
        poetry config virtualenvs.in-project true
        poetry install
      displayName: 'Install Poetry and dependencies'
    
    - task: Cache@2
      inputs:
        key: 'poetry | $(Agent.OS) | $(python.version) | poetry.lock'
        restoreKeys: |
          poetry | $(Agent.OS) | $(python.version)
          poetry | $(Agent.OS)
        path: .venv
      displayName: 'Cache Poetry virtual environment'
    
    - script: |
        poetry run mcp-sentinel scan . \
          --output sarif \
          --output-file security-results-$(python.version).sarif \
          --output html \
          --output-file security-results-$(python.version).html \
          --severity-threshold MEDIUM
      displayName: 'Run security scan'
    
    - task: PublishBuildArtifacts@1
      inputs:
        pathToPublish: 'security-results-$(python.version).html'
        artifactName: 'security-report-$(python.version)'
      displayName: 'Publish HTML report'
    
    - task: PublishBuildArtifacts@1
      inputs:
        pathToPublish: 'security-results-$(python.version).sarif'
        artifactName: 'security-sarif-$(python.version)'
      displayName: 'Publish SARIF results'

- stage: SecurityGate
  displayName: 'Security Gate'
  dependsOn: SecurityScan
  condition: succeeded()
  jobs:
  - job: EvaluateResults
    displayName: 'Evaluate Security Results'
    steps:
    - script: |
        echo "Evaluating security scan results..."
        # Add custom evaluation logic here
        # Fail pipeline if critical issues found
      displayName: 'Evaluate scan results'
```

---

## Exit Codes

MCP Sentinel Python uses standardized exit codes for CI/CD integration:

| Exit Code | Meaning | CI/CD Action |
|-----------|---------|--------------|
| `0` | Success (no issues or below threshold) | Continue pipeline |
| `1` | General error | Fail build |
| `2` | Configuration error | Fail build |
| `3` | Critical vulnerabilities found | Fail build |
| `4` | High severity issues found | Configurable |
| `5` | Medium severity issues found | Configurable |
| `6` | Low severity issues found | Continue (warning) |
| `7` | Scan timeout | Fail build |
| `8` | File system error | Fail build |

### Using Exit Codes in Scripts

```bash
#!/bin/bash
# CI/CD script with proper exit code handling

poetry run mcp-sentinel scan . \
  --output sarif \
  --output-file results.sarif \
  --severity-threshold HIGH

EXIT_CODE=$?

case $EXIT_CODE in
  0)
    echo "✅ No security issues found"
    ;;
  3)
    echo "❌ Critical vulnerabilities found - failing build"
    exit 1
    ;;
  4)
    echo "⚠️ High severity issues found - continuing with warning"
    # Don't fail build for high issues in some cases
    ;;
  7)
    echo "⏱️ Scan timeout - retrying with increased timeout"
    poetry run mcp-sentinel scan . --timeout 300
    ;;
  *)
    echo "❌ Unexpected error (exit code: $EXIT_CODE)"
    exit 1
    ;;
esac
```

---

## Best Practices

### 1. Caching Strategy
```yaml
# Cache Poetry dependencies and virtual environment
- name: Cache Poetry
  uses: actions/cache@v3
  with:
    path: |
      ~/.cache/pypoetry
      .venv
    key: ${{ runner.os }}-poetry-${{ hashFiles('**/poetry.lock') }}
    restore-keys: |
      ${{ runner.os }}-poetry-
```

### 2. Matrix Testing
```yaml
strategy:
  matrix:
    python-version: [3.8, 3.9, 3.10, 3.11]
    os: [ubuntu-latest, windows-latest, macos-latest]
```

### 3. Parallel Scanning
```bash
# Split large codebases for faster scanning
poetry run mcp-sentinel scan src/ --output sarif --output-file src-results.sarif &
poetry run mcp-sentinel scan tests/ --output sarif --output-file test-results.sarif &
poetry run mcp-sentinel scan docs/ --output sarif --output-file docs-results.sarif &
wait

# Merge results if needed
poetry run mcp-sentinel merge-results *.sarif --output combined.sarif
```

### 4. Incremental Scanning
```bash
# Only scan changed files in PRs
if [ "$CI_EVENT_NAME" == "pull_request" ]; then
  CHANGED_FILES=$(git diff --name-only origin/main...HEAD)
  echo "$CHANGED_FILES" | xargs poetry run mcp-sentinel scan
else
  poetry run mcp-sentinel scan .
fi
```

### 5. Security Gate Configuration
```yaml
# Don't fail on medium/low issues in feature branches
- name: Security scan (feature branch)
  if: github.ref != 'refs/heads/main'
  run: |
    poetry run mcp-sentinel scan . \
      --severity-threshold HIGH \
      --exit-code-on-high 0  # Don't fail on high issues

- name: Security scan (main branch)
  if: github.ref == 'refs/heads/main'
  run: |
    poetry run mcp-sentinel scan . \
      --severity-threshold MEDIUM  # Stricter on main
```

---

## Performance Optimization

### 1. Async Concurrency Tuning
```bash
# Optimize for CI/CD environment
poetry run mcp-sentinel scan . \
  --max-concurrent-files 20 \
  --timeout 60 \
  --memory-limit 512MB
```

### 2. Selective Scanning
```bash
# Skip certain directories in CI
poetry run mcp-sentinel scan . \
  --exclude-dir .git,node_modules,__pycache__,.pytest_cache \
  --exclude-pattern "*.min.js,*.bundle.js"
```

### 3. Result Caching
```yaml
# Cache scan results for unchanged files
- name: Cache scan results
  uses: actions/cache@v3
  with:
    path: .mcp-sentinel-cache
    key: mcp-sentinel-${{ hashFiles('**/poetry.lock') }}-${{ github.sha }}
    restore-keys: |
      mcp-sentinel-${{ hashFiles('**/poetry.lock') }}-
```

### 4. Resource Monitoring
```bash
# Monitor resource usage during scan
/usr/bin/time -v poetry run mcp-sentinel scan . 2>&1 | tee scan-metrics.txt

# Extract key metrics
MAX_MEMORY=$(grep "Maximum resident set size" scan-metrics.txt | awk '{print $6}')
CPU_TIME=$(grep "User time" scan-metrics.txt | awk '{print $4}')
echo "Max memory: ${MAX_MEMORY}KB, CPU time: ${CPU_TIME}s"
```

---

**Integration Checklist**:
- [ ] Configure exit codes based on severity thresholds
- [ ] Set up Poetry caching for faster builds
- [ ] Enable SARIF upload for GitHub Security tab
- [ ] Configure matrix testing across Python versions
- [ ] Set up incremental scanning for PRs
- [ ] Configure security gates per branch
- [ ] Add performance monitoring
- [ ] Set up result caching for large codebases