# MCP Sentinel v2.6.0 - CI/CD Integration Guide

## Table of Contents
- [Overview](#overview)
- [GitHub Actions](#github-actions)
- [GitLab CI](#gitlab-ci)
- [Jenkins](#jenkins)
- [CircleCI](#circleci)
- [Azure Pipelines](#azure-pipelines)
- [Bitbucket Pipelines](#bitbucket-pipelines)
- [Exit Codes](#exit-codes)
- [Best Practices](#best-practices)

---

## Overview

MCP Sentinel v2.6.0 integrates seamlessly into CI/CD pipelines to provide automated security scanning for every commit, pull request, or deployment.

### Key Features for CI/CD

- **Multiple Output Formats**: JSON, SARIF, HTML, terminal
- **Configurable Exit Codes**: Fail builds on Critical/High severities
- **Fast Execution**: ~7.8 seconds for typical Node.js project
- **SARIF Support**: Native GitHub Security tab integration
- **Baseline Comparison**: Detect only new vulnerabilities
- **Caching**: Results cached for faster subsequent scans

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
│  2. Install MCP Sentinel                │
│  3. Run security scan                   │
│  4. Upload results (SARIF/HTML)         │
│  5. Fail if Critical/High found         │
└──────┬──────────────────────────────────┘
       │
┌──────▼──────┐
│   Deploy    │  (only if scan passes)
└─────────────┘
```

---

## GitHub Actions

### Basic Integration

**.github/workflows/security-scan.yml**:

```yaml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest

    permissions:
      contents: read
      security-events: write  # For SARIF upload

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          override: true

      - name: Cache Cargo dependencies
        uses: actions/cache@v3
        with:
          path: |
            ~/.cargo/bin/
            ~/.cargo/registry/index/
            ~/.cargo/registry/cache/
            ~/.cargo/git/db/
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}

      - name: Install MCP Sentinel
        run: |
          git clone https://github.com/beejak/MCP_Scanner.git /tmp/mcp-scanner
          cd /tmp/mcp-scanner
          git checkout v2.6.0
          cargo build --release
          sudo cp target/release/mcp-sentinel /usr/local/bin/

      - name: Run security scan
        run: |
          mcp-sentinel scan \
            --format sarif \
            --output results.sarif \
            --fail-on critical,high \
            ./
        env:
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
          VULNERABLE_MCP_API_KEY: ${{ secrets.VULNERABLE_MCP_API_KEY }}

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: results.sarif

      - name: Upload scan results as artifact
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-scan-results
          path: results.sarif
```

### Advanced: Multi-Format Reports

```yaml
      - name: Run comprehensive scan
        run: |
          # Generate all report formats
          mcp-sentinel scan --format json --output results.json ./
          mcp-sentinel scan --format sarif --output results.sarif ./
          mcp-sentinel scan --format html --output results.html ./

          # Fail on critical/high only
          mcp-sentinel scan --fail-on critical,high ./

      - name: Upload all reports
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-reports
          path: |
            results.json
            results.sarif
            results.html

      - name: Comment on PR
        uses: actions/github-script@v6
        if: github.event_name == 'pull_request' && failure()
        with:
          script: |
            const fs = require('fs');
            const results = JSON.parse(fs.readFileSync('results.json', 'utf8'));

            const critical = results.vulnerabilities.filter(v => v.severity === 'critical').length;
            const high = results.vulnerabilities.filter(v => v.severity === 'high').length;

            const comment = `## 🔒 Security Scan Failed

            **Critical**: ${critical} | **High**: ${high}

            [View detailed report](https://github.com/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId})
            `;

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```

### Using Pre-built Docker Image

```yaml
      - name: Run MCP Sentinel (Docker)
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/workspace \
            -e NVD_API_KEY=${{ secrets.NVD_API_KEY }} \
            mcp-sentinel:2.6.0 scan \
            --format sarif \
            --output /workspace/results.sarif \
            /workspace
```

---

## GitLab CI

**.gitlab-ci.yml**:

```yaml
stages:
  - security
  - deploy

variables:
  MCP_VERSION: "2.6.0"

security-scan:
  stage: security
  image: rust:1.75

  before_script:
    - apt-get update && apt-get install -y git build-essential
    - git clone https://github.com/beejak/MCP_Scanner.git /tmp/mcp-scanner
    - cd /tmp/mcp-scanner && git checkout v${MCP_VERSION}
    - cargo build --release
    - cp target/release/mcp-sentinel /usr/local/bin/

  script:
    - cd $CI_PROJECT_DIR
    - mcp-sentinel scan --format json --output gl-security-report.json ./
    - mcp-sentinel scan --fail-on critical,high ./

  artifacts:
    reports:
      sast: gl-security-report.json
    paths:
      - gl-security-report.json
    expire_in: 1 week

  only:
    - merge_requests
    - main
    - develop

# Optional: Scheduled daily scan
scheduled-scan:
  stage: security
  extends: security-scan
  only:
    - schedules
```

### GitLab Security Dashboard Integration

```yaml
security-scan:
  script:
    # Convert SARIF to GitLab SAST format
    - mcp-sentinel scan --format sarif --output results.sarif ./
    - python3 /scripts/sarif_to_gitlab.py results.sarif gl-sast-report.json

  artifacts:
    reports:
      sast: gl-sast-report.json
```

**sarif_to_gitlab.py** (converter script):

```python
#!/usr/bin/env python3
import json
import sys

def convert_sarif_to_gitlab(sarif_file, output_file):
    with open(sarif_file) as f:
        sarif = json.load(f)

    gitlab_report = {
        "version": "15.0.0",
        "vulnerabilities": []
    }

    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            vuln = {
                "id": result["ruleId"],
                "category": "sast",
                "name": result["message"]["text"],
                "message": result["message"]["text"],
                "severity": result["level"].upper(),
                "confidence": "High",
                "scanner": {
                    "id": "mcp-sentinel",
                    "name": "MCP Sentinel"
                },
                "location": {
                    "file": result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                    "start_line": result["locations"][0]["physicalLocation"]["region"]["startLine"]
                },
                "identifiers": []
            }
            gitlab_report["vulnerabilities"].append(vuln)

    with open(output_file, 'w') as f:
        json.dump(gitlab_report, f, indent=2)

if __name__ == "__main__":
    convert_sarif_to_gitlab(sys.argv[1], sys.argv[2])
```

---

## Jenkins

**Jenkinsfile**:

```groovy
pipeline {
    agent any

    environment {
        MCP_VERSION = '2.6.0'
        NVD_API_KEY = credentials('nvd-api-key')
        VULNERABLE_MCP_API_KEY = credentials('vulnerable-mcp-api-key')
    }

    stages {
        stage('Install MCP Sentinel') {
            steps {
                sh '''
                    if ! command -v mcp-sentinel &> /dev/null; then
                        git clone https://github.com/beejak/MCP_Scanner.git /tmp/mcp-scanner
                        cd /tmp/mcp-scanner
                        git checkout v${MCP_VERSION}
                        cargo build --release
                        sudo cp target/release/mcp-sentinel /usr/local/bin/
                    fi
                '''
            }
        }

        stage('Security Scan') {
            steps {
                sh '''
                    mcp-sentinel scan \
                        --format json \
                        --output scan-results.json \
                        ./

                    mcp-sentinel scan \
                        --format html \
                        --output scan-results.html \
                        ./
                '''
            }
        }

        stage('Check Vulnerabilities') {
            steps {
                script {
                    def scanResult = sh(
                        script: 'mcp-sentinel scan --fail-on critical,high ./',
                        returnStatus: true
                    )

                    if (scanResult != 0) {
                        error("Critical or High severity vulnerabilities found!")
                    }
                }
            }
        }

        stage('Archive Reports') {
            steps {
                archiveArtifacts artifacts: 'scan-results.*', fingerprint: true

                publishHTML([
                    reportDir: '.',
                    reportFiles: 'scan-results.html',
                    reportName: 'Security Scan Report',
                    keepAll: true
                ])
            }
        }

        stage('Deploy') {
            when {
                branch 'main'
            }
            steps {
                echo 'Deploying application...'
                // Deployment steps
            }
        }
    }

    post {
        failure {
            emailext(
                subject: "Security Scan Failed: ${env.JOB_NAME}",
                body: "Security vulnerabilities detected. Check ${env.BUILD_URL} for details.",
                to: "${env.CHANGE_AUTHOR_EMAIL}"
            )
        }
    }
}
```

---

## CircleCI

**.circleci/config.yml**:

```yaml
version: 2.1

orbs:
  rust: circleci/rust@1.6.0

jobs:
  security-scan:
    docker:
      - image: cimg/rust:1.75

    steps:
      - checkout

      - restore_cache:
          keys:
            - mcp-sentinel-{{ .Environment.CACHE_VERSION }}

      - run:
          name: Install MCP Sentinel
          command: |
            if [ ! -f ~/.cargo/bin/mcp-sentinel ]; then
              git clone https://github.com/beejak/MCP_Scanner.git /tmp/mcp-scanner
              cd /tmp/mcp-scanner
              git checkout v2.6.0
              cargo build --release
              cp target/release/mcp-sentinel ~/.cargo/bin/
            fi

      - save_cache:
          key: mcp-sentinel-{{ .Environment.CACHE_VERSION }}
          paths:
            - ~/.cargo/bin/mcp-sentinel

      - run:
          name: Run security scan
          command: |
            mcp-sentinel scan \
              --format json \
              --output scan-results.json \
              ./

      - run:
          name: Check for critical/high vulnerabilities
          command: |
            mcp-sentinel scan --fail-on critical,high ./

      - store_artifacts:
          path: scan-results.json
          destination: security-scan

      - store_test_results:
          path: scan-results.json

workflows:
  security-check:
    jobs:
      - security-scan:
          filters:
            branches:
              only:
                - main
                - develop
          context:
            - security-credentials  # Contains NVD_API_KEY
```

---

## Azure Pipelines

**azure-pipelines.yml**:

```yaml
trigger:
  branches:
    include:
      - main
      - develop

pool:
  vmImage: 'ubuntu-latest'

variables:
  MCP_VERSION: '2.6.0'

stages:
  - stage: Security
    displayName: 'Security Scan'
    jobs:
      - job: ScanCode
        displayName: 'Run MCP Sentinel'
        steps:
          - checkout: self

          - task: Cache@2
            inputs:
              key: 'mcp-sentinel | "$(Agent.OS)" | "$(MCP_VERSION)"'
              path: $(Pipeline.Workspace)/mcp-sentinel
            displayName: 'Cache MCP Sentinel'

          - script: |
              if [ ! -f $(Pipeline.Workspace)/mcp-sentinel/mcp-sentinel ]; then
                git clone https://github.com/beejak/MCP_Scanner.git /tmp/mcp-scanner
                cd /tmp/mcp-scanner
                git checkout v$(MCP_VERSION)
                cargo build --release
                mkdir -p $(Pipeline.Workspace)/mcp-sentinel
                cp target/release/mcp-sentinel $(Pipeline.Workspace)/mcp-sentinel/
              fi
              sudo cp $(Pipeline.Workspace)/mcp-sentinel/mcp-sentinel /usr/local/bin/
            displayName: 'Install MCP Sentinel'

          - script: |
              mcp-sentinel scan \
                --format sarif \
                --output $(Build.ArtifactStagingDirectory)/scan-results.sarif \
                ./
            displayName: 'Run security scan'
            env:
              NVD_API_KEY: $(NVD_API_KEY)
              VULNERABLE_MCP_API_KEY: $(VULNERABLE_MCP_API_KEY)

          - task: PublishBuildArtifacts@1
            inputs:
              pathToPublish: '$(Build.ArtifactStagingDirectory)/scan-results.sarif'
              artifactName: 'SecurityScan'
            displayName: 'Publish scan results'

          - script: |
              mcp-sentinel scan --fail-on critical,high ./
            displayName: 'Check vulnerabilities'
            condition: succeededOrFailed()

  - stage: Deploy
    displayName: 'Deploy Application'
    dependsOn: Security
    condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
    jobs:
      - deployment: DeployProduction
        environment: 'production'
        strategy:
          runOnce:
            deploy:
              steps:
                - script: echo "Deploying to production"
```

---

## Bitbucket Pipelines

**bitbucket-pipelines.yml**:

```yaml
image: rust:1.75

definitions:
  caches:
    mcp-sentinel: /usr/local/bin/mcp-sentinel

pipelines:
  default:
    - step:
        name: Security Scan
        caches:
          - mcp-sentinel
          - cargo
        script:
          - |
            if [ ! -f /usr/local/bin/mcp-sentinel ]; then
              git clone https://github.com/beejak/MCP_Scanner.git /tmp/mcp-scanner
              cd /tmp/mcp-scanner
              git checkout v2.6.0
              cargo build --release
              cp target/release/mcp-sentinel /usr/local/bin/
            fi
          - cd $BITBUCKET_CLONE_DIR
          - mcp-sentinel scan --format json --output scan-results.json ./
          - mcp-sentinel scan --fail-on critical,high ./
        artifacts:
          - scan-results.json

  pull-requests:
    '**':
      - step:
          name: PR Security Check
          caches:
            - mcp-sentinel
          script:
            - mcp-sentinel scan --fail-on critical,high ./
          artifacts:
            - scan-results.json

  branches:
    main:
      - step:
          name: Security Scan
          script:
            - mcp-sentinel scan --format json --output scan-results.json ./
            - mcp-sentinel scan --fail-on critical,high ./
      - step:
          name: Deploy
          deployment: production
          script:
            - echo "Deploying to production"
```

---

## Exit Codes

MCP Sentinel uses standard exit codes for CI/CD integration:

| Exit Code | Meaning | Action |
|-----------|---------|--------|
| `0` | Success - No vulnerabilities found | ✅ Pass build |
| `1` | Vulnerabilities found (based on `--fail-on`) | ❌ Fail build |
| `2` | Scan error (file not found, parse error) | ❌ Fail build |
| `3` | Configuration error | ❌ Fail build |

### Configuring Failure Conditions

```bash
# Fail on any severity
mcp-sentinel scan --fail-on critical,high,medium,low ./

# Fail on critical only
mcp-sentinel scan --fail-on critical ./

# Fail on critical and high
mcp-sentinel scan --fail-on critical,high ./

# Don't fail build (always exit 0)
mcp-sentinel scan --no-fail ./
```

### Check Exit Code in Scripts

```bash
# Run scan and check result
if mcp-sentinel scan --fail-on critical,high ./; then
    echo "✅ Security scan passed"
else
    echo "❌ Security vulnerabilities found"
    exit 1
fi
```

---

## Best Practices

### 1. Scan on Every PR

Always run security scans on pull requests before merging:

```yaml
on:
  pull_request:
    branches: [main, develop]
```

### 2. Block Deployment on Critical/High

Prevent vulnerable code from reaching production:

```bash
mcp-sentinel scan --fail-on critical,high ./
```

### 3. Cache MCP Sentinel Binary

Avoid rebuilding on every run:

```yaml
- uses: actions/cache@v3
  with:
    path: ~/.cargo/bin/mcp-sentinel
    key: mcp-sentinel-v2.6.0
```

### 4. Use Baseline Comparison

Only fail on new vulnerabilities:

```bash
# Create baseline on main branch
mcp-sentinel scan --baseline ./ > baseline.json

# Compare on PR
mcp-sentinel scan --compare-baseline baseline.json --fail-on-new ./
```

### 5. Configure API Keys Securely

Store API keys in CI/CD secrets:

```yaml
env:
  NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
  VULNERABLE_MCP_API_KEY: ${{ secrets.VULNERABLE_MCP_API_KEY }}
```

### 6. Upload Multiple Report Formats

Provide reports for both humans and tools:

```bash
mcp-sentinel scan --format json --output results.json ./
mcp-sentinel scan --format html --output results.html ./
mcp-sentinel scan --format sarif --output results.sarif ./
```

### 7. Set Timeout

Prevent hanging scans:

```yaml
timeout-minutes: 10
```

### 8. Exclude Unnecessary Files

Speed up scans by excluding:

```bash
mcp-sentinel scan \
  --exclude "node_modules/**" \
  --exclude "dist/**" \
  --exclude "test/**" \
  ./
```

### 9. Parallel Scans for Monorepos

```yaml
strategy:
  matrix:
    project: [frontend, backend, api]
steps:
  - run: mcp-sentinel scan ./${{ matrix.project }}
```

### 10. Send Notifications

Alert team on failures:

```yaml
- name: Notify Slack
  if: failure()
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "Security scan failed on ${{ github.repository }}"
      }
```

---

## Example: Complete Production Pipeline

**Complete .github/workflows/security.yml**:

```yaml
name: Security Pipeline

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  security-scan:
    runs-on: ubuntu-latest
    timeout-minutes: 10

    permissions:
      contents: read
      security-events: write
      pull-requests: write

    steps:
      - uses: actions/checkout@v4

      - name: Cache MCP Sentinel
        uses: actions/cache@v3
        id: cache-mcp
        with:
          path: ~/.cargo/bin/mcp-sentinel
          key: mcp-sentinel-v2.6.0

      - name: Install MCP Sentinel
        if: steps.cache-mcp.outputs.cache-hit != 'true'
        run: |
          git clone https://github.com/beejak/MCP_Scanner.git /tmp/mcp
          cd /tmp/mcp && git checkout v2.6.0
          cargo build --release
          mkdir -p ~/.cargo/bin
          cp target/release/mcp-sentinel ~/.cargo/bin/

      - name: Run security scan (all formats)
        run: |
          mcp-sentinel scan --format json --output results.json ./
          mcp-sentinel scan --format sarif --output results.sarif ./
          mcp-sentinel scan --format html --output results.html ./
        env:
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: results.sarif

      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-reports
          path: results.*

      - name: Check for critical/high vulnerabilities
        run: mcp-sentinel scan --fail-on critical,high ./

      - name: Comment on PR
        uses: actions/github-script@v6
        if: github.event_name == 'pull_request' && always()
        with:
          script: |
            const fs = require('fs');
            const results = JSON.parse(fs.readFileSync('results.json'));
            const critical = results.vulnerabilities.filter(v => v.severity === 'critical').length;
            const high = results.vulnerabilities.filter(v => v.severity === 'high').length;

            const status = (critical + high) === 0 ? '✅ PASSED' : '❌ FAILED';
            const comment = `## Security Scan ${status}\n\n` +
              `**Critical**: ${critical} | **High**: ${high}\n\n` +
              `[View full report](https://github.com/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId})`;

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```

---

## Troubleshooting CI/CD

### Issue: Scan takes too long

**Solution**: Exclude unnecessary directories
```bash
mcp-sentinel scan --exclude "node_modules/**" --exclude "test/**" ./
```

### Issue: Cache not working

**Solution**: Verify cache key matches
```yaml
key: mcp-sentinel-${{ hashFiles('.mcp-version') }}
```

### Issue: SARIF upload fails

**Solution**: Ensure `security-events: write` permission
```yaml
permissions:
  security-events: write
```

---

**📚 More Examples**: See `docs/examples/` for additional CI/CD configurations.
