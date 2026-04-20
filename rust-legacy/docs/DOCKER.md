# MCP Sentinel - Docker Guide

**Version:** 2.5.0
**Purpose:** Complete guide to running MCP Sentinel in Docker

---

## 📋 Table of Contents

1. [Quick Start](#-quick-start)
2. [Installation](#-installation)
3. [Usage Examples](#-usage-examples)
4. [Docker Compose](#-docker-compose)
5. [Configuration](#-configuration)
6. [AI Analysis with Ollama](#-ai-analysis-with-ollama)
7. [CI/CD Integration](#-cicd-integration)
8. [Advanced Usage](#-advanced-usage)
9. [Troubleshooting](#-troubleshooting)
10. [Best Practices](#-best-practices)

---

## 🚀 Quick Start

```bash
# Pull pre-built image (when available)
docker pull ghcr.io/beejak/mcp-sentinel:2.5.0

# Or build locally
git clone https://github.com/beejak/MCP_Scanner
cd MCP_Scanner
docker build -t mcp-sentinel:2.5.0 .

# Run a scan
docker run --rm -v $(pwd):/workspace mcp-sentinel:2.5.0 scan /workspace

# With Semgrep
docker run --rm -v $(pwd):/workspace mcp-sentinel:2.5.0 scan /workspace --enable-semgrep

# Generate HTML report
docker run --rm -v $(pwd):/workspace mcp-sentinel:2.5.0 \
  scan /workspace --output html --output-file /workspace/report.html
```

---

## 📥 Installation

### Option 1: Pre-Built Image (Recommended)

```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/beejak/mcp-sentinel:2.5.0
docker pull ghcr.io/beejak/mcp-sentinel:latest

# Tag for convenience
docker tag ghcr.io/beejak/mcp-sentinel:2.5.0 mcp-sentinel:2.5.0
```

### Option 2: Build from Source

```bash
# Clone repository
git clone https://github.com/beejak/MCP_Scanner
cd MCP_Scanner

# Build image
docker build -t mcp-sentinel:2.5.0 .

# Verify
docker run --rm mcp-sentinel:2.5.0 --version
```

**Build Options:**

```bash
# Build with custom Rust version
docker build --build-arg RUST_VERSION=1.72 -t mcp-sentinel:custom .

# Build without cache (clean build)
docker build --no-cache -t mcp-sentinel:2.5.0 .

# View build progress
docker build --progress=plain -t mcp-sentinel:2.5.0 .
```

---

## 💻 Usage Examples

### Basic Scans

```bash
# Scan current directory
docker run --rm -v $(pwd):/workspace mcp-sentinel:2.5.0 scan /workspace

# Scan specific directory
docker run --rm -v /path/to/server:/workspace mcp-sentinel:2.5.0 scan /workspace

# Scan with Semgrep
docker run --rm -v $(pwd):/workspace mcp-sentinel:2.5.0 \
  scan /workspace --enable-semgrep

# Fail on high-severity issues (CI/CD)
docker run --rm -v $(pwd):/workspace mcp-sentinel:2.5.0 \
  scan /workspace --fail-on high
```

### Output Formats

```bash
# JSON output
docker run --rm -v $(pwd):/workspace mcp-sentinel:2.5.0 \
  scan /workspace --output json --output-file /workspace/results.json

# SARIF output (for GitHub Code Scanning)
docker run --rm -v $(pwd):/workspace mcp-sentinel:2.5.0 \
  scan /workspace --output sarif --output-file /workspace/results.sarif

# HTML report
docker run --rm -v $(pwd):/workspace mcp-sentinel:2.5.0 \
  scan /workspace --output html --output-file /workspace/audit.html
```

### Severity Filtering

```bash
# Show only high and critical
docker run --rm -v $(pwd):/workspace mcp-sentinel:2.5.0 \
  scan /workspace --severity high

# Show all issues
docker run --rm -v $(pwd):/workspace mcp-sentinel:2.5.0 \
  scan /workspace --severity low
```

### GitHub URL Scanning

```bash
# Scan GitHub repository
docker run --rm mcp-sentinel:2.5.0 \
  scan https://github.com/owner/repo

# Scan specific branch
docker run --rm mcp-sentinel:2.5.0 \
  scan https://github.com/owner/repo/tree/develop

# With Semgrep and HTML output
docker run --rm -v $(pwd):/workspace mcp-sentinel:2.5.0 \
  scan https://github.com/owner/repo \
  --enable-semgrep \
  --output html \
  --output-file /workspace/vendor-audit.html
```

---

## 🐳 Docker Compose

Docker Compose provides easier orchestration for complex workflows.

### Basic Usage

```bash
# Scan with default settings
docker-compose run --rm mcp-sentinel scan /workspace

# With Semgrep
docker-compose run --rm mcp-sentinel scan /workspace --enable-semgrep

# Custom command
docker-compose run --rm mcp-sentinel scan /workspace --severity high --fail-on critical
```

### Pre-Configured Services

#### 1. CI/CD Mode

```bash
# Run CI-optimized scan
docker-compose run --rm mcp-sentinel-ci

# What it does:
# - Enables Semgrep
# - Fails on high+ issues
# - Outputs JSON to ./scan-results.json
# - No colors, no progress bars (CI-friendly)
```

#### 2. Deep Analysis with AI

```bash
# Start Ollama service
docker-compose --profile ai up -d ollama

# Wait for Ollama to be ready (30-60 seconds)
docker-compose --profile ai ps

# Pull AI model
docker-compose --profile ai run --rm ollama ollama pull llama3.2:8b

# Run deep analysis
docker-compose --profile ai run --rm mcp-sentinel-deep

# What it does:
# - Scans with all engines (static + semantic + Semgrep + AI)
# - Uses local Ollama for privacy
# - Generates comprehensive HTML report
```

### Environment Variables

Create `.env` file:

```bash
# .env file
RUST_LOG=info
MCP_SENTINEL_LOG_LEVEL=info

# API keys (optional - for cloud LLM)
MCP_SENTINEL_API_KEY=sk-...
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
```

Then run:

```bash
docker-compose run --rm mcp-sentinel scan /workspace --mode deep --llm-provider openai
```

---

## ⚙️ Configuration

### Volume Mounts

```bash
# Mount current directory (read-only for security)
-v $(pwd):/workspace:ro

# Mount specific directory
-v /path/to/mcp-server:/workspace

# Mount with write permissions (for reports)
-v $(pwd):/workspace

# Mount custom config
-v $(pwd)/.mcp-sentinel.yaml:/home/mcp/.mcp-sentinel/config.yaml:ro
```

### Environment Variables

```bash
# Logging
-e RUST_LOG=debug
-e MCP_SENTINEL_LOG_LEVEL=debug

# API keys
-e MCP_SENTINEL_API_KEY=sk-...
-e OPENAI_API_KEY=sk-...

# Performance
-e MCP_SENTINEL_NO_PROGRESS=1

# Disable colors (CI)
-e NO_COLOR=1

# Custom Semgrep
-e SEMGREP_PATH=/custom/path
-e MCP_SENTINEL_SEMGREP_RULES=/path/to/rules.yaml
```

### Complete Example

```bash
docker run --rm \
  -v $(pwd):/workspace \
  -v $(pwd)/.mcp-sentinel.yaml:/home/mcp/.mcp-sentinel/config.yaml:ro \
  -e RUST_LOG=debug \
  -e MCP_SENTINEL_API_KEY=sk-... \
  -e MCP_SENTINEL_NO_PROGRESS=1 \
  mcp-sentinel:2.5.0 \
  scan /workspace \
  --mode deep \
  --enable-semgrep \
  --llm-provider openai \
  --output html \
  --output-file /workspace/audit.html
```

---

## 🤖 AI Analysis with Ollama

Run AI-powered analysis locally with Ollama (free, private).

### Setup

```bash
# Start Ollama container
docker-compose --profile ai up -d ollama

# Check status
docker-compose --profile ai ps

# Pull model (first time only)
docker-compose --profile ai run --rm ollama ollama pull llama3.2:8b

# List available models
docker-compose --profile ai run --rm ollama ollama list
```

### Run Deep Analysis

```bash
# Using docker-compose
docker-compose --profile ai run --rm mcp-sentinel-deep

# Using docker run
docker run --rm \
  -v $(pwd):/workspace \
  --network mcp_scanner_default \
  -e OLLAMA_HOST=http://ollama:11434 \
  mcp-sentinel:2.5.0 \
  scan /workspace \
  --mode deep \
  --enable-semgrep \
  --llm-provider ollama \
  --output html \
  --output-file /workspace/comprehensive-audit.html
```

### Ollama Management

```bash
# View logs
docker-compose --profile ai logs ollama

# Restart Ollama
docker-compose --profile ai restart ollama

# Stop Ollama
docker-compose --profile ai down

# Clean up (removes models)
docker-compose --profile ai down -v
```

### Alternative Models

```bash
# Pull different model
docker-compose --profile ai run --rm ollama ollama pull codestral:22b

# Use in scan
docker run --rm \
  -v $(pwd):/workspace \
  --network mcp_scanner_default \
  -e OLLAMA_HOST=http://ollama:11434 \
  mcp-sentinel:2.5.0 \
  scan /workspace \
  --mode deep \
  --llm-provider ollama \
  --llm-model codestral:22b
```

---

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Run MCP Sentinel
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/workspace \
            ghcr.io/beejak/mcp-sentinel:2.5.0 \
            scan /workspace \
            --enable-semgrep \
            --fail-on high \
            --output sarif \
            --output-file /workspace/results.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
# .gitlab-ci.yml
security_scan:
  stage: test
  image: docker:latest
  services:
    - docker:dind

  script:
    - docker run --rm -v $(pwd):/workspace ghcr.io/beejak/mcp-sentinel:2.5.0
      scan /workspace --enable-semgrep --fail-on high --output json --output-file /workspace/report.json

  artifacts:
    reports:
      codequality: report.json
    paths:
      - report.json
    expire_in: 30 days

  allow_failure: false
```

### Jenkins

```groovy
// Jenkinsfile
pipeline {
    agent any

    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    docker run --rm \
                      -v ${WORKSPACE}:/workspace \
                      ghcr.io/beejak/mcp-sentinel:2.5.0 \
                      scan /workspace \
                      --enable-semgrep \
                      --fail-on high \
                      --output json \
                      --output-file /workspace/scan-results.json
                '''
            }
        }

        stage('Publish Results') {
            steps {
                archiveArtifacts artifacts: 'scan-results.json', fingerprint: true
            }
        }
    }

    post {
        always {
            publishHTML([
                reportDir: '.',
                reportFiles: 'scan-results.json',
                reportName: 'Security Scan Results'
            ])
        }
    }
}
```

### CircleCI

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  security_scan:
    docker:
      - image: docker:latest
    steps:
      - checkout
      - setup_remote_docker
      - run:
          name: Run MCP Sentinel
          command: |
            docker run --rm \
              -v $(pwd):/workspace \
              ghcr.io/beejak/mcp-sentinel:2.5.0 \
              scan /workspace \
              --enable-semgrep \
              --fail-on high \
              --output json \
              --output-file /workspace/results.json
      - store_artifacts:
          path: results.json

workflows:
  version: 2
  security:
    jobs:
      - security_scan
```

---

## 🎓 Advanced Usage

### Interactive Shell

```bash
# Enter container for debugging
docker run --rm -it \
  -v $(pwd):/workspace \
  --entrypoint /bin/bash \
  mcp-sentinel:2.5.0

# Inside container:
mcp-sentinel scan /workspace --verbose
mcp-sentinel --help
```

### Multi-Repository Scanning

```bash
#!/bin/bash
# scan-all.sh

REPOS=(
  "/path/to/repo1"
  "/path/to/repo2"
  "/path/to/repo3"
)

for REPO in "${REPOS[@]}"; do
  echo "Scanning $REPO..."
  docker run --rm \
    -v "$REPO:/workspace" \
    mcp-sentinel:2.5.0 \
    scan /workspace \
    --enable-semgrep \
    --output html \
    --output-file /workspace/audit-$(basename "$REPO").html
done
```

### Scheduled Scans (Cron)

```bash
# Add to crontab
# Daily scan at 2 AM
0 2 * * * docker run --rm -v /app:/workspace mcp-sentinel:2.5.0 scan /workspace --enable-semgrep --output json --output-file /app/scan-$(date +\%Y\%m\%d).json

# Weekly comprehensive scan
0 0 * * 0 docker-compose --profile ai run --rm mcp-sentinel-deep
```

### Resource Limits

```bash
# Limit CPU and memory
docker run --rm \
  --cpus=2.0 \
  --memory=2g \
  -v $(pwd):/workspace \
  mcp-sentinel:2.5.0 \
  scan /workspace

# With docker-compose (already configured in docker-compose.yml)
docker-compose run --rm mcp-sentinel scan /workspace
```

### Custom Network

```bash
# Create network
docker network create mcp-network

# Run Ollama
docker run -d \
  --name ollama \
  --network mcp-network \
  ollama/ollama:latest

# Run scanner
docker run --rm \
  --network mcp-network \
  -v $(pwd):/workspace \
  -e OLLAMA_HOST=http://ollama:11434 \
  mcp-sentinel:2.5.0 \
  scan /workspace --mode deep --llm-provider ollama
```

---

## 🔍 Troubleshooting

### Common Issues

#### "Permission denied" on mounted volumes

```bash
# Problem: Container can't read files
# Solution: Check file permissions

# Fix permissions
chmod -R a+r /path/to/scan

# Or run with current user
docker run --rm \
  --user $(id -u):$(id -g) \
  -v $(pwd):/workspace \
  mcp-sentinel:2.5.0 \
  scan /workspace
```

#### "Semgrep not found"

```bash
# Problem: Semgrep not in image
# Solution: Rebuild with Semgrep stage

docker build --no-cache -t mcp-sentinel:2.5.0 .

# Verify Semgrep is available
docker run --rm mcp-sentinel:2.5.0 semgrep --version
```

#### "Ollama connection refused"

```bash
# Problem: Can't reach Ollama service
# Solution: Check network and host

# Verify Ollama is running
docker-compose --profile ai ps

# Check logs
docker-compose --profile ai logs ollama

# Test connection
docker run --rm --network mcp_scanner_default curlimages/curl curl http://ollama:11434/api/tags
```

#### Container exits immediately

```bash
# Problem: Command syntax error
# Solution: Check command

# View help
docker run --rm mcp-sentinel:2.5.0 --help

# Run with verbose
docker run --rm -v $(pwd):/workspace mcp-sentinel:2.5.0 scan /workspace --verbose
```

#### Large image size

```bash
# Check image size
docker images mcp-sentinel:2.5.0

# Expected: ~250-300 MB
# If larger, rebuild:
docker build --no-cache -t mcp-sentinel:2.5.0 .

# Clean up build cache
docker builder prune
```

### Debug Mode

```bash
# Run with maximum verbosity
docker run --rm \
  -v $(pwd):/workspace \
  -e RUST_LOG=trace \
  -e MCP_SENTINEL_LOG_LEVEL=debug \
  mcp-sentinel:2.5.0 \
  scan /workspace --verbose
```

### View Container Logs

```bash
# With docker-compose
docker-compose logs mcp-sentinel
docker-compose --profile ai logs ollama

# With docker run (if running in detached mode)
docker logs mcp-sentinel-scanner
```

---

## ✅ Best Practices

### Security

```bash
# 1. Use read-only volumes when possible
-v $(pwd):/workspace:ro

# 2. Run as non-root (already default in our image)
# User 'mcp' is used automatically

# 3. Enable security options
docker run --rm \
  --security-opt no-new-privileges \
  --read-only \
  --tmpfs /tmp \
  -v $(pwd):/workspace \
  mcp-sentinel:2.5.0 \
  scan /workspace

# 4. Don't expose secrets in commands (use environment variables)
-e MCP_SENTINEL_API_KEY=sk-...  # From .env file
```

### Performance

```bash
# 1. Use specific tags (not 'latest')
mcp-sentinel:2.5.0  # Good
mcp-sentinel:latest  # Avoid in production

# 2. Set resource limits
--cpus=2.0 --memory=2g

# 3. Use docker-compose for complex workflows
docker-compose run --rm mcp-sentinel-ci

# 4. Clean up after use
docker run --rm ...  # Automatic cleanup
```

### CI/CD

```bash
# 1. Use --fail-on for quality gates
--fail-on high

# 2. Generate machine-readable output
--output json --output-file /workspace/results.json

# 3. Disable progress indicators
-e MCP_SENTINEL_NO_PROGRESS=1

# 4. Cache images in CI
# Use docker layer caching or registry caching
```

### Maintenance

```bash
# Clean up old containers
docker container prune

# Clean up old images
docker image prune

# Clean up everything (careful!)
docker system prune -a

# Update to latest
docker pull ghcr.io/beejak/mcp-sentinel:latest
```

---

## 📊 Image Details

### Image Layers

```
debian:bookworm-slim (base)           ~50 MB
├── System packages (git, curl)        ~30 MB
├── MCP Sentinel binary               ~20 MB
├── Semgrep + dependencies            ~150 MB
└── Configuration files                 ~1 MB
────────────────────────────────────────────
Total:                                ~250 MB
```

### What's Included

- ✅ MCP Sentinel v2.5.0 binary
- ✅ Semgrep 1.45.0
- ✅ Git (for GitHub URL scanning)
- ✅ Curl (for health checks)
- ✅ Python 3.11 (for Semgrep)
- ✅ Non-root user (mcp)
- ✅ Health check configured

### What's NOT Included

- ❌ Development tools
- ❌ Build artifacts
- ❌ Documentation
- ❌ Test fixtures
- ❌ Source code

---

## 🔗 Resources

- [Main README](../README.md) - Project overview
- [Command Cheat Sheet](CHEATSHEET.md) - Quick reference
- [CLI Reference](CLI_REFERENCE.md) - Complete documentation
- [GitHub Repository](https://github.com/beejak/MCP_Scanner)

---

## 🆘 Getting Help

- **Issues:** https://github.com/beejak/MCP_Scanner/issues
- **Discussions:** https://github.com/beejak/MCP_Scanner/discussions
- **Docker Hub:** (Coming soon)
- **GHCR:** ghcr.io/beejak/mcp-sentinel

---

**Version:** 2.5.0
**Last Updated:** October 26, 2025
**Maintained by:** MCP Sentinel Team
