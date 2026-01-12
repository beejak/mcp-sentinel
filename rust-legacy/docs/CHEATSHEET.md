# MCP Sentinel - Command Cheat Sheet

**Version:** 2.5.0
**Quick Reference:** Essential commands for everyday use

---

## 📥 Installation

### 🐳 Docker (Recommended - Zero Dependencies)
```bash
# Pull image
docker pull ghcr.io/beejak/mcp-sentinel:2.5.0

# Quick test
docker run --rm ghcr.io/beejak/mcp-sentinel:2.5.0 --version

# Scan current directory
docker run --rm -v $(pwd):/workspace ghcr.io/beejak/mcp-sentinel:2.5.0 scan /workspace
```

### 📦 Binary Installation
```bash
# Download binary (fastest native performance)
wget https://github.com/beejak/MCP_Scanner/releases/download/v2.5.0/mcp-sentinel-linux-x86_64
chmod +x mcp-sentinel-linux-x86_64
sudo mv mcp-sentinel-linux-x86_64 /usr/local/bin/mcp-sentinel
```

### 🦀 Cargo Installation
```bash
cargo install mcp-sentinel
```

### ✅ Verify Installation
```bash
mcp-sentinel --version  # Binary/Cargo
docker run --rm ghcr.io/beejak/mcp-sentinel:2.5.0 --version  # Docker
```

---

## 🐳 Docker Usage

### Basic Scans
```bash
# Scan current directory
docker run --rm -v $(pwd):/workspace ghcr.io/beejak/mcp-sentinel:2.5.0 scan /workspace

# Scan with Semgrep
docker run --rm -v $(pwd):/workspace ghcr.io/beejak/mcp-sentinel:2.5.0 scan /workspace --enable-semgrep

# Deep analysis with AI (requires Ollama)
docker-compose --profile ai up -d ollama
docker-compose --profile ai run --rm mcp-sentinel-deep

# Scan GitHub URL
docker run --rm ghcr.io/beejak/mcp-sentinel:2.5.0 scan https://github.com/owner/repo
```

### Generate Reports
```bash
# JSON output
docker run --rm -v $(pwd):/workspace ghcr.io/beejak/mcp-sentinel:2.5.0 \
  scan /workspace --output json --output-file /workspace/results.json

# HTML report
docker run --rm -v $(pwd):/workspace ghcr.io/beejak/mcp-sentinel:2.5.0 \
  scan /workspace --output html --output-file /workspace/report.html

# SARIF for CI/CD
docker run --rm -v $(pwd):/workspace ghcr.io/beejak/mcp-sentinel:2.5.0 \
  scan /workspace --output sarif --output-file /workspace/results.sarif
```

### Docker Compose Workflows
```bash
# Build image locally
docker-compose build

# Basic scan (uses default command)
docker-compose run --rm mcp-sentinel scan /workspace

# CI/CD mode (fail on high, JSON output)
docker-compose run --rm mcp-sentinel-ci

# Deep analysis with AI
docker-compose --profile ai up -d ollama
docker-compose --profile ai run --rm mcp-sentinel-deep

# Interactive shell
docker-compose run --rm --entrypoint /bin/bash mcp-sentinel

# Clean up
docker-compose down -v
docker-compose --profile ai down -v  # Include AI services
```

### Environment Variables (Docker)
```bash
# Using .env file (recommended)
cat > .env << 'EOF'
RUST_LOG=debug
MCP_SENTINEL_API_KEY=sk-...
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
EOF

docker-compose run --rm mcp-sentinel scan /workspace

# Inline environment variables
docker run --rm \
  -v $(pwd):/workspace \
  -e RUST_LOG=debug \
  -e MCP_SENTINEL_API_KEY=sk-... \
  ghcr.io/beejak/mcp-sentinel:2.5.0 \
  scan /workspace --mode deep
```

### Docker + CI/CD
```bash
# GitHub Actions
docker run --rm \
  -v ${{ github.workspace }}:/workspace \
  ghcr.io/beejak/mcp-sentinel:2.5.0 \
  scan /workspace --fail-on high --output sarif --output-file /workspace/results.sarif

# GitLab CI
docker run --rm \
  -v $(pwd):/workspace \
  ghcr.io/beejak/mcp-sentinel:2.5.0 \
  scan /workspace --enable-semgrep --fail-on high --output json --output-file /workspace/report.json

# Jenkins Pipeline
sh 'docker run --rm -v $WORKSPACE:/workspace ghcr.io/beejak/mcp-sentinel:2.5.0 scan /workspace --fail-on high'
```

### Advanced Docker Usage
```bash
# Scan multiple directories
docker run --rm \
  -v $(pwd)/server1:/server1:ro \
  -v $(pwd)/server2:/server2:ro \
  ghcr.io/beejak/mcp-sentinel:2.5.0 \
  scan /server1 /server2

# Custom config file
docker run --rm \
  -v $(pwd):/workspace \
  -v $(pwd)/custom-config.yaml:/config.yaml:ro \
  ghcr.io/beejak/mcp-sentinel:2.5.0 \
  scan /workspace --config /config.yaml

# Resource limits
docker run --rm \
  --cpus=2 \
  --memory=2g \
  -v $(pwd):/workspace \
  ghcr.io/beejak/mcp-sentinel:2.5.0 \
  scan /workspace

# Run as specific user (match host UID)
docker run --rm \
  --user $(id -u):$(id -g) \
  -v $(pwd):/workspace \
  ghcr.io/beejak/mcp-sentinel:2.5.0 \
  scan /workspace
```

### Docker Troubleshooting
```bash
# Check if image exists
docker images | grep mcp-sentinel

# Pull latest image
docker pull ghcr.io/beejak/mcp-sentinel:latest

# View container logs
docker-compose logs mcp-sentinel

# Check Ollama status
docker-compose --profile ai ps
curl http://localhost:11434/api/tags

# Rebuild image (if Dockerfile changed)
docker-compose build --no-cache

# Remove old images
docker rmi ghcr.io/beejak/mcp-sentinel:2.5.0
```

**📘 For complete Docker documentation:** [docs/DOCKER.md](DOCKER.md)

---

## ⚡ Quick Scans (Most Common)

```bash
# Quick scan (pattern matching only)
mcp-sentinel scan ./my-server

# Scan with Semgrep (+40% coverage)
mcp-sentinel scan ./my-server --enable-semgrep

# Comprehensive scan (all engines)
mcp-sentinel scan ./my-server --mode deep --enable-semgrep --llm-provider ollama

# Scan GitHub repository directly
mcp-sentinel scan https://github.com/owner/repo

# Fail CI/CD on high-severity issues
mcp-sentinel scan ./my-server --fail-on high
```

---

## 🆕 v2.5.0 Features

### 🌳 Semantic Analysis (Automatic)
```bash
# Automatically runs for Python, JavaScript, TypeScript, Go
mcp-sentinel scan ./python-server  # Tree-sitter AST parsing enabled

# Shows dataflow analysis in output
mcp-sentinel scan ./server --verbose
```

### 🔍 Semgrep Integration
```bash
# Enable Semgrep (requires: pip install semgrep)
mcp-sentinel scan ./server --enable-semgrep

# With custom rules
export MCP_SENTINEL_SEMGREP_RULES=/path/to/rules.yaml
mcp-sentinel scan ./server --enable-semgrep
```

### 🐙 GitHub URL Scanning
```bash
# Scan repository (main branch)
mcp-sentinel scan https://github.com/owner/repo

# Scan specific branch
mcp-sentinel scan https://github.com/owner/repo/tree/develop

# Scan specific tag/release
mcp-sentinel scan https://github.com/owner/repo/tree/v1.2.3

# Scan specific commit
mcp-sentinel scan https://github.com/owner/repo/commit/abc123def

# With Semgrep and severity filter
mcp-sentinel scan https://github.com/owner/repo --enable-semgrep --severity high
```

### 📊 HTML Reports
```bash
# Generate HTML dashboard
mcp-sentinel scan ./server --output html --output-file report.html

# Comprehensive HTML audit
mcp-sentinel scan ./server \
  --mode deep \
  --enable-semgrep \
  --llm-provider ollama \
  --output html \
  --output-file audit.html

# Open in browser
open report.html  # macOS
xdg-open report.html  # Linux
```

---

## 🎯 Common Workflows

### Development (Fast Feedback)
```bash
# Quick scan during development
mcp-sentinel scan .

# Watch mode (not yet implemented - Phase 3)
# mcp-sentinel monitor . --watch
```

### Pre-Commit / Pre-Push
```bash
# Fail on medium+ issues
mcp-sentinel scan . --fail-on medium

# Quick check before commit
mcp-sentinel scan . --severity high --no-color
```

### CI/CD Pipeline
```bash
# SARIF output for GitHub Code Scanning
mcp-sentinel scan . \
  --fail-on high \
  --output sarif \
  --output-file results.sarif

# JSON output for custom processing
mcp-sentinel scan . \
  --enable-semgrep \
  --fail-on medium \
  --output json \
  --output-file scan-results.json
```

### Security Audit (Comprehensive)
```bash
# Maximum coverage audit
mcp-sentinel scan ./server \
  --mode deep \
  --enable-semgrep \
  --llm-provider openai \
  --llm-model gpt-4o \
  --severity low \
  --output html \
  --output-file security-audit-$(date +%Y-%m-%d).html
```

### Third-Party Evaluation
```bash
# Audit dependency before installing
mcp-sentinel scan https://github.com/vendor/mcp-server \
  --enable-semgrep \
  --fail-on high \
  --output html \
  --output-file vendor-audit.html
```

---

## 🚦 Output Formats

```bash
# Terminal (default, colored)
mcp-sentinel scan ./server

# JSON (for CI/CD)
mcp-sentinel scan ./server --output json

# JSON to file
mcp-sentinel scan ./server --output json --output-file results.json

# SARIF (for GitHub/GitLab)
mcp-sentinel scan ./server --output sarif --output-file results.sarif

# HTML (v2.5.0 - interactive dashboard)
mcp-sentinel scan ./server --output html --output-file report.html

# Disable colors (CI logs)
mcp-sentinel scan ./server --no-color
```

---

## 🔧 Configuration

### Quick Config (In-Project)
```bash
# Create project config
cat > .mcp-sentinel.yaml << 'EOF'
version: "1.0"
mode: quick
min_severity: medium
exclude_patterns:
  - "node_modules/"
  - "tests/"
  - ".git/"
EOF

# Use it
mcp-sentinel scan .
```

### User Config (Home Directory)
```bash
# Create user config
mkdir -p ~/.mcp-sentinel
cat > ~/.mcp-sentinel/config.yaml << 'EOF'
version: "1.0"
mode: quick
min_severity: low
parallel_workers: 8

llm:
  provider: ollama
  model: llama3.2:8b
EOF

# Applies to all scans
mcp-sentinel scan ./any-server
```

### Custom Config File
```bash
# Use specific config
mcp-sentinel scan ./server --config custom-config.yaml
```

### Priority: CLI > Project > User > Defaults
```bash
# CLI flags override everything
mcp-sentinel scan . --mode deep --config .mcp-sentinel.yaml
# Uses deep mode (CLI) even if config says quick
```

---

## 🧠 AI Analysis (Deep Mode)

```bash
# Local AI (Ollama - free, private)
mcp-sentinel scan ./server --mode deep --llm-provider ollama

# OpenAI GPT-4
mcp-sentinel scan ./server --mode deep --llm-provider openai --llm-api-key sk-...

# Anthropic Claude
mcp-sentinel scan ./server --mode deep --llm-provider anthropic --llm-api-key sk-ant-...

# Google Gemini (cheapest)
mcp-sentinel scan ./server --mode deep --llm-provider gemini --llm-api-key AIza...

# With environment variable (recommended)
export MCP_SENTINEL_API_KEY=sk-...
mcp-sentinel scan ./server --mode deep --llm-provider openai

# Specific model
mcp-sentinel scan ./server --mode deep --llm-provider openai --llm-model gpt-4o
```

---

## 🎚️ Severity Filtering

```bash
# Show all issues (default)
mcp-sentinel scan ./server --severity low

# Show medium and above
mcp-sentinel scan ./server --severity medium

# Show only high and critical
mcp-sentinel scan ./server --severity high

# Show only critical
mcp-sentinel scan ./server --severity critical

# Fail on specific level
mcp-sentinel scan ./server --fail-on high  # Exit 1 if high+ found
```

---

## 🚦 Exit Codes (CI/CD)

```bash
# Exit code meanings:
# 0 = Success (no issues or below threshold)
# 1 = Vulnerabilities found (at/above --fail-on level)
# 2 = Scan error (target not found, permission denied)
# 3 = Usage error (invalid arguments)

# Check exit code
mcp-sentinel scan ./server --fail-on high
echo $?  # 0 or 1

# Use in scripts
if mcp-sentinel scan . --fail-on high; then
  echo "✅ Security check passed"
else
  echo "❌ Security issues found"
  exit 1
fi
```

---

## 🔬 Debug & Troubleshooting

```bash
# Verbose logging
mcp-sentinel scan ./server --verbose

# Very verbose (trace level)
RUST_LOG=mcp_sentinel=trace mcp-sentinel scan ./server

# Disable progress indicators
MCP_SENTINEL_NO_PROGRESS=1 mcp-sentinel scan ./server

# Check if Semgrep is available
which semgrep
semgrep --version

# Check if Ollama is running
curl http://localhost:11434/api/tags
```

---

## 📚 Common One-Liners

### Local Development
```bash
# Fast feedback loop
mcp-sentinel scan . && echo "✅ Clean" || echo "❌ Issues found"
```

### GitHub Actions
```bash
# In workflow file
mcp-sentinel scan . --fail-on high --output sarif --output-file results.sarif
```

### Pre-Commit Hook
```bash
# .git/hooks/pre-commit
#!/bin/bash
mcp-sentinel scan . --fail-on medium --no-color || exit 1
```

### Audit All Dependencies
```bash
# Create audit script
cat > audit-deps.sh << 'EOF'
#!/bin/bash
for repo in \
  "https://github.com/vendor-a/mcp-server" \
  "https://github.com/vendor-b/mcp-toolkit" \
  "https://github.com/vendor-c/mcp-utils"
do
  echo "🔍 Auditing $repo..."
  mcp-sentinel scan "$repo" --enable-semgrep --severity high
done
EOF
chmod +x audit-deps.sh
./audit-deps.sh
```

### Daily Security Scan
```bash
# Cron job (daily at 2am)
0 2 * * * cd /app && mcp-sentinel scan . --enable-semgrep --output json --output-file scan-$(date +\%Y\%m\%d).json
```

### Compare Before/After Fix
```bash
# Before fix
mcp-sentinel scan . --output json --output-file before.json

# After fix
mcp-sentinel scan . --output json --output-file after.json

# Compare (using jq)
diff <(jq -S .summary before.json) <(jq -S .summary after.json)
```

---

## 🌐 Environment Variables

```bash
# API key for cloud LLM providers
export MCP_SENTINEL_API_KEY=sk-...

# Default config file location
export MCP_SENTINEL_CONFIG=/path/to/config.yaml

# Log level
export MCP_SENTINEL_LOG_LEVEL=debug  # debug, info, warn, error

# Disable colors
export NO_COLOR=1

# Disable progress indicators
export MCP_SENTINEL_NO_PROGRESS=1

# Rust logging (very verbose)
export RUST_LOG=mcp_sentinel=trace

# Custom Semgrep path
export SEMGREP_PATH=/custom/path/to/semgrep

# Custom Semgrep rules
export MCP_SENTINEL_SEMGREP_RULES=/path/to/rules.yaml

# Ollama custom host
export OLLAMA_HOST=http://remote-server:11434
```

---

## 🎯 Performance Tips

```bash
# Fast scan (pattern matching only)
mcp-sentinel scan . --mode quick  # ~2s for small projects

# Skip Semgrep (saves 10-15s)
mcp-sentinel scan .  # Don't add --enable-semgrep

# Reduce workers (lower CPU usage)
mcp-sentinel scan . --config <(echo "parallel_workers: 2")

# Exclude large directories
cat > .mcp-sentinel.yaml << 'EOF'
exclude_patterns:
  - "node_modules/"
  - "vendor/"
  - "dist/"
  - ".git/"
EOF

# Skip AI analysis (saves ~30-60s)
mcp-sentinel scan . --mode quick  # Instead of deep
```

---

## 🔗 Integration Examples

### GitHub Actions

**🐳 Using Docker (Recommended):**
```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run MCP Sentinel (Docker)
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/workspace \
            ghcr.io/beejak/mcp-sentinel:2.5.0 \
            scan /workspace --enable-semgrep --fail-on high --output sarif --output-file /workspace/results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

**Binary Installation (Alternative):**
```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install MCP Sentinel
        run: |
          wget https://github.com/beejak/MCP_Scanner/releases/download/v2.5.0/mcp-sentinel-linux-x86_64
          chmod +x mcp-sentinel-linux-x86_64
          sudo mv mcp-sentinel-linux-x86_64 /usr/local/bin/mcp-sentinel
          pip install semgrep

      - name: Scan
        run: |
          mcp-sentinel scan . \
            --enable-semgrep \
            --fail-on high \
            --output sarif \
            --output-file results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI

**🐳 Using Docker (Recommended):**
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
  allow_failure: false
```

**Binary Installation (Alternative):**
```yaml
# .gitlab-ci.yml
security_scan:
  stage: test
  image: rust:latest
  script:
    - apt-get update && apt-get install -y wget
    - wget https://github.com/beejak/MCP_Scanner/releases/download/v2.5.0/mcp-sentinel-linux-x86_64
    - chmod +x mcp-sentinel-linux-x86_64
    - ./mcp-sentinel-linux-x86_64 scan . --enable-semgrep --fail-on high --output json --output-file report.json
  artifacts:
    reports:
      codequality: report.json
  allow_failure: false
```

### CircleCI
```yaml
# .circleci/config.yml
version: 2.1

jobs:
  security-scan:
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
              scan /workspace --enable-semgrep --fail-on high

workflows:
  security:
    jobs:
      - security-scan
```

### Jenkins Pipeline
```groovy
// Jenkinsfile
pipeline {
    agent any

    stages {
        stage('Security Scan') {
            steps {
                script {
                    docker.image('ghcr.io/beejak/mcp-sentinel:2.5.0').inside('-v $WORKSPACE:/workspace') {
                        sh 'mcp-sentinel scan /workspace --enable-semgrep --fail-on high'
                    }
                }
            }
        }
    }
}
```

### Pre-Commit Hook
```bash
# .git/hooks/pre-commit
#!/bin/bash
set -e

echo "🔍 Running MCP Sentinel security scan..."
mcp-sentinel scan . --fail-on medium --no-color

if [ $? -eq 0 ]; then
  echo "✅ Security scan passed"
else
  echo "❌ Security issues found - commit blocked"
  echo "💡 Fix issues or run: git commit --no-verify"
  exit 1
fi
```

---

## 💡 Pro Tips

### Combine Multiple Engines
```bash
# Maximum vulnerability detection
mcp-sentinel scan ./server \
  --mode deep \              # Enable AI analysis
  --enable-semgrep \         # Enable Semgrep
  --llm-provider ollama      # Free local AI
# = 85% more coverage than basic scan
```

### Filter by Type
```bash
# Coming in future versions - for now use grep
mcp-sentinel scan . --output json | jq '.vulnerabilities[] | select(.type=="command_injection")'
```

### Generate Weekly Reports
```bash
# Weekly audit with HTML report
0 0 * * 0 cd /app && mcp-sentinel scan . \
  --enable-semgrep \
  --output html \
  --output-file /reports/weekly-$(date +\%Y-\%W).html
```

### Scan Modified Files Only (Git)
```bash
# Get changed files
CHANGED_FILES=$(git diff --name-only HEAD)

# Scan only if files exist
if [ -n "$CHANGED_FILES" ]; then
  echo "$CHANGED_FILES" | xargs mcp-sentinel scan
fi
```

### Compare Branches
```bash
# Scan main branch
git checkout main
mcp-sentinel scan . --output json --output-file main.json

# Scan feature branch
git checkout feature/new-feature
mcp-sentinel scan . --output json --output-file feature.json

# Compare vulnerability counts
echo "Main: $(jq '.summary.total_vulnerabilities' main.json)"
echo "Feature: $(jq '.summary.total_vulnerabilities' feature.json)"
```

---

## 🆘 Common Issues

### "Semgrep not found"
```bash
pip install semgrep
# Or: brew install semgrep (macOS)
```

### "Ollama connection refused"
```bash
# Start Ollama
ollama serve

# Or use cloud provider
mcp-sentinel scan . --mode deep --llm-provider openai
```

### "Permission denied"
```bash
# Check permissions
ls -la /path/to/server

# Fix if needed
chmod -R u+r /path/to/server
```

### "Target not found"
```bash
# Use absolute path
mcp-sentinel scan $(pwd)/my-server

# Or check spelling
ls -d ./my-server
```

### Scan too slow
```bash
# Use quick mode
mcp-sentinel scan . --mode quick

# Skip Semgrep
mcp-sentinel scan .  # Without --enable-semgrep

# Exclude large directories (see .mcp-sentinel.yaml above)
```

---

## 📚 More Resources

- [Full Documentation](CLI_REFERENCE.md) - Complete command reference
- [Sample Reports](samples/) - See example outputs
- [Architecture](ARCHITECTURE_PHASE_2_5.md) - Technical details
- [Release Notes](../RELEASE_NOTES_v2.5.0.md) - What's new in v2.5.0
- [GitHub Repository](https://github.com/beejak/MCP_Scanner) - Source code & issues

---

## 🎓 Quick Learning Path

**5 minutes:** Basic scan
```bash
mcp-sentinel scan ./server
```

**10 minutes:** Add Semgrep
```bash
pip install semgrep
mcp-sentinel scan ./server --enable-semgrep
```

**15 minutes:** Generate HTML report
```bash
mcp-sentinel scan ./server --enable-semgrep --output html --output-file report.html
open report.html
```

**20 minutes:** Set up CI/CD
```bash
# Copy GitHub Actions example above
# Add to .github/workflows/security.yml
```

**30 minutes:** Comprehensive audit
```bash
# Install Ollama: https://ollama.ai
ollama pull llama3.2:8b
mcp-sentinel scan ./server --mode deep --enable-semgrep --llm-provider ollama
```

---

**Version:** 2.5.0
**Last Updated:** October 26, 2025
**Found an issue?** [Report it](https://github.com/beejak/MCP_Scanner/issues)
