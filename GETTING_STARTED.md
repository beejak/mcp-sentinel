# Getting Started with MCP Sentinel

Welcome! This guide will help you get MCP Sentinel up and running in minutes.

## Quick Start (5 Minutes)

### Option 1: Using Poetry (Recommended for Development)

```bash
# 1. Clone the repository
git clone https://github.com/beejak/mcp-sentinel.git
cd mcp-sentinel

# 2. Install Poetry (if not already installed)
curl -sSL https://install.python-poetry.org | python3 -

# 3. Install dependencies
poetry install

# 4. Run your first scan!
poetry run mcp-sentinel scan /path/to/your/project

# 5. View beautiful results in your terminal
```

### Option 2: Using Docker (Production-Ready)

```bash
# 1. Pull the image
docker pull ghcr.io/mcp-sentinel/mcp-sentinel:latest

# 2. Scan your project
docker run --rm -v $(pwd):/workspace \
  ghcr.io/mcp-sentinel/mcp-sentinel:latest \
  scan /workspace
```

### Option 3: Using pip

```bash
# 1. Install
pip install mcp-sentinel

# 2. Scan
mcp-sentinel scan /path/to/project
```

## Your First Scan

Let's scan a project for hardcoded secrets:

```bash
# Scan current directory
poetry run mcp-sentinel scan .

# Scan with JSON output
poetry run mcp-sentinel scan . --output json

# Filter critical findings only
poetry run mcp-sentinel scan . --severity critical --severity high

# Save results to file
poetry run mcp-sentinel scan . --output json --json-file results.json
```

## Understanding the Results

MCP Sentinel will show you:

```
┌─────────── Scan Summary ───────────┐
│ Target      │ /path/to/project     │
│ Status      │ COMPLETED            │
│ Files Scanned│ 95/100              │
│ Duration    │ 3.45s                │
│ Total Vulns │ 12                   │
└─────────────────────────────────────┘

┌── Vulnerabilities by Severity ──┐
│ CRITICAL │ 2                      │
│ HIGH     │ 5                      │
│ MEDIUM   │ 3                      │
│ LOW      │ 2                      │
└──────────────────────────────────┘

Detailed Findings:

1. CRITICAL - Hardcoded AWS Access Key
   File: src/config.py:42
   AWS access key found: AKIA.... This grants programmatic access to AWS resources.
   Code: AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

2. HIGH - Hardcoded OpenAI API Key
   File: src/ai/client.py:15
   OpenAI API Key found: sk-12.... This provides access to OpenAI's API services.
   Code: OPENAI_KEY = "sk-1234567890..."
```

## What Does MCP Sentinel Detect?

### Currently Implemented (v4.1.0)

✅ **Secrets Detection (15+ types)** - 100% pass rate
- AWS Access Keys & Secret Keys
- OpenAI API Keys
- Anthropic Claude API Keys
- Google API Keys
- GitHub Personal Access Tokens
- Slack Tokens
- JWT Tokens
- Private Keys (RSA, EC, OpenSSH)
- Database Connection Strings (PostgreSQL, MySQL)
- Generic API Keys

✅ **Code Injection Detection** - Pattern + comment analysis

✅ **Prompt Injection Detection** - AI-specific attacks

✅ **Tool Poisoning Detection** - 40/40 tests passing

✅ **Supply Chain Security** - Dependency vulnerabilities

✅ **XSS Detection** - Cross-site scripting patterns

✅ **Path Traversal Detection** - Directory traversal attacks

✅ **Config Security** - 92.2% pass rate

✅ **SAST Integration (Phase 4.1)** - Semgrep + Bandit
- 1000+ security rules via Semgrep
- Python-specific checks via Bandit
- Multi-engine orchestration
- 26/26 tests passing

**Overall Status**: 373 tests, 344 passing (92.2%), 79.44% coverage

### Coming Soon

🔜 **Semantic Analysis** (Phase 4.2) - AST-based dataflow
🔜 **AI-Powered Analysis** (Phase 4.3) - Multi-LLM support

## Common Use Cases

### 1. Pre-Commit Scanning

Catch secrets before they hit your repository:

```bash
# In your project
poetry run mcp-sentinel scan . --severity critical

# Add to .git/hooks/pre-commit
#!/bin/sh
poetry run mcp-sentinel scan . --severity critical || exit 1
```

### 2. CI/CD Integration

Add to your GitHub Actions workflow:

```yaml
- name: Security Scan
  run: |
    pip install mcp-sentinel
    mcp-sentinel scan . --output sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### 3. Developer Workflow

Scan before every commit:

```bash
# Quick scan
mcp-sentinel scan src/

# Deep scan with all engines (when ready)
mcp-sentinel audit .

# Monitor for changes
mcp-sentinel monitor . --interval 300
```

## Configuration

Create a `.mcp-sentinel.yaml` file:

```bash
# Generate default config
poetry run mcp-sentinel init
```

Customize it:

```yaml
# .mcp-sentinel.yaml

# Engines to enable
engines:
  static: true     # Pattern-based detection (default)
  sast: true       # Semgrep + Bandit (Phase 4.1 complete)
  semantic: false  # AST dataflow analysis (Phase 4.2 planned)
  ai: false        # Multi-LLM analysis (Phase 4.3 planned)

# Reporting
reporting:
  formats: [terminal, json]
  output_dir: ./reports

# Performance
performance:
  max_workers: 4
  parallel_execution: true
```

## Environment Variables

For sensitive configuration:

```bash
# Copy example
cp .env.example .env

# Edit with your values
nano .env
```

Key variables:

```bash
# AI Providers (optional for now)
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...

# Integrations (coming in Phase 4)
JIRA_URL=https://your-company.atlassian.net
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
```

## Development Setup

Want to contribute? Here's how to set up for development:

```bash
# 1. Fork and clone
git clone https://github.com/beejak/mcp-sentinel.git
cd mcp-sentinel

# 2. Install dependencies (including dev tools)
poetry install --with dev

# 3. Install pre-commit hooks
poetry run pre-commit install

# 4. Run tests
poetry run pytest

# 5. Run with coverage
poetry run pytest --cov=mcp_sentinel --cov-report=html

# 6. Check code quality
poetry run black src/ tests/
poetry run ruff check src/ tests/
poetry run mypy src/

# 7. Run the scanner locally
poetry run mcp-sentinel scan .
```

## Docker Development

```bash
# Build image
docker build -t mcp-sentinel:dev .

# Run scan
docker run --rm -v $(pwd):/workspace mcp-sentinel:dev scan /workspace

# Full stack with docker-compose
docker-compose up -d

# Check services
docker-compose ps

# View logs
docker-compose logs -f api

# Access API docs
open http://localhost:8000/docs
```

## Troubleshooting

### "Command not found: mcp-sentinel"

Make sure you're in the Poetry shell or use `poetry run`:

```bash
# Option 1: Activate shell
poetry shell
mcp-sentinel scan .

# Option 2: Use poetry run
poetry run mcp-sentinel scan .
```

### "ModuleNotFoundError: No module named 'mcp_sentinel'"

Install the project:

```bash
poetry install
```

### "Permission denied" on scans

Make sure you have read access to the target directory.

### Tests failing

Make sure all dependencies are installed:

```bash
poetry install --with dev
poetry run pytest -v
```

## Next Steps

Now that you have MCP Sentinel running:

1. **Scan your projects**: Start finding secrets in your codebase
2. **Read the docs**: Check out [PYTHON_REWRITE_ARCHITECTURE.md](../PYTHON_REWRITE_ARCHITECTURE.md)
3. **Contribute**: See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines
4. **Follow the roadmap**: Watch [IMPLEMENTATION_ROADMAP.md](../IMPLEMENTATION_ROADMAP.md) for updates

## Getting Help

- **Issues**: https://github.com/beejak/mcp-sentinel/issues
- **Discussions**: https://github.com/beejak/mcp-sentinel/discussions
- **Documentation**: Check the `docs/` directory
- **Status**: See [PROJECT_STATUS.md](PROJECT_STATUS.md) for current state

## Examples

Check the `examples/` directory (coming soon) for:
- GitHub Actions workflows
- GitLab CI configs
- Pre-commit hook templates
- Custom detector examples
- Integration examples

---

**Happy Scanning! 🔍🛡️**

Found a secret? Great! Now let's secure it properly. 🔐
