# Quick Start Guide - 5 Minutes to Your First Scan

Get MCP Sentinel running in under 5 minutes! This guide covers installation and your first security scan.

## Prerequisites

- **Python 3.9+** (check: `python --version`)
- **pip** (check: `pip --version`)

## Step 1: Install MCP Sentinel (1 minute)

```bash
# Clone the repository
git clone https://github.com/beejak/mcp-sentinel.git
cd mcp-sentinel

# Install dependencies
pip install -e .
```

**Verify installation:**
```bash
mcp-sentinel --version
```

You should see: `MCP Sentinel version 4.3.0` (or later)

## Step 2: Run Your First Scan (30 seconds)

Scan the current directory with default engines (Static + SAST):

```bash
mcp-sentinel scan .
```

**What happens:**
- Scans all Python, JavaScript, TypeScript, Go, Java files
- Uses 2 engines: Static Analysis + SAST (Semgrep + Bandit)
- Shows findings in colored terminal output
- Takes ~5-30 seconds depending on codebase size

## Step 3: Generate an HTML Report (1 minute)

Create a beautiful interactive dashboard:

```bash
mcp-sentinel scan . --output html --json-file report.html
```

**Open the report:**
- Windows: `start report.html`
- Mac: `open report.html`
- Linux: `xdg-open report.html`

The HTML report includes:
- Executive summary with risk scoring
- Vulnerability breakdown by severity
- Interactive charts and graphs
- Code snippets with context
- Remediation guidance

## Step 4: Try All 4 Engines (2 minutes)

Run a comprehensive scan with all analysis engines:

```bash
mcp-sentinel scan . --engines all --output html --json-file full-scan.html
```

**4 Engines in Action:**
1. **Static Analysis** - Pattern-based detection (fast)
2. **SAST** - Semgrep + Bandit (industry standards)
3. **Semantic Analysis** - AST-based taint tracking (accurate)
4. **AI Analysis** - Claude 3.5 Sonnet (requires API key - see below)

**Note:** AI engine requires `ANTHROPIC_API_KEY` environment variable:
```bash
export ANTHROPIC_API_KEY=your-key-here  # Linux/Mac
set ANTHROPIC_API_KEY=your-key-here     # Windows
```

## Common Workflows

### CI/CD Integration (GitHub Actions)

Generate SARIF report for GitHub Code Scanning:

```bash
mcp-sentinel scan . --output sarif --json-file results.sarif
```

Upload `results.sarif` to GitHub Security tab. See [GitHub Actions Template](.github/workflows/mcp-sentinel-template.yml) for automation.

### Filter by Severity

Show only critical and high severity issues:

```bash
mcp-sentinel scan . --severity critical --severity high
```

### Scan Specific Directory

```bash
mcp-sentinel scan /path/to/your/project
```

### Production Scan Recipe

Comprehensive scan with filtering and reporting:

```bash
mcp-sentinel scan . \
  --engines all \
  --severity critical --severity high \
  --output html \
  --json-file production-scan.html
```

## Configuration (Optional)

Create a config file for project-specific settings:

```bash
mcp-sentinel init
```

This creates `.mcp-sentinel.yaml` with default settings. Edit to:
- Enable/disable specific engines
- Configure AI provider settings
- Set file inclusion/exclusion patterns
- Customize report formats
- Adjust performance settings

## What's Detected?

MCP Sentinel finds **8 vulnerability categories**:

| Category | Examples |
|----------|----------|
| **Hardcoded Secrets** | API keys, AWS credentials, passwords, tokens |
| **Code Injection** | SQL injection, command injection, eval abuse |
| **Prompt Injection** | AI manipulation, prompt leaking, jailbreaks |
| **XSS Vulnerabilities** | DOM XSS, stored XSS, reflected XSS |
| **Config Security** | Weak crypto, debug mode, exposed endpoints |
| **Path Traversal** | Directory traversal, path injection |
| **Tool Poisoning** | Invisible Unicode, homoglyph attacks |
| **Supply Chain** | Typosquatting, malicious packages |

## Performance Tips

### Fast Scans (5-10 seconds)
Use static analysis only for quick checks:
```bash
mcp-sentinel scan . --engines static
```

### Balanced Scans (10-30 seconds)
Default engines provide good coverage:
```bash
mcp-sentinel scan .  # static + sast
```

### Deep Scans (30-60 seconds)
Add semantic analysis for complex vulnerabilities:
```bash
mcp-sentinel scan . --engines static,sast,semantic
```

### Production Scans (1-5 minutes)
All engines including AI for maximum coverage:
```bash
mcp-sentinel scan . --engines all
```

## Troubleshooting

### "No module named 'mcp_sentinel'"
- Ensure you ran `pip install -e .` in the repo directory
- Check: `pip show mcp-sentinel`

### "Semgrep not found" or "Bandit not found"
- SAST tools are optional but recommended
- Install: `pip install semgrep bandit`
- Or skip: `mcp-sentinel scan . --engines static`

### AI engine not working
- Requires API key: `export ANTHROPIC_API_KEY=your-key`
- Costs ~$0.10-0.50 per scan
- Optional - other engines work without it

### Slow scans
- Exclude node_modules, venv: Edit `.mcp-sentinel.yaml`
- Use fewer engines: `--engines static`
- Scan specific directories only

## Next Steps

1. **Explore Reports** - Check `examples/` folder for sample reports
2. **Read Architecture** - See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for technical details
3. **Customize Config** - Run `mcp-sentinel init` and edit `.mcp-sentinel.yaml`
4. **CI/CD Integration** - Use [GitHub Actions template](.github/workflows/mcp-sentinel-template.yml)
5. **Framework Tutorials** - See `docs/tutorials/` for Django, FastAPI, Express.js guides

## Get Help

- **Documentation**: [README.md](README.md)
- **Issues**: [GitHub Issues](https://github.com/beejak/mcp-sentinel/issues)
- **Feature Requests**: [GitHub Discussions](https://github.com/beejak/mcp-sentinel/discussions)

---

**You're all set!** 🎉

Run `mcp-sentinel scan .` and start finding vulnerabilities in your code.
