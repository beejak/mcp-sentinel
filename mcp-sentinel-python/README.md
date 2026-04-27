# MCP Sentinel - Python Edition

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Test Coverage](https://img.shields.io/badge/coverage-%7E80%25%20overall-brightgreen.svg)](https://github.com/mcp-sentinel/mcp-sentinel-python)
[![Tests](https://img.shields.io/badge/tests-393%20passing-success.svg)](https://github.com/beejak/mcp-sentinel/tree/main/mcp-sentinel-python)

<div align="center">

## 🛡️ Enterprise-Grade Security Scanner for MCP Servers

**Phase 4.1 Complete - Multi-Engine SAST Integration ✅**

Modern Python implementation with async-first architecture, multi-engine scanning (Static + SAST), comprehensive testing, and enterprise-ready code quality.

---

**[📖 Documentation](docs/)** • **[🚀 Quick Start](#-quick-start)** • **[✨ Features](#-current-features)** • **[🤝 Contributing](docs/CONTRIBUTING.md)**

---

</div>

## 🎉 What's New - Phase 4.1: Multi-Engine SAST Integration!

We've completed **Phase 4.1**, adding a powerful SAST engine that integrates **Semgrep** and **Bandit** for industry-standard static analysis alongside our custom pattern-based detectors:

| Milestone | Status | Details |
|-----------|--------|---------|
| **Multi-Engine Scanner** | ✅ Complete | Concurrent execution of multiple analysis engines |
| **SAST Engine** | ✅ Complete | Semgrep + Bandit integration with 50+ mappings |
| **9 static detectors** | ✅ Complete | Includes **PrototypePollutionDetector** (CWE-1321) plus Phase 1–3 suite |
| **26 SAST Tests** | ✅ Passing | 100% pass rate, 70-80% coverage |
| **100+ patterns** | ✅ Implemented | Compiled regex patterns across static detectors |
| **4 Report Formats** | ✅ Complete | Terminal, JSON, SARIF 2.1.0, HTML interactive reports |
| **Enterprise Docs** | ✅ Complete | Full documentation suite with guides and examples |

**Recent Additions (Phase 4.1):**
- ✅ **SAST Engine** - Integrates Semgrep (multi-language) + Bandit (Python security)
- ✅ **Multi-Engine Architecture** - Concurrent scanning with multiple engines
- ✅ **Vulnerability Type Mapping** - 50+ tool-specific to MCP Sentinel type mappings
- ✅ **Graceful Degradation** - Works even when external tools are missing
- ✅ **26 Comprehensive Tests** - All passing with mock-based and real tool testing

**Phase 3 Highlights:**
- ✅ **XSSDetector** - 6 pattern categories, 18 patterns, 100% coverage
- ✅ **ConfigSecurityDetector** - 8 categories, 35 patterns, 96.49% coverage
- ✅ **PathTraversalDetector** - 5 categories, 22 patterns, 96.67% coverage
- ✅ **PrototypePollutionDetector** - JavaScript/TypeScript **CWE-1321** (`__proto__`, `setPrototypeOf`), Apr 2026
- ✅ **SARIF Report Generator** - GitHub Code Scanning compatible, SARIF 2.1.0 standard
- ✅ **HTML Report Generator** - Beautiful interactive reports with executive dashboard

## 🚀 Quick Start

```bash
# Install with Poetry
poetry install

# Or install with pip
pip install mcp-sentinel

# Run a scan with terminal output
mcp-sentinel scan /path/to/mcp/server

# Generate beautiful HTML report
mcp-sentinel scan /path/to/mcp/server --output html --json-file report.html

# Generate SARIF report for GitHub Code Scanning
mcp-sentinel scan /path/to/mcp/server --output sarif --json-file report.sarif

# Generate JSON report
mcp-sentinel scan /path/to/mcp/server --output json --json-file report.json

# Scan with multiple engines (Phase 4+)
mcp-sentinel scan /path/to/mcp/server --engines static,sast --output html

# Start API server
mcp-sentinel server --port 8000
```

## Live MCP scanning, reports, and exit codes

The CLI command `mcp-sentinel scan <path>` analyzes **files on disk** under `<path>` (for example a **cloned MCP server repository** or this repo’s `tests/fixtures`). It performs static (and optional SAST) analysis over the tree; it does **not** attach to a running MCP process over stdio or HTTP+SSE today. For a “live” assessment, clone the server (or your vulnerable sample), then point `scan` at that directory.

**Good default targets before you pass a custom vulnerable repo URL**

1. **`tests/fixtures/`** — small, always present, intentionally noisy samples (good for exercising HTML/SARIF/JSON output).
2. **A vulnerable MCP server you clone locally** — for example [beejak/Vulnerable-MCP-Server](https://github.com/beejak/Vulnerable-MCP-Server): `git clone https://github.com/beejak/Vulnerable-MCP-Server.git` then `mcp-sentinel scan ./Vulnerable-MCP-Server --output html --json-file reports/scan.html` (create `reports/` first if you like; it is listed in `.gitignore`).
3. **`src/mcp_sentinel`** — baseline scan of this scanner’s own code (typically fewer critical findings than fixtures).

**Where outputs land**

| Kind | Location |
|------|----------|
| **Scan reports** (HTML, JSON, SARIF) | Path you pass to `--json-file` (flag name is historical; it is the output file for all non-terminal formats). |
| **pytest coverage (HTML)** | `htmlcov/index.html` after `pytest --cov=src --cov-report=html` |

If the scan finds **critical** severity issues, the CLI **still writes** your report (JSON/SARIF/HTML or terminal summary), then exits with **code 1** (Click’s `Abort`) so CI can fail the job. That is **not** “the scan aborted before reporting.” Use **`--no-fail-on-critical`** for **exit 0** when triaging locally. Open the generated artifacts to review findings.

### Windows / install notes

- **`pip install -e .`** (or Poetry) on **Python 3.12** is the path most often used on Windows; optional deps **`uvloop`** and **`semgrep`** are skipped on win32 via environment markers in `pyproject.toml`.
- **`ruff check src tests`** and **`pytest tests/`** are the canonical sanity commands (393 tests, all passing as of the last maintenance pass).

## Recent maintenance (2026)

- **Detectors**: **Prototype pollution** (CWE-1321) for JS/TS/JSON; **prompt injection** noise reduction for Chat API-style **`role`** / **`content`** (string-aware brace pairing); path traversal skips for ES/TS **relative module imports**; hardened config security, secrets, supply-chain manifests, XSS; SARIF paths on Windows; full `pytest tests/` green.
- **Models**: Replaced deprecated `datetime.utcnow()` with **timezone-aware UTC** (`datetime.now(UTC)`) and migrated Pydantic **`class Config` → `model_config = ConfigDict(...)`** on `Vulnerability` and `ScanResult`.

## Complementary scanners (same org: [github.com/beejak](https://github.com/beejak))

MCP Sentinel Python is **MCP server *source* static analysis** (and optional Semgrep/Bandit). Other public repos by the same author target different layers; they are **not** vendored into this package, but you can run them in the same security assessment.

**Note on the beejak account:** many public repositories there are **forks** of upstream projects (MCP servers, FastAPI, LangChain, n8n, `modelcontextprotocol/servers`, and similar). Those are **ecosystem / integration / study** copies, not additional “MCP Sentinel” engines. You can still point **`mcp-sentinel scan <path>`** at a **local clone** of any of them to audit that code—but you do **not** need to wire each fork into this Python package.

| Project | What it is | How to use it with an MCP server |
|--------|------------|----------------------------------|
| [**mcp-sentinel** (Rust)](https://github.com/beejak/mcp-sentinel) | Static scanner with a **broader Rust implementation** (e.g. additional OWASP-mapped detectors: missing auth, network binding, SSRF, weak crypto, rug pull, MCP sampling, etc.) | `mcp-sentinel scan <path>` on the same clone; **diff/merge** or **correlate** JSON/SARIF with this Python tool for defense in depth. |
| [**docker-scanner**](https://github.com/beejak/docker-scanner) | **Container** vulnerability scanner (Go, Trivy; CVEs, CISA KEV, optional runc host checks, SBOM) | After `docker build` for your MCP image: `scanner scan --image <image:tag> --output-dir ./reports` (and/or use its [MCP server](https://github.com/beejak/docker-scanner/blob/main/docs/ide-and-mcp.md) for agent-driven image review). **Complements** code scanning: supply-chain CVs in the image, not Python patterns. |
| [**Argus** (LLM Scanner)](https://github.com/beejak/Argus) | **Hugging Face model bundle** admission: `scan-bundle` / `admit-model` on weight and config trees, configlint, optional dynamic probe | Use when you **ship or download model weights** next to an MCP app. **Not** a substitute for scanning `server.py` / `package.json` in a normal MCP repo. |
| [**NetSec**](https://github.com/beejak/NetSec) | **Network** security toolkit (scanning, DNS, SSL, traffic) | Relevant if the MCP server exposes custom ports or you are **hardening the host/network** around the server. |

**Practical pipeline (example):** (1) `mcp-sentinel scan ./my-mcp` (and/or Rust `mcp-sentinel`) → (2) `docker build -t my-mcp:dev .` → (3) `docker-scanner` / Trivy on `my-mcp:dev` → (4) Argus only if you bundle ML artifacts.

## ✨ Current Features (Phase 4.1)

### 🚀 Multi-Engine Architecture

**2 Analysis Engines Available:**

| Engine | Status | Description | Tools |
|--------|--------|-------------|-------|
| **Static Analysis** | ✅ Active | Pattern-based detection with **9** specialized detectors | MCP Sentinel (custom) |
| **SAST Integration** | ✅ Active | Industry-standard static analysis | Semgrep + Bandit |
| **Semantic Analysis** | 🚧 Phase 4.2 | AST-based dataflow and taint tracking | Tree-sitter (planned) |
| **AI Analysis** | 🚧 Phase 4.3 | LLM-powered vulnerability detection | LangChain + GPT-4/Claude (planned) |

**Multi-Engine Features:**
- ✅ Concurrent execution for performance
- ✅ Automatic deduplication of findings
- ✅ Unified vulnerability format across all engines
- ✅ Graceful degradation (works even if tools missing)
- ✅ Configurable via `--engines` flag

### 🔍 9 comprehensive vulnerability detectors (static engine)

| Detector | Patterns | Coverage | Status |
|----------|----------|----------|--------|
| **SecretsDetector** | 15+ types | 95%+ | ✅ Phase 1 |
| **PromptInjectionDetector** | Jailbreaks, role confusion | 95%+ | ✅ Phase 1 |
| **ToolPoisoningDetector** | Unicode attacks, keywords | 95%+ | ✅ Phase 2 |
| **SupplyChainDetector** | 11 attack patterns | 95%+ | ✅ Phase 2 |
| **XSSDetector** | 6 categories, 18 patterns | 100% | ✅ Phase 3 |
| **ConfigSecurityDetector** | 8 categories, 35 patterns | 96.49% | ✅ Phase 3 |
| **PathTraversalDetector** | 5 categories, 22 patterns | 96.67% | ✅ Phase 3 |
| **CodeInjectionDetector** | Python, JS/TS | 95%+ | ✅ Phase 1 |
| **PrototypePollutionDetector** | CWE-1321 (`__proto__` keys, `.__proto__=`, `setPrototypeOf`) | — | ✅ 2026 |

### 🎯 100+ vulnerability patterns (static engine)

**Secrets & Credentials:**
- AWS Access Keys (AKIA*, ASIA*), Secret Keys
- OpenAI API Keys (sk-*), Anthropic API Keys
- JWT Tokens, Private Keys (RSA, EC, OpenSSH)
- Database Connection Strings, GitHub Tokens
- Hardcoded Passwords & API Tokens

**Code Injection:**
- Command injection (os.system, subprocess, child_process.exec)
- Code execution (eval, exec, Function constructor)
- Template injection vulnerabilities

**Web Vulnerabilities:**
- DOM-based XSS (innerHTML, outerHTML, document.write)
- Event handler injection (onclick, onerror, onload)
- JavaScript protocol injection (javascript:, data:text/html)
- React dangerouslySetInnerHTML, Vue v-html
- jQuery unsafe methods (.html(), .append(), .prepend())

**Path Manipulation:**
- Directory traversal sequences (../, ..\\, URL-encoded)
- Unsafe file operations (open, read, write with user input)
- Archive extraction vulnerabilities (Zip Slip)
- Missing path sanitization

**Configuration Security:**
- Debug mode in production
- Weak/missing authentication
- Insecure CORS configurations
- Missing security headers
- Exposed debug/admin endpoints

**AI Security:**
- Prompt injection & jailbreak attempts
- System prompt manipulation
- Role confusion attacks
- Tool description poisoning
- Invisible Unicode manipulation

**Prototype pollution (JavaScript / TypeScript, CWE-1321):**
- `__proto__` / `constructor` style keys in object literals
- Direct `__proto__` assignment, `Object.setPrototypeOf` / `Reflect.setPrototypeOf` (review call sites)

**Supply Chain:**
- Malicious install scripts (preinstall, postinstall)
- Insecure HTTP/Git dependencies
- Wildcard version specifiers
- Package confusion attacks

### 📊 Report Generators (Phase 3+)

MCP Sentinel now supports multiple output formats for seamless integration:

| Format | Description | Use Case |
|--------|-------------|----------|
| **Terminal** | Rich colored output with tables | Quick scans and debugging |
| **JSON** | Structured data format | CI/CD pipelines, automation |
| **SARIF 2.1.0** | Industry standard format | GitHub Code Scanning, IDE integration |
| **HTML** | Beautiful interactive reports | Executive summaries, sharing with teams |

**SARIF Features:**
- ✅ GitHub Code Scanning compatible
- ✅ Full vulnerability location mapping
- ✅ Rule definitions for all detector types
- ✅ Severity-based categorization
- ✅ Remediation suggestions

**HTML Report Features:**
- ✅ Executive dashboard with key metrics
- ✅ Risk score visualization
- ✅ Animated severity breakdown
- ✅ Detailed findings with code snippets
- ✅ Self-contained (no external dependencies)
- ✅ Professional styling with responsive design

### 🏗️ Architecture Highlights

- **Async-First**: Full asyncio implementation for concurrent scanning
- **Type-Safe**: Comprehensive type hints with Pydantic models
- **Modular**: Clean detector architecture with BaseDetector pattern
- **Extensible**: Easy to add new detectors and patterns
- **Well-Tested**: 393 `pytest` tests; overall line coverage ~80% with `pytest --cov=src` (higher on several detectors)
- **Modern Python**: Python 3.11+ with latest best practices
- **Multi-Format Reports**: Terminal, JSON, SARIF, and HTML outputs

### ⚡ Performance

- **Concurrent File Scanning**: Async processing for speed
- **Pattern Matching**: Compiled regex for fast detection
- **Clean Code**: Black-formatted, Ruff-linted, mypy type-checked
- **CI-Ready**: GitHub Actions integration ready

## 📦 Installation

### Using Poetry (Recommended)

```bash
# Clone repository
git clone https://github.com/mcp-sentinel/mcp-sentinel-python.git
cd mcp-sentinel-python

# Install all dependencies (including dev tools)
poetry install --with dev

# Activate virtual environment
poetry shell

# Verify installation
poetry run mcp-sentinel --version
```

### Development Setup

```bash
# Install pre-commit hooks
poetry run pre-commit install

# Run tests
poetry run pytest

# Run tests with coverage
poetry run pytest --cov=mcp_sentinel --cov-report=html

# Type checking
poetry run mypy src/

# Linting
poetry run ruff check src/

# Formatting
poetry run black src/
```

### Quick Verification

```bash
# Test all 9 static detectors
poetry run pytest tests/unit/

# Test Phase 3 detectors specifically
poetry run pytest tests/unit/test_xss.py
poetry run pytest tests/unit/test_config_security.py
poetry run pytest tests/unit/test_path_traversal.py
poetry run pytest tests/unit/test_prototype_pollution.py
```

### Optional: smoke-scan cloned forks (beejak mirrors)

Use this when you want MCP Sentinel to exercise **real upstream-sized** trees (shallow clones), without committing them.

1. Edit `tests/fork_targets.manifest` if you want different `owner/repo` lines (default lists a few **beejak** MCP-oriented forks).
2. Run **`scripts/clone_fork_test_targets.ps1`** (Windows) or **`scripts/clone_fork_test_targets.sh`** — repos land in **`tests/external/<repo>/`** (gitignored).
3. Enable collection of the opt-in test and run it (faster without coverage):

```powershell
$env:MCP_SENTINEL_RUN_FORK_TESTS = "1"
pytest tests/integration/test_external_fork_smoke.py -m external_forks --no-cov
```

Without **`MCP_SENTINEL_RUN_FORK_TESTS`**, default **`pytest`** does not collect that module (see **`pytest_ignore_collect`** in `tests/conftest.py`).

## 🔧 Configuration (Phase 3)

### Current Configuration Options

```yaml
# .mcp-sentinel.yaml (Phase 3 - Static Analysis Focus)
scan:
  # Detectors to enable (all 9 static detectors available)
  detectors:
    - secrets
    - prompt_injection
    - tool_poisoning
    - supply_chain
    - xss
    - config_security
    - path_traversal
    - command_injection

  # Severity filtering
  min_severity: low  # low, medium, high, critical

  # File patterns to exclude
  exclude_patterns:
    - "node_modules/"
    - ".git/"
    - "__pycache__/"
    - "*.pyc"
    - "dist/"
    - "build/"

  # Performance settings
  max_concurrent_files: 10
  timeout_seconds: 300

# Output configuration
output:
  format: terminal  # terminal, json, sarif, html
  file: scan_results.json
  verbose: true

# Report generation (Phase 3+)
reporting:
  formats: [terminal, json, sarif, html]
  output_dir: ./reports
  include_code_snippets: true
  github_code_scanning: true  # SARIF compatibility
```

**Note**: Advanced features like AI analysis and enterprise integrations are planned for Phase 4+. See [Roadmap](#-roadmap) for details.

## 📖 Usage Examples (Phase 3)

### Testing Individual Detectors

Phase 3 focuses on comprehensive detector implementation and testing. You can test each detector individually:

```bash
# Test all detectors (393 tests)
poetry run pytest

# Test specific detector suites
poetry run pytest tests/unit/test_secrets_detector.py      # Phase 1: Secrets
poetry run pytest tests/unit/test_prompt_injection.py      # Phase 1: Prompt Injection
poetry run pytest tests/unit/test_tool_poisoning.py        # Phase 2: Tool Poisoning
poetry run pytest tests/unit/test_supply_chain.py          # Phase 2: Supply Chain
poetry run pytest tests/unit/test_xss.py                   # Phase 3: XSS (89 tests)
poetry run pytest tests/unit/test_config_security.py       # Phase 3: Config (68 tests)
poetry run pytest tests/unit/test_path_traversal.py        # Phase 3: Path Traversal (60 tests)
poetry run pytest tests/unit/test_prototype_pollution.py   # CWE-1321 prototype pollution

# Run with coverage report
poetry run pytest --cov=mcp_sentinel --cov-report=html
# View report: open htmlcov/index.html

# Run with verbose output
poetry run pytest -v

# Run specific test
poetry run pytest tests/unit/test_xss.py::test_dom_xss_detection -v
```

### Generating Reports

```bash
# Generate different report formats
mcp-sentinel scan /path/to/project --output terminal  # Default: colored terminal output
mcp-sentinel scan /path/to/project --output json --json-file results.json
mcp-sentinel scan /path/to/project --output sarif --json-file results.sarif
mcp-sentinel scan /path/to/project --output html --json-file report.html

# Filter by severity
mcp-sentinel scan /path/to/project --severity critical --severity high --output html

# Scan with specific engines and generate HTML report
mcp-sentinel scan /path/to/project --engines static --output html --json-file report.html

# Upload SARIF to GitHub Code Scanning
mcp-sentinel scan /path/to/project --output sarif --json-file results.sarif
gh api repos/{owner}/{repo}/code-scanning/sarifs -F sarif=@results.sarif
```

### Using Report Generators Programmatically

```python
from pathlib import Path
from mcp_sentinel.core import MultiEngineScanner
from mcp_sentinel.engines.base import EngineType
from mcp_sentinel.reporting.generators import SARIFGenerator, HTMLGenerator

# Run a scan
scanner = MultiEngineScanner(enabled_engines={EngineType.STATIC})
result = await scanner.scan_directory("/path/to/project")

# Generate SARIF report
sarif_gen = SARIFGenerator()
sarif_gen.save_to_file(result, Path("report.sarif"))

# Generate HTML report
html_gen = HTMLGenerator()
html_gen.save_to_file(result, Path("report.html"))

# Get report as string
sarif_json = sarif_gen.generate_json(result)
html_content = html_gen.generate(result)
```

### Using Detectors Programmatically

```python
from pathlib import Path
from mcp_sentinel.detectors.xss import XSSDetector
from mcp_sentinel.detectors.config_security import ConfigSecurityDetector
from mcp_sentinel.detectors.path_traversal import PathTraversalDetector

# Initialize detectors
xss_detector = XSSDetector()
config_detector = ConfigSecurityDetector()
path_detector = PathTraversalDetector()

# Scan code for XSS vulnerabilities
code = '''
function displayUser(name) {
    document.getElementById("user").innerHTML = name;  // Vulnerable!
}
'''
xss_vulns = await xss_detector.detect(Path("app.js"), code, file_type="javascript")
for vuln in xss_vulns:
    print(f"Found {vuln.type} at line {vuln.line_number}: {vuln.title}")

# Scan configuration for security issues
config = '''
DEBUG = True  # Vulnerable in production!
SECRET_KEY = "hardcoded-secret"  # Never hardcode secrets!
'''
config_vulns = await config_detector.detect(Path("settings.py"), config, file_type="python")

# Scan for path traversal
path_code = '''
file_path = os.path.join(base_dir, request.params['file'])  # Vulnerable!
with open(file_path) as f:
    return f.read()
'''
path_vulns = await path_detector.detect(Path("api.py"), path_code, file_type="python")
```

### Development Workflow

```bash
# Run full quality check suite
poetry run pytest                    # All tests
poetry run mypy src/                # Type checking
poetry run ruff check src/          # Linting
poetry run black --check src/       # Format check

# Auto-fix issues
poetry run black src/               # Format code
poetry run ruff --fix src/          # Fix linting issues

# Pre-commit hooks (automatic on git commit)
poetry run pre-commit run --all-files
```

## 🚀 Coming in Phase 4+ (Planned)

### Multi-Engine Analysis Platform (Phase 4) ⚠️ CRITICAL
```bash
# Scan with all 4 analysis engines (Static, Semantic, SAST, AI)
mcp-sentinel scan /path/to/project --engines all --output json,html

# Use specific engines
mcp-sentinel scan /path/to/project --engines static,semantic,sast

# AI-powered analysis with multiple LLM providers
mcp-sentinel scan /path/to/project --engines ai --ai-provider anthropic

# Semantic analysis with dataflow tracking
mcp-sentinel scan /path/to/project --engines semantic --dataflow

# SAST with Semgrep + Bandit
mcp-sentinel scan /path/to/project --engines sast

# GitHub repository scanning with multi-engine analysis
mcp-sentinel scan https://github.com/owner/repo --engines all
```

**What Phase 4 Adds:**
- 🌳 **Semantic Analysis**: Tree-sitter AST parsing with taint tracking
- 🔍 **SAST Integration**: Semgrep (1000+ rules) + Bandit
- 🤖 **AI Analysis**: LangChain + GPT-4/Claude/Gemini/Ollama with RAG
- 📊 **Engine Comparison**: See which engines found what vulnerabilities

### Enterprise Platform (Phase 5+)
- **FastAPI Server**: RESTful API for remote scanning
- **Database Layer**: PostgreSQL + Redis for scan history
- **Task Queue**: Celery for background jobs
- **Integrations**: Jira, Slack, Vault, GitHub/GitLab
- **Web Dashboard**: React UI with real-time monitoring

See [Roadmap](#-roadmap) for complete feature timeline.

## 🏗️ Architecture (Phase 3)

### Current Architecture

```
┌──────────────────────────────────────────────┐
│          MCP Sentinel Core                   │
│         (Python 3.11+ / Asyncio)            │
└─────────────┬────────────────────────────────┘
              │
     ┌────────▼────────┐
     │   BaseDetector  │ (Abstract Class)
     └────────┬────────┘
              │
   ┌──────────┴──────────────────────────┐
   │                                     │
   ▼                                     ▼
┌──────────────────┐              ┌──────────────────┐
│ Phase 1 Detectors│              │ Phase 2 Detectors│
├──────────────────┤              ├──────────────────┤
│ • Secrets        │              │ • ToolPoisoning  │
│ • PromptInjection│              │ • SupplyChain    │
│ • CodeInjection  │              │                  │
└──────────────────┘              └──────────────────┘

              ┌──────────────────┐
              │ Phase 3 Detectors│
              ├──────────────────┤
              │ • XSS            │
              │ • ConfigSecurity │
              │ • PathTraversal  │
              │ • PrototypePollution │
              └──────────────────┘
                     │
        ┌────────────┴────────────┐
        │                         │
        ▼                         ▼
  ┌──────────┐            ┌──────────────┐
  │ Pydantic │            │  Test Suite  │
  │  Models  │            │  (393 tests) │
  └──────────┘            └──────────────┘
```

### Current Components (Phase 3)

- **9 Specialized Detectors**: Complete vulnerability detection coverage (including prototype pollution)
- **Pydantic Models**: Type-safe data validation with Vulnerability, Confidence, Severity
- **Async Detection**: Concurrent file processing with asyncio
- **Comprehensive Tests**: 393 tests; coverage see `pytest --cov=src`
- **Pattern Matching**: 100+ compiled regex patterns across static detectors

### Planned Components (Phase 4+)

**Phase 4 - Multi-Engine Analysis:**
- **Semantic Analysis Engine**: Tree-sitter AST + dataflow + taint tracking
- **SAST Integration Engine**: Semgrep + Bandit with 1000+ rules
- **AI Analysis Engine**: LangChain + GPT-4/Claude/Gemini/Ollama + RAG
- **Scanner Engine**: Multi-engine orchestration with progress tracking
- **Report Generators**: HTML, SARIF, JSON with engine attribution

**Phase 5+ - Enterprise Platform:**
- **FastAPI Server**: RESTful API for enterprise integration
- **Database Layer**: PostgreSQL for scan history and trends
- **Task Queue**: Celery for background processing
- **Enterprise Integrations**: Jira, Slack, Vault connections
- **Web Dashboard**: React UI with real-time monitoring

## 🧪 Development

### Project Structure (Phase 3)

```
mcp-sentinel-python/
├── src/mcp_sentinel/
│   ├── detectors/           # ✅ 9 vulnerability detectors
│   │   ├── base.py         # BaseDetector abstract class
│   │   ├── secrets.py      # Phase 1: Secrets detection
│   │   ├── prompt_injection.py  # Phase 1: Prompt injection
│   │   ├── code_injection.py    # Phase 1: Code/command injection
│   │   ├── tool_poisoning.py    # Phase 2: Tool poisoning
│   │   ├── supply_chain.py      # Phase 2: Supply chain
│   │   ├── xss.py          # Phase 3: XSS detection
│   │   ├── config_security.py   # Phase 3: Config security
│   │   ├── path_traversal.py    # Phase 3: Path traversal
│   │   └── prototype_pollution.py # CWE-1321 (JS/TS/JSON)
│   ├── core/               # ✅ Core scanning infrastructure
│   │   ├── scanner.py      # Legacy scanner
│   │   ├── multi_engine_scanner.py  # Multi-engine orchestration
│   │   ├── config.py       # Configuration management
│   │   └── exceptions.py   # Custom exceptions
│   ├── engines/            # ✅ Analysis engines
│   │   ├── base.py         # BaseEngine abstract class
│   │   └── static/         # Static analysis engine
│   ├── reporting/          # ✅ Report generators (Phase 3+)
│   │   └── generators/
│   │       ├── sarif_generator.py   # SARIF 2.1.0 format
│   │       └── html_generator.py    # HTML interactive reports
│   ├── cli/                # ✅ Command-line interface
│   │   └── main.py         # CLI commands and argument parsing
│   ├── models/             # ✅ Pydantic data models
│   │   ├── vulnerability.py
│   │   └── scan_result.py
│   └── __init__.py
├── tests/
│   ├── unit/               # ✅ 393 comprehensive tests
│   │   ├── test_secrets_detector.py
│   │   ├── test_prompt_injection.py
│   │   ├── test_command_injection.py
│   │   ├── test_tool_poisoning.py
│   │   ├── test_supply_chain.py
│   │   ├── test_xss.py              # 89 tests, 100% coverage
│   │   ├── test_config_security.py  # 68 tests, 96.49% coverage
│   │   ├── test_path_traversal.py   # 60 tests, 96.67% coverage
│   │   └── test_prototype_pollution.py
│   ├── integration/        # 🔜 Phase 4: End-to-end tests
│   └── conftest.py
├── docs/                   # ✅ Enterprise documentation
│   ├── ARCHITECTURE.md
│   ├── CONTRIBUTING.md
│   ├── DEVELOPMENT_SETUP.md
│   └── README.md
├── pyproject.toml          # Poetry configuration
├── .pre-commit-config.yaml # Code quality hooks
└── README.md               # This file
```

### Quality Standards

Phase 3 maintains enterprise-grade code quality:

- **Test Coverage**: ~80% overall with `pytest --cov=src`; several detectors much higher
- **Type Safety**: Full type hints with mypy strict mode
- **Code Style**: Black formatting + Ruff linting
- **Documentation**: Comprehensive docstrings (Google style)
- **CI/CD Ready**: Pre-commit hooks + GitHub Actions compatible

## 🗺️ Roadmap

### ✅ Phase 1 Complete - Foundation (Nov 2025)
- [x] Core detector architecture with BaseDetector pattern
- [x] SecretsDetector: 15+ secret types (AWS, OpenAI, JWT, private keys)
- [x] PromptInjectionDetector: Jailbreaks, role confusion, system prompt manipulation
- [x] CodeInjectionDetector: Python, JavaScript/TypeScript dangerous functions
- [x] Pydantic models for type-safe vulnerability data
- [x] Async-first architecture with asyncio
- [x] Initial test suite with fixtures

### ✅ Phase 2 Complete - AI & Supply Chain (Dec 2025)
- [x] ToolPoisoningDetector: Unicode attacks, malicious keywords, hidden markers
- [x] SupplyChainDetector: 11 package confusion patterns
  - Malicious install scripts (preinstall, postinstall with RCE)
  - Insecure HTTP/Git dependencies
  - Wildcard versions, scoped package confusion
- [x] Expanded test coverage to 95%+
- [x] Enhanced documentation

### ✅ Phase 3 Complete - 100% Detector Parity + Report Generators (Jan 2026)
- [x] XSSDetector: 6 categories, 18 patterns, 100% coverage
  - DOM XSS, event handlers, JavaScript protocol
  - React/Vue framework vulnerabilities, jQuery unsafe methods
- [x] ConfigSecurityDetector: 8 categories, 35 patterns, 96.49% coverage
  - Debug mode, weak auth, insecure CORS, missing headers
  - Weak secrets, missing rate limits, SSL/TLS issues
- [x] PathTraversalDetector: 5 categories, 22 patterns, 96.67% coverage
  - Directory traversal, unsafe file ops, Zip Slip
  - Path manipulation, missing sanitization
- [x] PrototypePollutionDetector: CWE-1321 patterns for JS/TS/JSON (`__proto__`, `setPrototypeOf`)
- [x] **SARIF Report Generator**: SARIF 2.1.0 format with GitHub Code Scanning support
- [x] **HTML Report Generator**: Beautiful interactive reports with executive dashboard
- [x] **CLI Integration**: Multi-format output support (terminal, JSON, SARIF, HTML)
- [x] 393 comprehensive tests (100% pass rate on `pytest tests/`)
- [x] Enterprise documentation suite
- [x] Contributing guidelines and development setup

**Current Status**: **9** static detectors, **100+** patterns, **393** tests, 4 report formats, enterprise-ready ✅

---

### 🚧 Phase 4 Planned - Multi-Engine Analysis Platform (Q1 2026)

**Goal**: 4-engine analysis platform with CLI scanner for comprehensive vulnerability detection

#### Analysis Engines (4 engines, 24-33 days) ⚠️ CRITICAL

- [ ] **Semantic Analysis Engine** (tree-sitter, dataflow, taint tracking)
  - Tree-sitter AST parsing for Python, JavaScript, TypeScript, Go
  - Dataflow analysis with source-to-sink tracking
  - Taint propagation through variables and function calls
  - Control flow graph construction
  - Inter-procedural analysis

- [ ] **SAST Integration Engine** (Semgrep, Bandit)
  - Semgrep integration with 1000+ community rules
  - Bandit security linter for Python
  - Security-focused rule filtering
  - Result normalization and deduplication
  - Configurable severity thresholds

- [ ] **AI Analysis Engine** (LangChain, multiple LLMs, RAG)
  - LangChain orchestration framework
  - Multi-provider support (OpenAI GPT-4, Anthropic Claude, Google Gemini, Ollama)
  - RAG (Retrieval-Augmented Generation) for security knowledge
  - Contextual vulnerability analysis
  - False positive reduction with AI reasoning
  - Automated remediation suggestions

- [ ] **Static Analysis Engine** (centralized pattern registry)
  - Unified pattern registry for all static detectors
  - Optimized pattern matching engine
  - Batch processing for efficiency
  - Plugin architecture for custom patterns

#### Scanner Infrastructure

- [ ] **Scanner Engine**
  - Directory traversal and file discovery
  - Progress tracking and reporting
  - Multi-detector orchestration
  - Multi-engine coordination (Static, Semantic, SAST, AI)
  - Concurrent file processing with asyncio
  - Configuration file support (YAML)

- [ ] **CLI Application**
  - ✅ `mcp-sentinel scan` command (completed Phase 3)
  - `--engines` flag enhancement (static, semantic, sast, ai, all)
  - ✅ Multiple output formats (terminal, JSON, SARIF, HTML) - Phase 3
  - Severity filtering and fail-on thresholds
  - GitHub URL scanning support
  - CI/CD integration guides

- [ ] **Enhanced Report Generation**
  - ✅ SARIF 2.1.0 output for GitHub Code Scanning (Phase 3)
  - ✅ JSON structured output (Phase 3)
  - ✅ HTML interactive reports (Phase 3)
  - ✅ Terminal colored output (Phase 3)
  - Engine attribution in all report formats
  - Engine comparison and overlap analysis
  - Multi-engine vulnerability deduplication reporting

- [ ] **Integration Tests**
  - End-to-end multi-engine scanning workflows
  - Engine performance benchmarks
  - Accuracy comparison tests
  - CI/CD pipeline tests

**Estimated Duration**: 6-8 weeks (expanded scope with 4 engines)
**Complexity**: Very High - Adding 3 new analysis paradigms

---

### 🔮 Phase 5 - Enterprise Platform Foundation (Q2 2026)

**FastAPI Server** (Est. 4-6 weeks):
- RESTful API for remote scanning
- GraphQL query interface
- WebSocket for real-time updates
- JWT-based authentication & authorization
- API rate limiting and quotas
- OpenAPI/Swagger documentation

**Database Layer** (Est. 3-4 weeks):
- PostgreSQL for scan history
- Redis caching layer
- Scan result persistence with full engine data
- Vulnerability trending over time
- Historical comparison and drift detection
- Database migrations (Alembic)

**Task Queue** (Est. 2-3 weeks):
- Celery distributed task processing
- Background scan jobs with priority queues
- Scheduled scans (cron-like)
- Worker scaling and load balancing
- Task retry logic and error handling

---

### 🔗 Phase 6 - Enterprise Integrations (Q3 2026)

**Ticketing Systems** (Est. 4-5 weeks):
- **Jira**: Auto-create security tickets, custom field mapping
- **ServiceNow**: Incident creation, workflow integration
- **Linear**: Issue tracking with priority mapping

**Notification Channels** (Est. 3-4 weeks):
- **Slack**: Channel notifications, interactive buttons
- **Microsoft Teams**: Card-based notifications
- **PagerDuty**: Incident creation for critical vulnerabilities
- **Email**: Customizable templates, digest emails

**Secret Management** (Est. 2-3 weeks):
- **HashiCorp Vault**: Secure API key storage and rotation
- **AWS Secrets Manager**: Cloud-native secret management
- **Azure Key Vault**: Microsoft cloud integration

**VCS Integration** (Est. 3-4 weeks):
- **GitHub**: PR comments, commit status checks, issue linking
- **GitLab**: Merge request comments, pipeline integration
- **Bitbucket**: PR annotations, build status

**Logging & Monitoring** (Est. 3-4 weeks):
- **Splunk**: Event forwarding, custom dashboards
- **Datadog**: Metrics, APM integration, log forwarding
- **Elasticsearch**: Log aggregation, Kibana dashboards
- **Prometheus**: Metrics export, Grafana integration

---

### 📊 Phase 7 - Advanced Reporting & Analytics (Q3-Q4 2026)

**Report Formats** (Est. 3-4 weeks):
- PDF executive summaries with charts
- Excel exports for data analysis
- Markdown reports for GitHub
- Custom Jinja2-based templates

**Compliance Mappings** (Est. 4-5 weeks):
- SOC 2 control mapping
- HIPAA security rule alignment
- PCI-DSS requirements mapping
- NIST CSF framework alignment
- CIS Controls benchmark mapping
- ISO 27001 standard compliance

**Analytics Dashboard** (Est. 5-6 weeks):
- Vulnerability trend dashboards
- Risk scoring algorithms (CVSS-based)
- False positive rate tracking
- Detector/engine performance metrics
- Time-to-remediation tracking
- Team performance benchmarks

---

### 🖥️ Phase 8 - Web Dashboard (Q4 2026)

**Frontend** (React + TypeScript) (Est. 8-10 weeks):
- Real-time scanning visualization
- Vulnerability management (triage, assign, resolve)
- Team collaboration features (comments, assignments)
- Custom rule authoring UI
- Scan history browser with filtering
- Interactive charts and graphs
- Dark/light mode

**User Management** (Est. 3-4 weeks):
- Role-based access control (Admin, Security, Developer)
- Team and organization support
- SSO integration (SAML, OAuth 2.0)
- Audit logging

**Dashboard Features** (Est. 4-5 weeks):
- Executive summary view
- Security posture overview
- Vulnerability heatmaps
- Remediation workflow management
- SLA tracking and alerts
- Custom dashboard widgets

---

### 📋 Long-Term Vision (2027+)

- **Language Expansion**: Rust, Java, C++, Ruby, PHP semantic analysis
- **IDE Integrations**: VS Code, JetBrains, Vim plugins
- **Runtime Monitoring**: Proxy-based MCP traffic analysis
- **ML Detection**: Advanced machine learning models
- **Threat Intelligence**: CVE correlation, exploit databases
- **Container Security**: Docker, Kubernetes scanning
- **Mobile MCP**: iOS, Android MCP client analysis

## 📚 Documentation

### Available Now
- **[📖 Architecture](docs/ARCHITECTURE.md)** - System design and detector architecture
- **[🤝 Contributing Guide](docs/CONTRIBUTING.md)** - How to contribute to the project
- **[🛠️ Development Setup](docs/DEVELOPMENT_SETUP.md)** - Complete setup instructions
- **[📝 Lessons Learned](docs/LESSONS_LEARNED.md)** - Development insights and best practices

### Planned (Phase 4+)
- User Guide - End-user documentation
- API Reference - FastAPI endpoint documentation
- Integration Guides - Enterprise integration tutorials
- Deployment Guide - Production deployment instructions

## 🤝 Contributing

We welcome contributions! Phase 3 is complete, and we're ready for community involvement.

### Quick Start for Contributors

```bash
# 1. Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/mcp-sentinel-python.git
cd mcp-sentinel-python

# 2. Install dependencies
poetry install --with dev

# 3. Install pre-commit hooks
poetry run pre-commit install

# 4. Run tests to verify
poetry run pytest

# 5. Make your changes and test
poetry run pytest --cov=mcp_sentinel

# 6. Submit a pull request
```

**Read the full guide**: [CONTRIBUTING.md](docs/CONTRIBUTING.md)

### What We Need Help With

**Phase 4 (Multi-Engine Analysis Platform)** ⚠️ AMBITIOUS:
- [ ] Semantic analysis engine (tree-sitter AST parsing, dataflow analysis)
- [ ] SAST integration (Semgrep + Bandit)
- [ ] AI analysis engine (LangChain + multi-LLM support)
- [ ] Scanner orchestration for multi-engine coordination
- [ ] CLI command implementation with --engines flag
- [ ] Report generators with engine attribution (HTML, SARIF, JSON)
- [ ] Integration tests for multi-engine workflows

**General**:
- [ ] Additional vulnerability patterns for existing detectors
- [ ] Documentation improvements
- [ ] Bug fixes and performance optimization
- [ ] Test coverage improvements for edge cases

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Architecture inspired by**: Original [Rust MCP Sentinel](https://github.com/mcp-sentinel/mcp-sentinel)
- **Built with modern Python**: Python 3.11+, Pydantic, AsyncIO
- **Testing framework**: pytest, pytest-asyncio, pytest-cov
- **Code quality**: Black, Ruff, mypy, pre-commit
- **Influenced by**: Industry-leading SAST tools and security research

## 📊 Project Stats

<div align="center">

| Metric | Value |
|--------|-------|
| **Detectors** | **9** (static engine default set) |
| **Patterns** | **100+** (compiled regex across static detectors) |
| **Tests** | **393** (`pytest tests/`) |
| **Coverage** | ~80% overall (`pytest --cov=src`) |
| **Report Formats** | 4 (Terminal, JSON, SARIF, HTML) |
| **Code Quality** | Black + Ruff + mypy |
| **Documentation** | Enterprise-grade |

</div>

---

<div align="center">

## ⭐ Star History

If you find MCP Sentinel Python Edition useful, please consider giving it a star!

**[⭐ Star on GitHub](https://github.com/mcp-sentinel/mcp-sentinel-python)**

---

**Current Version**: 3.0.0 — Phase 4.1 multi-engine CLI & detectors maintained (Apr 2026)
**Next Milestone**: Phase 4.2 semantic / deeper SAST integration

**Made with 🛡️ by the MCP Sentinel Team**

</div>
