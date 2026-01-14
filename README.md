# MCP Sentinel - Python Edition

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Test Coverage](https://img.shields.io/badge/coverage-70.77%25-brightgreen.svg)](https://github.com/beejak/mcp-sentinel)
[![Tests](https://img.shields.io/badge/tests-369%2F371%20passing%20(99.5%25)-brightgreen.svg)](https://github.com/beejak/mcp-sentinel)
[![Version](https://img.shields.io/badge/version-v1.0.0--beta.2-blue.svg)](https://github.com/beejak/mcp-sentinel/releases/tag/v1.0.0-beta.2)

<div align="center">

## 🛡️ Enterprise-Grade Security Scanner for MCP Servers

**🎉 Phase 4.2.2 Progress - 99.5% Test Pass Rate (369/371) ✅**

Modern Python implementation with async-first architecture, semantic analysis engine, multi-engine scanning (Static + SAST + Semantic), and enterprise-ready code quality.

---

**[🚀 Quick Start](#-quick-start)** • **[✨ Features](#-features)** • **[📖 Documentation](docs/)** • **[🤝 Contributing](docs/CONTRIBUTING.md)**

---

</div>

## 🎯 What's New - v1.0.0-beta.2

**Latest (Jan 14, 2026):** Phase 4.2.2 in progress - 2 more tests passing, approaching 100% coverage!

| Achievement | Value | Details |
|-------------|-------|---------|
| **Test Pass Rate** | **99.5%** | 369/371 tests passing (+2 from beta.1) |
| **Code Coverage** | **70.77%** | Continued improvement |
| **Tests Fixed** | **2 new** | JavaScript comments + Python fixtures |
| **Engines** | **3 active** | Static + SAST + Semantic analysis |

### Phase 4.2.2 Progress

**JavaScript Comment Detection (Day 11)**
- ✅ Multi-line comment stripping for JavaScript/TypeScript (`/* ... */`)
- ✅ Prevents false positives from code inside comments
- ✅ test_ignore_javascript_comments now passing

**Python Fixture Detection (Day 11)**
- ✅ Enhanced semantic analysis now detects all patterns in fixture files
- ✅ Multi-line taint tracking working across complex scenarios
- ✅ test_python_fixture_file now passing (12+ vulnerabilities detected)

**Remaining Work**
- 🔄 2 tests still xfailed: Java File() constructor + Node.js file handlers
- 🎯 These require full semantic analysis for Java/JavaScript (planned for future phase)

**[📋 View Phase 4.2.1 Release Notes](RELEASE_NOTES_v1.0.0-beta.1.md)**

---

## 🚀 Quick Start

```bash
# Clone and install
git clone https://github.com/beejak/mcp-sentinel.git
cd mcp-sentinel
pip install -e .

# Run a basic scan
mcp-sentinel scan /path/to/mcp/server

# Generate HTML report
mcp-sentinel scan /path/to/mcp/server --output html --json-file report.html

# Scan with all engines
mcp-sentinel scan /path/to/mcp/server --engines static,sast,semantic

# Generate SARIF for GitHub Code Scanning
mcp-sentinel scan /path/to/mcp/server --output sarif --json-file report.sarif
```

---

## ✨ Features

### 🔍 Multi-Engine Analysis

**3 Analysis Engines:**

| Engine | Status | Description |
|--------|--------|-------------|
| **Static Analysis** | ✅ Production | Pattern-based detection with 8 specialized detectors |
| **SAST Integration** | ✅ Production | Semgrep (1000+ rules) + Bandit |
| **Semantic Analysis** | ✅ Production | AST parsing, taint tracking, CFG analysis |

**Multi-Engine Features:**
- ✅ Concurrent execution for performance
- ✅ Automatic deduplication of findings
- ✅ Two-phase detection: Pattern → Semantic → Dedup
- ✅ CFG-based guard detection for false positive reduction

### 🛡️ 8 Specialized Detectors

| Detector | Patterns | Test Pass Rate | Status |
|----------|----------|----------------|--------|
| **SecretsDetector** | 15+ secret types | 100% | ✅ |
| **PromptInjectionDetector** | Jailbreaks, role manipulation | 100% | ✅ |
| **CodeInjectionDetector** | Command/code execution | 100% | ✅ |
| **XSSDetector** | 18 patterns, 6 categories | 100% | ✅ |
| **PathTraversalDetector** | Directory traversal, Zip Slip | 97% | ✅ |
| **ConfigSecurityDetector** | Debug mode, weak auth | 96% | ✅ |
| **SupplyChainDetector** | 11 attack patterns | 100% | ✅ |
| **ToolPoisoningDetector** | Unicode attacks | 100% | ✅ |

### 🎯 100+ Vulnerability Patterns

**Comprehensive Detection:**
- 🔐 Secrets & Credentials (AWS, OpenAI, JWT, private keys)
- 💉 Code Injection (eval, exec, command execution)
- 🌐 Web Vulnerabilities (XSS, DOM manipulation)
- 📁 Path Traversal (directory traversal, Zip Slip)
- ⚙️ Config Issues (debug mode, weak auth, CORS)
- 🤖 AI Security (prompt injection, jailbreaks)
- 📦 Supply Chain (malicious scripts, dependency confusion)

### 📊 Multiple Report Formats

| Format | Description | Use Case |
|--------|-------------|----------|
| **Terminal** | Rich colored output | Quick scans, debugging |
| **JSON** | Structured data | CI/CD, automation |
| **SARIF 2.1.0** | Industry standard | GitHub Code Scanning, IDEs |
| **HTML** | Interactive reports | Executive summaries, teams |

**Report Features:**
- ✅ GitHub Code Scanning compatible (SARIF)
- ✅ Executive dashboard with metrics
- ✅ Severity-based categorization
- ✅ Code snippets with line numbers
- ✅ Remediation guidance

---

## 📦 Installation

### Using pip

```bash
# Install from source
git clone https://github.com/beejak/mcp-sentinel.git
cd mcp-sentinel
pip install -e .

# Verify installation
mcp-sentinel --version
```

### Using Poetry (Development)

```bash
# Clone repository
git clone https://github.com/beejak/mcp-sentinel.git
cd mcp-sentinel

# Install dependencies
poetry install --with dev

# Activate virtual environment
poetry shell

# Run tests
pytest tests/unit/ -v
# Expected: 367 passed, 3 xfailed, 1 xpassed
```

---

## 🔧 Usage Examples

### Scanning

```bash
# Basic scan with terminal output
mcp-sentinel scan /path/to/mcp/server

# Scan with specific engines
mcp-sentinel scan /path/to/mcp/server --engines static,semantic

# Generate multiple report formats
mcp-sentinel scan /path/to/mcp/server --output html,sarif,json

# Filter by severity
mcp-sentinel scan /path/to/mcp/server --severity critical --severity high
```

### Programmatic Usage

```python
from pathlib import Path
from mcp_sentinel.detectors import XSSDetector, PathTraversalDetector
from mcp_sentinel.core import MultiEngineScanner
from mcp_sentinel.engines.base import EngineType

# Use individual detector
detector = XSSDetector()
code = 'document.getElementById("user").innerHTML = userInput;'
vulns = await detector.detect(Path("app.js"), code, "javascript")

# Use multi-engine scanner
scanner = MultiEngineScanner(
    enabled_engines={EngineType.STATIC, EngineType.SEMANTIC}
)
result = await scanner.scan_directory("/path/to/project")

# Generate reports
from mcp_sentinel.reporting.generators import HTMLGenerator, SARIFGenerator

html_gen = HTMLGenerator()
html_gen.save_to_file(result, Path("report.html"))

sarif_gen = SARIFGenerator()
sarif_gen.save_to_file(result, Path("report.sarif"))
```

---

## 🧪 Development

### Running Tests

```bash
# Run all tests
pytest tests/unit/ -v

# Run with coverage
pytest tests/unit/ --cov=src/mcp_sentinel --cov-report=html

# Run specific detector tests
pytest tests/unit/test_xss.py -v
pytest tests/unit/test_path_traversal.py -v
pytest tests/unit/test_config_security.py -v
```

### Code Quality

```bash
# Format code
black src/

# Lint code
ruff check src/

# Type check
mypy src/

# Run pre-commit hooks
pre-commit run --all-files
```

### Project Structure

```
mcp-sentinel/
├── src/mcp_sentinel/
│   ├── detectors/          # 8 vulnerability detectors
│   ├── engines/            # 3 analysis engines
│   │   ├── static/        # Pattern-based detection
│   │   ├── sast/          # Semgrep + Bandit
│   │   └── semantic/      # AST + taint tracking + CFG
│   ├── reporting/          # Report generators (HTML, SARIF)
│   ├── core/              # Scanner infrastructure
│   ├── cli/               # Command-line interface
│   └── models/            # Pydantic data models
├── tests/
│   └── unit/              # 367 passing tests
├── docs/                  # Documentation
└── pyproject.toml         # Poetry configuration
```

---

## 🗺️ Roadmap

### ✅ Completed Phases

- **Phase 1-2:** Foundation + 8 detectors (Nov-Dec 2025)
- **Phase 3:** Report generators + SARIF/HTML (Jan 2026)
- **Phase 4.1:** SAST engine integration (Jan 2026)
- **Phase 4.2.1:** Semantic engine + bug fixes **(Current - 98.9% pass rate)**

### 🚧 Future Phases

**Phase 4.2.2** (Q1 2026):
- Fix remaining 3 xfailed tests
- Advanced multi-line pattern detection
- Java/Node.js semantic analysis

**Phase 4.3** (Q2 2026):
- AI-powered analysis engine (LangChain + GPT-4/Claude)
- Advanced control flow analysis
- Custom rule authoring

**Phase 5+** (Q3-Q4 2026):
- FastAPI server with REST API
- Web dashboard (React)
- Enterprise integrations (Jira, Slack, GitHub)
- Database layer (PostgreSQL + Redis)

---

## 📚 Documentation

- **[Architecture](docs/ARCHITECTURE.md)** - System design and components
- **[Contributing Guide](docs/CONTRIBUTING.md)** - How to contribute
- **[Development Setup](docs/DEVELOPMENT_SETUP.md)** - Setup instructions
- **[Release Notes](RELEASE_NOTES_v1.0.0-beta.1.md)** - v1.0.0-beta.1 details

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

**What We Need:**
- Additional vulnerability patterns
- Performance optimizations
- Documentation improvements
- Bug fixes and test coverage

---

## 📊 Project Stats

| Metric | Value |
|--------|-------|
| **Test Pass Rate** | 98.9% (367/371) |
| **Code Coverage** | 70.44% |
| **Detectors** | 8 specialized |
| **Engines** | 3 active |
| **Patterns** | 100+ vulnerability patterns |
| **Report Formats** | 4 (Terminal, JSON, SARIF, HTML) |
| **Languages** | Python, JavaScript, TypeScript |

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

Built with ❤️ using:
- Python 3.11+ with asyncio
- Pydantic for type safety
- pytest for comprehensive testing
- Black, Ruff, mypy for code quality

Inspired by the original [Rust MCP Sentinel](https://github.com/mcp-sentinel/mcp-sentinel)

---

<div align="center">

**Made with 🛡️ for the MCP Security Community**

**[⭐ Star on GitHub](https://github.com/beejak/mcp-sentinel)** • **[📦 View Releases](https://github.com/beejak/mcp-sentinel/releases)**

</div>
