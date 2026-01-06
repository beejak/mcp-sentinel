# MCP Sentinel - Python Edition

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

> **Enterprise-grade security scanner for Model Context Protocol (MCP) servers**

MCP Sentinel is a comprehensive security platform that combines static analysis, semantic analysis, SAST, and AI-powered detection to identify vulnerabilities in MCP implementations before they become security incidents.

## 🚀 Quick Start

```bash
# Install with Poetry
poetry install

# Or install with pip
pip install mcp-sentinel

# Run a scan
mcp-sentinel scan /path/to/mcp/server

# Start API server
mcp-sentinel server --port 8000

# Run comprehensive audit
mcp-sentinel audit /path/to/project --output html
```

## ✨ Key Features

### 🔍 Multi-Engine Detection
- **Static Analysis**: 40+ regex patterns for secrets, injection flaws
- **Semantic Analysis**: Tree-sitter AST parsing with dataflow tracking
- **SAST Integration**: Semgrep + Bandit for comprehensive coverage
- **AI Analysis**: LLM-powered contextual vulnerability detection

### 🎯 78+ Vulnerability Patterns
- Hardcoded secrets (15+ types: AWS keys, API tokens, private keys)
- Code injection (command injection, eval, exec)
- Prompt injection & jailbreaks
- Tool poisoning attacks
- Supply chain vulnerabilities (11 patterns)
- DOM-based XSS
- Path traversal
- MCP configuration security

### 🏢 Enterprise Integrations
- **Ticketing**: Jira, ServiceNow, Linear
- **Notifications**: Slack, Microsoft Teams, PagerDuty, Email
- **Secret Management**: HashiCorp Vault, AWS Secrets Manager
- **VCS**: GitHub, GitLab, Bitbucket
- **CI/CD**: GitHub Actions, GitLab CI, Jenkins, CircleCI
- **Logging**: Splunk, Datadog, Elasticsearch

### 📊 Advanced Reporting
- **Interactive HTML**: Charts, filterable tables, risk scoring
- **PDF Reports**: Executive summaries, technical details
- **Excel**: Data analysis friendly exports
- **SARIF 2.1.0**: Security tool integration
- **Compliance**: SOC2, HIPAA, PCI-DSS, NIST mapping

### ⚡ Performance
- **<5s scans** for 1000 files
- **<100ms API latency** (p95)
- **Parallel processing** with asyncio
- **Smart caching** (Redis + in-memory)
- **Differential scanning** (git diff aware)

## 📦 Installation

### Using Poetry (Recommended)

```bash
# Clone repository
git clone https://github.com/mcp-sentinel/mcp-sentinel-python.git
cd mcp-sentinel-python

# Install dependencies
poetry install

# Activate virtual environment
poetry shell
```

### Using pip

```bash
pip install mcp-sentinel

# With all extras
pip install "mcp-sentinel[all]"

# With specific features
pip install "mcp-sentinel[ai,integrations]"
```

### Using Docker

```bash
# Pull image
docker pull ghcr.io/mcp-sentinel/mcp-sentinel:latest

# Run scan
docker run --rm -v $(pwd):/workspace mcp-sentinel scan /workspace
```

## 🔧 Configuration

Create a configuration file at `.mcp-sentinel.yaml`:

```yaml
# Analysis engines to enable
engines:
  static: true
  semantic: true
  sast: true
  ai: true

# AI provider configuration
ai:
  provider: anthropic  # openai, anthropic, google, ollama
  model: claude-3-5-sonnet-20241022
  api_key: ${ANTHROPIC_API_KEY}
  max_tokens: 4000

# Integrations
integrations:
  jira:
    enabled: true
    url: https://your-company.atlassian.net
    project_key: SEC
    api_token: ${JIRA_API_TOKEN}

  slack:
    enabled: true
    webhook_url: ${SLACK_WEBHOOK_URL}
    channel: "#security-alerts"

# Reporting
reporting:
  formats: [html, json, sarif]
  output_dir: ./reports

# Performance
performance:
  max_workers: 4
  cache_enabled: true
  parallel_execution: true
```

## 📖 Usage Examples

### CLI Usage

```bash
# Basic scan
mcp-sentinel scan /path/to/project

# Scan with specific engines
mcp-sentinel scan /path/to/project --engines static,semantic,ai

# Output to multiple formats
mcp-sentinel scan /path/to/project -o json,html,sarif

# Scan GitHub repository
mcp-sentinel scan https://github.com/owner/repo

# Comprehensive audit (all engines)
mcp-sentinel audit /path/to/project --severity critical,high

# Continuous monitoring
mcp-sentinel monitor /path/to/project --interval 300

# Initialize configuration
mcp-sentinel init
```

### API Usage

```python
from mcp_sentinel import Scanner
from mcp_sentinel.engines import StaticEngine, SemanticEngine, AIEngine

# Create scanner
scanner = Scanner(
    engines=[
        StaticEngine(),
        SemanticEngine(),
        AIEngine(provider="anthropic", model="claude-3-5-sonnet-20241022")
    ]
)

# Scan directory
results = await scanner.scan_directory("/path/to/project")

# Generate reports
from mcp_sentinel.reporting import HTMLReportGenerator

generator = HTMLReportGenerator()
report = await generator.generate(results)
report.save("./report.html")
```

### FastAPI Server

```bash
# Start server
mcp-sentinel server --host 0.0.0.0 --port 8000

# Access API docs
open http://localhost:8000/docs
```

```python
import httpx

# Trigger scan via API
async with httpx.AsyncClient() as client:
    response = await client.post(
        "http://localhost:8000/api/v1/scans",
        json={
            "target": "/path/to/project",
            "engines": ["static", "semantic", "ai"],
            "output_formats": ["json", "sarif"]
        }
    )
    scan_id = response.json()["scan_id"]

    # Get results
    results = await client.get(f"http://localhost:8000/api/v1/scans/{scan_id}")
    print(results.json())
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    API Gateway                           │
│               (FastAPI + GraphQL)                        │
└────────────┬────────────────────────────┬───────────────┘
             │                            │
    ┌────────▼────────┐         ┌────────▼────────┐
    │  Scan Service   │         │  Report Service │
    └────────┬────────┘         └────────┬────────┘
             │                            │
    ┌────────▼────────────────────────────▼────────┐
    │         Message Queue (Celery)               │
    └────────┬────────────────────────────┬────────┘
             │                            │
    ┌────────▼────────┐         ┌────────▼────────┐
    │  Worker Nodes   │         │  Worker Nodes   │
    └─────────────────┘         └─────────────────┘
```

### Key Components

- **Detectors**: 8 specialized vulnerability detectors
- **Engines**: 4 complementary analysis engines
- **Integrations**: 15+ enterprise integrations
- **Reporting**: 6 output formats
- **Storage**: PostgreSQL + Redis + S3
- **Async Tasks**: Celery with Redis broker

## 🧪 Development

### Setup Development Environment

```bash
# Install dependencies (including dev)
poetry install --with dev

# Install pre-commit hooks
pre-commit install

# Run tests
pytest

# Run tests with coverage
pytest --cov

# Type checking
mypy src/

# Linting
ruff check src/
black --check src/

# Format code
black src/
ruff --fix src/
```

### Running Tests

```bash
# Unit tests
pytest tests/unit

# Integration tests
pytest tests/integration

# E2E tests
pytest tests/e2e

# Performance tests
locust -f tests/performance/locustfile.py
```

### Project Structure

```
mcp-sentinel-python/
├── src/mcp_sentinel/
│   ├── api/              # FastAPI application
│   ├── cli/              # Click-based CLI
│   ├── core/             # Core business logic
│   ├── detectors/        # Vulnerability detectors
│   ├── engines/          # Analysis engines
│   ├── integrations/     # Enterprise integrations
│   ├── reporting/        # Report generation
│   ├── storage/          # Data persistence
│   └── tasks/            # Async task processing
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
├── docs/
├── k8s/                  # Kubernetes manifests
└── migrations/           # Database migrations
```

## 🚢 Deployment

### Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Scale workers
docker-compose up -d --scale worker=5
```

### Kubernetes

```bash
# Deploy to Kubernetes
kubectl apply -f k8s/

# Check status
kubectl get pods -n mcp-sentinel

# View logs
kubectl logs -f deployment/mcp-sentinel-api -n mcp-sentinel
```

### Helm

```bash
# Install with Helm
helm install mcp-sentinel ./helm/mcp-sentinel \
  --namespace mcp-sentinel \
  --create-namespace \
  --values values.prod.yaml
```

## 📚 Documentation

- [Architecture Overview](docs/architecture.md)
- [User Guide](docs/user-guide/index.md)
- [API Reference](docs/api-reference.md)
- [Integration Guides](docs/integrations/)
- [Developer Guide](docs/developer-guide/)
- [Deployment Guide](docs/deployment/)

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`pytest`)
5. Run linting (`ruff check`, `mypy`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Ported from the original [Rust implementation](https://github.com/mcp-sentinel/mcp-sentinel)
- Built with [FastAPI](https://fastapi.tiangolo.com/), [LangChain](https://www.langchain.com/), and [Tree-sitter](https://tree-sitter.github.io/)
- Inspired by industry-leading security tools

## 📞 Support

- **Documentation**: https://docs.mcp-sentinel.dev
- **Issues**: https://github.com/mcp-sentinel/mcp-sentinel-python/issues
- **Discord**: https://discord.gg/mcp-sentinel
- **Email**: support@mcp-sentinel.dev

## 🗺️ Roadmap

### v3.0.0 (Current)
- ✅ Complete rewrite in Python
- ✅ FastAPI + GraphQL APIs
- ✅ 15+ enterprise integrations
- ✅ Advanced reporting (HTML, PDF, Excel)
- ✅ AI-powered analysis

### v3.1.0 (Next)
- [ ] Rust, Java, C++ language support
- [ ] Custom rule authoring UI
- [ ] Advanced ML-based detection

### v3.2.0 (Future)
- [ ] Web dashboard (React)
- [ ] Real-time monitoring UI
- [ ] Vulnerability trend prediction

---

**Made with ❤️ by the MCP Sentinel Team**
