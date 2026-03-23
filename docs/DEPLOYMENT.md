# MCP Sentinel — Deployment Guide

**Version**: v0.2.0

MCP Sentinel is a command-line tool. There is no server to deploy, no database to provision, and no API to host. You install it wherever you need to run scans: a developer laptop, a CI runner, or a Docker container.

---

## Installation

### pip (recommended)

```bash
pip install mcp-sentinel
```

Or pin to a specific version:

```bash
pip install mcp-sentinel==0.2.0
```

### From source

```bash
git clone https://github.com/beejak/mcp-sentinel.git
cd mcp-sentinel
pip install -e .
```

### With dev dependencies (for running tests)

```bash
pip install -e ".[dev]"
```

### Verify installation

```bash
mcp-sentinel --version
mcp-sentinel --help
```

---

## Python version requirements

| Python | Supported |
|---|---|
| 3.9 | Yes |
| 3.10 | Yes |
| 3.11 | Yes (recommended) |
| 3.12 | Yes |
| 3.8 and below | No |

---

## Running a scan

```bash
# Scan a directory, print to terminal
mcp-sentinel scan /path/to/mcp-server

# Write SARIF output for GitHub Code Scanning
mcp-sentinel scan /path/to/mcp-server \
  --output sarif \
  --json-file results.sarif

# Write JSON output for scripting
mcp-sentinel scan /path/to/mcp-server \
  --output json \
  --json-file results.json

# Only report critical findings
mcp-sentinel scan /path/to/mcp-server --severity critical
```

---

## Docker

MCP Sentinel has no official Docker image, but it's trivial to containerize:

```dockerfile
FROM python:3.11-slim

RUN pip install mcp-sentinel

ENTRYPOINT ["mcp-sentinel"]
```

Build and run:

```bash
docker build -t mcp-sentinel .

# Scan a local directory by mounting it
docker run --rm \
  -v /path/to/mcp-server:/target:ro \
  mcp-sentinel scan /target \
    --output sarif \
    --json-file /dev/stdout \
    --no-progress
```

---

## CI/CD

See [`docs/CI_CD_INTEGRATION.md`](CI_CD_INTEGRATION.md) for ready-to-use configs for:

- GitHub Actions
- GitLab CI
- Jenkins
- Azure DevOps
- CircleCI
- Bitbucket Pipelines

Short version for any CI system:

```bash
pip install mcp-sentinel
mcp-sentinel scan . --output sarif --json-file results.sarif --no-progress
```

---

## Virtualenv / isolation

MCP Sentinel has no optional runtime dependencies beyond what's listed in `pyproject.toml`. It's safe to install in a shared virtualenv alongside your MCP server dependencies.

```bash
python -m venv .venv
source .venv/bin/activate
pip install mcp-sentinel
mcp-sentinel scan .
```

---

## Ignoring paths

Create a `.sentinelignore` file at the root of your project with paths to exclude (`.gitignore` syntax):

```
node_modules/
.venv/
__pycache__/
*.min.js
dist/
build/
```

---

## Configuration

All configuration is via environment variables. See [`docs/CONFIGURATION.md`](CONFIGURATION.md) for the full reference.

Key variables:

```bash
LOG_LEVEL=info          # debug | info | warning | error
MAX_WORKERS=4           # concurrent file workers
CACHE_TTL=3600          # cache TTL in seconds (0 = disabled)
```
