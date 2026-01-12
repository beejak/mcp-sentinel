# MCP Sentinel Python - Docker Guide

**Version**: 1.0.0  
**Purpose**: Complete guide to containerizing and running Python edition

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Dockerfile Options](#dockerfile-options)
3. [Multi-Stage Builds](#multi-stage-builds)
4. [Docker Compose](#docker-compose)
5. [Optimization Strategies](#optimization-strategies)
6. [CI/CD Integration](#cicd-integration)
7. [Security Best Practices](#security-best-practices)
8. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Using Pre-Built Image

```bash
# Pull from registry (when available)
docker pull ghcr.io/beejak/mcp-sentinel-python:1.0.0

# Run basic scan
docker run --rm -v $(pwd):/workspace ghcr.io/beejak/mcp-sentinel-python:1.0.0 scan /workspace

# Generate HTML report
docker run --rm -v $(pwd):/workspace ghcr.io/beejak/mcp-sentinel-python:1.0.0 \
  scan /workspace --output html --output-file /workspace/report.html

# Scan with custom config
docker run --rm -v $(pwd):/workspace \
  -v $(pwd)/config.toml:/app/config.toml \
  ghcr.io/beejak/mcp-sentinel-python:1.0.0 \
  scan /workspace --config /app/config.toml
```

### Building Locally

```bash
# Clone repository
git clone https://github.com/beejak/MCP_Scanner
cd MCP_Scanner/mcp-sentinel-python

# Build Docker image
docker build -t mcp-sentinel-python:local .

# Test the image
docker run --rm -v $(pwd):/workspace mcp-sentinel-python:local scan /workspace --help
```

---

## Dockerfile Options

### Standard Dockerfile

```dockerfile
# Dockerfile.python-standard
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VENV_IN_PROJECT=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install poetry==1.6.1

# Set work directory
WORKDIR /app

# Copy dependency files
COPY pyproject.toml poetry.lock ./

# Install dependencies
RUN poetry install --no-dev --no-interaction --no-ansi

# Copy application code
COPY . .

# Install the application
RUN poetry install --no-interaction --no-ansi

# Create non-root user
RUN adduser --disabled-password --gecos '' appuser && chown -R appuser:appuser /app
USER appuser

# Set entrypoint
ENTRYPOINT ["poetry", "run", "mcp-sentinel"]
CMD ["--help"]
```

### Alpine-Based Dockerfile (Smaller)

```dockerfile
# Dockerfile.python-alpine
FROM python:3.11-alpine

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_NO_INTERACTION=1

# Install system dependencies
RUN apk add --no-cache \
    build-base \
    git \
    libffi-dev \
    openssl-dev

# Install Poetry
RUN pip install poetry==1.6.1

# Set work directory
WORKDIR /app

# Copy and install dependencies
COPY pyproject.toml poetry.lock ./
RUN poetry config virtualenvs.create false \
    && poetry install --no-dev --no-interaction --no-ansi

# Copy application
COPY . .
RUN poetry install --no-interaction --no-ansi

# Create non-root user
RUN adduser -D -s /bin/sh appuser && chown -R appuser:appuser /app
USER appuser

ENTRYPOINT ["mcp-sentinel"]
CMD ["--help"]
```

### Distroless Dockerfile (Security-Focused)

```dockerfile
# Dockerfile.python-distroless
# Multi-stage build for minimal attack surface
FROM python:3.11-slim as builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install poetry==1.6.1

WORKDIR /app

# Copy and install dependencies
COPY pyproject.toml poetry.lock ./
RUN poetry config virtualenvs.create false \
    && poetry install --no-dev --no-interaction --no-ansi

# Copy application
COPY . .
RUN poetry install --no-interaction --no-ansi

# Create minimal runtime image
FROM gcr.io/distroless/python3-debian11

WORKDIR /app

# Copy installed packages and application
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/mcp-sentinel /usr/local/bin/mcp-sentinel
COPY --from=builder /app /app

# Set Python path
ENV PYTHONPATH=/usr/local/lib/python3.11/site-packages

ENTRYPOINT ["mcp-sentinel"]
```

---

## Multi-Stage Builds

### Development vs Production

```dockerfile
# Dockerfile.python-multistage
FROM python:3.11-slim as base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_NO_INTERACTION=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN pip install poetry==1.6.1

WORKDIR /app

# Development stage
FROM base as development

COPY pyproject.toml poetry.lock ./
RUN poetry install --no-interaction --no-ansi

COPY . .
RUN poetry install --no-interaction --no-ansi

EXPOSE 8000
CMD ["poetry", "run", "mcp-sentinel", "scan", "/workspace", "--watch"]

# Production stage
FROM base as production

COPY pyproject.toml poetry.lock ./
RUN poetry install --no-dev --no-interaction --no-ansi

COPY . .
RUN poetry install --no-interaction --no-ansi

# Create non-root user
RUN adduser --disabled-password --gecos '' appuser && chown -R appuser:appuser /app
USER appuser

ENTRYPOINT ["poetry", "run", "mcp-sentinel"]
CMD ["--help"]

# Build commands:
# docker build --target development -t mcp-sentinel-python:dev .
# docker build --target production -t mcp-sentinel-python:prod .
```

### Build Arguments for Flexibility

```dockerfile
# Dockerfile.python-args
ARG PYTHON_VERSION=3.11
ARG POETRY_VERSION=1.6.1

FROM python:${PYTHON_VERSION}-slim

ARG PYTHON_VERSION
ARG POETRY_VERSION

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN pip install poetry==${POETRY_VERSION}

WORKDIR /app

COPY pyproject.toml poetry.lock ./
RUN poetry install --no-dev --no-interaction --no-ansi

COPY . .
RUN poetry install --no-interaction --no-ansi

ARG APP_USER=appuser
RUN adduser --disabled-password --gecos '' ${APP_USER} && chown -R ${APP_USER}:${APP_USER} /app
USER ${APP_USER}

ENTRYPOINT ["poetry", "run", "mcp-sentinel"]

# Build with custom arguments:
# docker build --build-arg PYTHON_VERSION=3.10 --build-arg POETRY_VERSION=1.5.1 -t mcp-sentinel-python:custom .
```

---

## Docker Compose

### Basic Development Setup

```yaml
# docker-compose.dev.yml
version: '3.8'

services:
  mcp-sentinel:
    build:
      context: .
      dockerfile: Dockerfile.python-standard
      target: development
    volumes:
      - .:/workspace
      - poetry-cache:/root/.cache/pypoetry
    environment:
      - PYTHONPATH=/app
    command: scan /workspace --output html --output-file /workspace/dev-report.html
    networks:
      - sentinel-network

  # Optional: File watcher for continuous scanning
  sentinel-watch:
    build:
      context: .
      dockerfile: Dockerfile.python-standard
      target: development
    volumes:
      - .:/workspace
    command: scan /workspace --watch --output json --output-file /workspace/watch-results.json
    profiles:
      - watch

volumes:
  poetry-cache:

networks:
  sentinel-network:
    driver: bridge
```

### Production Setup with Multiple Services

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  # Main scanner service
  scanner:
    image: ghcr.io/beejak/mcp-sentinel-python:1.0.0
    volumes:
      - ./code:/workspace:ro
      - ./reports:/reports
    environment:
      - SCAN_TIMEOUT=300
      - MAX_CONCURRENT_FILES=10
    command: scan /workspace --output html --output-file /reports/scan-report.html
    networks:
      - sentinel-network
    restart: unless-stopped

  # API service (if implementing REST API)
  api:
    image: ghcr.io/beejak/mcp-sentinel-python:1.0.0
    ports:
      - "8080:8080"
    environment:
      - API_MODE=true
      - SCAN_WORKERS=4
    volumes:
      - ./uploads:/uploads
      - ./reports:/reports
    networks:
      - sentinel-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Redis for caching (optional)
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    networks:
      - sentinel-network
    restart: unless-stopped

  # PostgreSQL for results storage (optional)
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: sentinel_results
      POSTGRES_USER: sentinel
      POSTGRES_PASSWORD: ${DB_PASSWORD:-sentinel123}
    volumes:
      - postgres-data:/var/lib/postgresql/data
    networks:
      - sentinel-network
    restart: unless-stopped

volumes:
  redis-data:
  postgres-data:

networks:
  sentinel-network:
    driver: bridge
```

### CI/CD Pipeline Setup

```yaml
# docker-compose.ci.yml
version: '3.8'

services:
  # Scanner for CI/CD pipelines
  ci-scanner:
    build:
      context: .
      dockerfile: Dockerfile.python-alpine
    volumes:
      - ${WORKSPACE:-.}:/workspace:ro
      - ./ci-reports:/reports
    environment:
      - CI=true
      - SCAN_SEVERITY_THRESHOLD=${THRESHOLD:-MEDIUM}
      - SCAN_TIMEOUT=180
    command: >
      scan /workspace 
      --output sarif 
      --output-file /reports/ci-results.sarif
      --output html 
      --output-file /reports/ci-results.html
      --severity-threshold ${THRESHOLD:-MEDIUM}
    networks:
      - ci-network

  # SARIF processor for CI
  sarif-processor:
    image: ghcr.io/github/sarif-tools:latest
    volumes:
      - ./ci-reports:/reports:ro
    command: >
      sarif diff 
      /reports/baseline.sarif 
      /reports/ci-results.sarif 
      --output /reports/diff-results.sarif
    depends_on:
      - ci-scanner
    networks:
      - ci-network
    profiles:
      - sarif-diff

networks:
  ci-network:
    driver: bridge
```

---

## Optimization Strategies

### 1. Layer Caching Optimization

```dockerfile
# Optimize layer caching by copying dependency files first
FROM python:3.11-slim

# Install Poetry first (rarely changes)
RUN pip install poetry==1.6.1

# Copy dependency files (change less frequently)
COPY pyproject.toml poetry.lock ./
RUN poetry install --no-dev --no-interaction --no-ansi

# Copy source code (changes frequently)
COPY . .
RUN poetry install --no-interaction --no-ansi
```

### 2. Multi-Architecture Builds

```bash
# Build for multiple architectures
docker buildx create --name multiarch --use
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag ghcr.io/beejak/mcp-sentinel-python:1.0.0 \
  --push .
```

### 3. Size Optimization

```dockerfile
# Use Python slim variant
FROM python:3.11-slim

# Remove unnecessary packages after build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && poetry install --no-dev --no-interaction \
    && apt-get remove -y build-essential \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* /var/tmp/*
```

### 4. Performance Tuning

```dockerfile
# Set Python optimizations
ENV PYTHONOPTIMIZE=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Configure Poetry for performance
ENV POETRY_NO_INTERACTION=1 \
    POETRY_VENV_IN_PROJECT=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache
```

---

## CI/CD Integration

### GitHub Actions with Docker

```yaml
name: Docker Security Scan
on: [push, pull_request]

jobs:
  docker-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3
      
      - name: Build scanner image
        run: |
          docker build -f Dockerfile.python-alpine \
            -t mcp-sentinel-python:ci .
      
      - name: Run security scan
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/workspace:ro \
            -v ${{ github.workspace }}/reports:/reports \
            mcp-sentinel-python:ci \
            scan /workspace \
            --output sarif \
            --output-file /reports/results.sarif \
            --severity-threshold HIGH
      
      - name: Upload SARIF results
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: reports/results.sarif
```

### GitLab CI with Docker

```yaml
# .gitlab-ci.yml
docker-security-scan:
  stage: security
  image: docker:24-dind
  services:
    - docker:24-dind
  variables:
    DOCKER_DRIVER: overlay2
    DOCKER_TLS_CERTDIR: "/certs"
  before_script:
    - docker info
  script:
    - docker build -f Dockerfile.python-standard -t mcp-sentinel-python:gitlab .
    - docker run --rm \\
        -v $CI_PROJECT_DIR:/workspace:ro \\
        -v $CI_PROJECT_DIR/reports:/reports \\
        mcp-sentinel-python:gitlab \\
        scan /workspace \\
        --output sarif \\
        --output-file /reports/gitlab-results.sarif
  artifacts:
    reports:
      sast: reports/gitlab-results.sarif
    paths:
      - reports/gitlab-results.sarif
    expire_in: 1 week
```

---

## Security Best Practices

### 1. Non-Root User

```dockerfile
# Always run as non-root user
RUN adduser --disabled-password --gecos '' appuser
USER appuser
```

### 2. Read-Only Root Filesystem

```bash
# Run container with read-only root filesystem
docker run --rm \
  --read-only \
  -v $(pwd):/workspace:ro \
  -v /tmp:/tmp \
  -v $(pwd)/reports:/reports \
  mcp-sentinel-python scan /workspace
```

### 3. Security Scanning

```bash
# Scan the Docker image itself for vulnerabilities
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image mcp-sentinel-python:1.0.0
```

### 4. Resource Limits

```bash
# Run with resource limits
docker run --rm \
  --memory=512m \
  --cpus=1.0 \
  -v $(pwd):/workspace:ro \
  mcp-sentinel-python scan /workspace
```

### 5. Network Isolation

```bash
# Run in isolated network
docker network create --driver bridge isolated-scanner
docker run --rm \
  --network isolated-scanner \
  --network-alias scanner \
  -v $(pwd):/workspace:ro \
  mcp-sentinel-python scan /workspace
```

---

## Troubleshooting

### Common Issues

#### 1. Permission Denied
```bash
# Fix: Ensure proper volume permissions
docker run --rm \
  -u $(id -u):$(id -g) \
  -v $(pwd):/workspace \
  mcp-sentinel-python scan /workspace
```

#### 2. Memory Issues
```bash
# Fix: Increase memory limit and reduce concurrency
docker run --rm \
  --memory=1g \
  -e MAX_CONCURRENT_FILES=5 \
  -v $(pwd):/workspace:ro \
  mcp-sentinel-python scan /workspace
```

#### 3. Slow Performance
```bash
# Fix: Use Alpine-based image and optimize mounts
docker run --rm \
  --mount type=bind,source=$(pwd),target=/workspace,readonly \
  --tmpfs /tmp:rw,noexec,nosuid,size=100m \
  mcp-sentinel-python:alpine scan /workspace
```

#### 4. Poetry Issues in Container
```bash
# Fix: Clear Poetry cache and reinstall
docker run --rm \
  -v $(pwd):/workspace \
  mcp-sentinel-python bash -c "
    poetry cache clear --all pypi
    poetry install --no-interaction
    poetry run mcp-sentinel scan /workspace
  "
```

### Debugging Commands

```bash
# Check container logs
docker logs <container-id>

# Run with debug output
docker run --rm \
  -e DEBUG=1 \
  -v $(pwd):/workspace \
  mcp-sentinel-python scan /workspace

# Interactive debugging
docker run --rm -it \
  -v $(pwd):/workspace \
  --entrypoint /bin/bash \
  mcp-sentinel-python

# Check filesystem permissions
docker run --rm \
  -v $(pwd):/workspace \
  mcp-sentinel-python bash -c "ls -la /workspace"
```

### Performance Monitoring

```bash
# Monitor container resources
docker stats $(docker run -d -v $(pwd):/workspace mcp-sentinel-python scan /workspace)

# Profile memory usage
docker run --rm \
  -v $(pwd):/workspace \
  mcp-sentinel-python python -m memory_profiler -c "
import memory_profiler
from mcp_sentinel import scan_directory
scan_directory('/workspace')
"
```

---

**Docker Checklist**:
- [ ] Choose appropriate base image (slim/alpine/distroless)
- [ ] Implement multi-stage builds for optimization
- [ ] Configure proper caching layers
- [ ] Set up non-root user
- [ ] Configure health checks
- [ ] Implement security scanning
- [ ] Set up Docker Compose for development
- [ ] Configure CI/CD integration
- [ ] Optimize for size and performance
- [ ] Document troubleshooting steps