# MCP Sentinel - Deployment Guide

This document outlines the steps to deploy MCP Sentinel in various environments.

## Prerequisites

- **Docker** (v20.10+)
- **Docker Compose** (v2.0+)
- **Python** (3.9+) - *If running bare metal*

## Docker Deployment (Recommended)

The easiest way to run MCP Sentinel is via Docker.

### 1. Build the Image

```bash
docker build -t mcp-sentinel:latest .
```

### 2. Configure Environment

Create a `.env` file based on the example in `CONFIGURATION.md`.

```bash
cp .env.example .env
# Edit .env with your keys and settings
```

### 3. Run with Docker Compose

```bash
docker-compose up -d
```

This will start:
- **API Server**: http://localhost:8000
- **PostgreSQL**: Database
- **Redis**: Cache & Message Broker

## Bare Metal Deployment

### 1. Install Dependencies

```bash
# System dependencies (Ubuntu/Debian)
sudo apt-get install -y build-essential python3-dev libpq-dev

# Install Poetry
curl -sSL https://install.python-poetry.org | python3 -
```

### 2. Install Project

```bash
git clone https://github.com/your-org/mcp-sentinel.git
cd mcp-sentinel
poetry install
```

### 3. Database Setup

```bash
# Ensure PostgreSQL is running and create database
createdb mcp_sentinel
```

### 4. Run Server

```bash
poetry run uvicorn mcp_sentinel.api.main:app --host 0.0.0.0 --port 8000
```

## Cloud Deployment

### AWS (ECS/Fargate)

1. Push Docker image to ECR.
2. Create a Task Definition using the image.
3. Configure environment variables in the Task Definition (use Secrets Manager for keys).
4. Launch Service behind an Application Load Balancer.

### Kubernetes (Helm)

*Coming soon: Official Helm chart.*

Current approach:
1. Create `Deployment` and `Service` manifests.
2. Use `ConfigMap` for non-sensitive config and `Secret` for API keys.
3. Apply manifests: `kubectl apply -f k8s/`

## Verification

After deployment, verify health:

```bash
curl http://localhost:8000/health
# Output: {"status": "ok", ...}
```
