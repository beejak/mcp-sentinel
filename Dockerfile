# Multi-stage production Dockerfile for MCP Sentinel

# Stage 1: Builder
FROM python:3.11-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
ENV POETRY_VERSION=1.7.1
RUN curl -sSL https://install.python-poetry.org | python3 -
ENV PATH="/root/.local/bin:$PATH"

# Set working directory
WORKDIR /build

# Copy dependency files
COPY pyproject.toml poetry.lock ./

# Install dependencies (no dev dependencies)
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root --only main

# Copy source code
COPY src/ ./src/
COPY README.md ./

# Install the package
RUN poetry build && pip install dist/*.whl

# Stage 2: Runtime
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 sentinel && \
    mkdir -p /app /data /reports && \
    chown -R sentinel:sentinel /app /data /reports

# Set working directory
WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/mcp-sentinel /usr/local/bin/mcp-sentinel

# Switch to non-root user
USER sentinel

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command (can be overridden)
CMD ["mcp-sentinel", "server", "--host", "0.0.0.0", "--port", "8000"]

# Metadata
LABEL org.opencontainers.image.title="MCP Sentinel"
LABEL org.opencontainers.image.description="Enterprise security scanner for MCP servers"
LABEL org.opencontainers.image.version="4.1.0"
LABEL org.opencontainers.image.authors="MCP Sentinel Team"
LABEL org.opencontainers.image.source="https://github.com/beejak/mcp-sentinel"
