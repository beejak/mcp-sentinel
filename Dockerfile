# MCP Sentinel - Multi-Engine Security Scanner
# Supports both CLI scanning and API server modes
#
# Build: docker build -t mcp-sentinel .
#
# CLI Usage Examples:
# - Scan current directory:
#   docker run -v $(pwd):/scan mcp-sentinel scan /scan
#
# - Generate HTML report:
#   docker run -v $(pwd):/scan -v $(pwd)/reports:/reports \
#     mcp-sentinel scan /scan --output html --json-file /reports/report.html
#
# - Multi-engine scan:
#   docker run -v $(pwd):/scan mcp-sentinel scan /scan --engines all
#
# - AI-powered scan (requires API key):
#   docker run -e ANTHROPIC_API_KEY=your-key -v $(pwd):/scan \
#     mcp-sentinel scan /scan --engines all
#
# Server Mode:
# - docker run -p 8000:8000 mcp-sentinel server

# Stage 1: Builder
FROM python:3.11-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy dependency files
COPY pyproject.toml setup.py README.md ./

# Copy source code
COPY src/ ./src/

# Install MCP Sentinel and all dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e . && \
    pip install --no-cache-dir semgrep bandit

# Stage 2: Runtime
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 sentinel && \
    mkdir -p /app /scan /reports && \
    chown -R sentinel:sentinel /app /scan /reports

# Set working directory
WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/mcp-sentinel /usr/local/bin/mcp-sentinel
COPY --from=builder /usr/local/bin/semgrep /usr/local/bin/semgrep
COPY --from=builder /usr/local/bin/bandit /usr/local/bin/bandit

# Switch to non-root user
USER sentinel

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV MCP_SENTINEL_VERSION=4.3.0

# Volume mounts for scanning
VOLUME ["/scan", "/reports"]

# Health check for server mode
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default entrypoint (can be overridden)
ENTRYPOINT ["mcp-sentinel"]

# Default command - shows help (override for specific operations)
CMD ["--help"]

# Metadata
LABEL org.opencontainers.image.title="MCP Sentinel"
LABEL org.opencontainers.image.description="Multi-Engine Security Scanner - CLI and Server modes"
LABEL org.opencontainers.image.version="4.3.0"
LABEL org.opencontainers.image.authors="MCP Sentinel Team"
LABEL org.opencontainers.image.source="https://github.com/beejak/mcp-sentinel"
