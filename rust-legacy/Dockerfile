# MCP Sentinel - Multi-Stage Production Dockerfile
# Version: 2.5.0
# Purpose: Build minimal, secure, production-ready Docker image

# ============================================================================
# Stage 1: Builder - Compile Rust binary
# ============================================================================
FROM rust:1.70-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy dependency manifests first (Docker layer caching optimization)
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs to cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy actual source code
COPY src ./src
COPY tests ./tests

# Build the actual binary
# Touch main.rs to force rebuild with real code
RUN touch src/main.rs && \
    cargo build --release && \
    strip target/release/mcp-sentinel

# Verify binary works
RUN ./target/release/mcp-sentinel --version

# ============================================================================
# Stage 2: Semgrep Installation (Optional Component)
# ============================================================================
FROM python:3.11-slim-bookworm AS semgrep-builder

# Install Semgrep
RUN pip install --no-cache-dir semgrep==1.45.0

# ============================================================================
# Stage 3: Runtime - Minimal production image
# ============================================================================
FROM debian:bookworm-slim

# Metadata labels (OCI standard)
LABEL org.opencontainers.image.title="MCP Sentinel" \
      org.opencontainers.image.description="Enterprise-grade security scanner for Model Context Protocol servers" \
      org.opencontainers.image.version="2.5.0" \
      org.opencontainers.image.authors="MCP Sentinel Team" \
      org.opencontainers.image.url="https://github.com/beejak/MCP_Scanner" \
      org.opencontainers.image.source="https://github.com/beejak/MCP_Scanner" \
      org.opencontainers.image.licenses="Apache-2.0"

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    git \
    curl \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Copy MCP Sentinel binary from builder
COPY --from=builder /app/target/release/mcp-sentinel /usr/local/bin/mcp-sentinel

# Copy Semgrep from semgrep-builder (optional)
COPY --from=semgrep-builder /usr/local/bin/semgrep /usr/local/bin/semgrep
COPY --from=semgrep-builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

# Create non-root user for security
RUN groupadd -r mcp && \
    useradd -r -g mcp -d /home/mcp -s /sbin/nologin mcp && \
    mkdir -p /home/mcp/.mcp-sentinel && \
    chown -R mcp:mcp /home/mcp

# Create workspace directory
RUN mkdir -p /workspace && \
    chown mcp:mcp /workspace

# Set working directory
WORKDIR /workspace

# Switch to non-root user
USER mcp

# Set environment variables
ENV PATH="/usr/local/bin:${PATH}" \
    RUST_LOG="info" \
    MCP_SENTINEL_LOG_LEVEL="info"

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD mcp-sentinel --version || exit 1

# Default command (shows help)
ENTRYPOINT ["mcp-sentinel"]
CMD ["--help"]

# ============================================================================
# Build Instructions:
# ============================================================================
# Build image:
#   docker build -t mcp-sentinel:2.5.0 .
#   docker build -t mcp-sentinel:latest .
#
# Run scan:
#   docker run --rm -v $(pwd):/workspace mcp-sentinel:2.5.0 scan .
#
# With Semgrep:
#   docker run --rm -v $(pwd):/workspace mcp-sentinel:2.5.0 scan . --enable-semgrep
#
# Interactive shell:
#   docker run --rm -it -v $(pwd):/workspace --entrypoint /bin/bash mcp-sentinel:2.5.0
#
# ============================================================================
# Security Features:
# ============================================================================
# - Multi-stage build (minimal final image)
# - Non-root user (mcp)
# - Stripped binary (smaller size)
# - No unnecessary packages
# - Read-only filesystem compatible
# - Health check included
#
# ============================================================================
# Size Optimization:
# ============================================================================
# Expected image size: ~250-300 MB
# - Builder stage: ~2 GB (discarded)
# - Final image: Debian slim + binary + Semgrep
#
# Further optimization (if needed):
# - Use Alpine Linux (requires musl compilation)
# - Remove Semgrep (saves ~100 MB)
# - Use UPX compression on binary
# ============================================================================
