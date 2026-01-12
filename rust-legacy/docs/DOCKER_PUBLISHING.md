# Docker Publishing Guide - MCP Sentinel

**Complete guide for publishing MCP Sentinel to Docker Hub and GitHub Container Registry (GHCR)**

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Manual Publishing](#manual-publishing)
3. [Automated Publishing (GitHub Actions)](#automated-publishing-github-actions)
4. [Multi-Architecture Builds](#multi-architecture-builds)
5. [Tagging Strategy](#tagging-strategy)
6. [Best Practices](#best-practices)
7. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Accounts
1. **Docker Hub account**: https://hub.docker.com/signup
2. **GitHub account**: (you already have this)

### Required Tokens

#### Docker Hub Personal Access Token
1. Login to Docker Hub: https://hub.docker.com
2. Go to Account Settings → Security → New Access Token
3. Create token with **Read & Write** permissions
4. **Save the token** (shown only once)

#### GitHub Personal Access Token (for GHCR)
1. Go to GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Generate new token with these scopes:
   - `write:packages` - Upload packages to GitHub Package Registry
   - `read:packages` - Download packages from GitHub Package Registry
   - `delete:packages` - Delete packages from GitHub Package Registry (optional)
3. **Save the token** (shown only once)

### Add Secrets to GitHub Repository

1. Go to your repository: https://github.com/beejak/MCP_Scanner
2. Navigate to **Settings → Secrets and variables → Actions**
3. Click **New repository secret** and add:

   - **Name**: `DOCKER_HUB_USERNAME`
     **Value**: Your Docker Hub username (e.g., `beejak`)

   - **Name**: `DOCKER_HUB_TOKEN`
     **Value**: Your Docker Hub Personal Access Token

   - **Name**: `GHCR_TOKEN`
     **Value**: Your GitHub Personal Access Token
     *(Alternative: Use built-in `${{ secrets.GITHUB_TOKEN }}` which auto-rotates)*

---

## Manual Publishing

### Quick Manual Publish (Single Architecture)

```bash
# 1. Build the image
cd /path/to/MCP_Scanner
docker build -t mcp-sentinel:2.5.0 .

# 2. Test the image locally
docker run --rm mcp-sentinel:2.5.0 --version

# 3. Login to registries
docker login  # Docker Hub (enter username/password)
docker login ghcr.io -u beejak -p YOUR_GITHUB_TOKEN

# 4. Tag for Docker Hub
docker tag mcp-sentinel:2.5.0 beejak/mcp-sentinel:2.5.0
docker tag mcp-sentinel:2.5.0 beejak/mcp-sentinel:latest

# 5. Tag for GHCR
docker tag mcp-sentinel:2.5.0 ghcr.io/beejak/mcp-sentinel:2.5.0
docker tag mcp-sentinel:2.5.0 ghcr.io/beejak/mcp-sentinel:latest

# 6. Push to Docker Hub
docker push beejak/mcp-sentinel:2.5.0
docker push beejak/mcp-sentinel:latest

# 7. Push to GHCR
docker push ghcr.io/beejak/mcp-sentinel:2.5.0
docker push ghcr.io/beejak/mcp-sentinel:latest
```

### Verify Published Images

```bash
# Pull from Docker Hub
docker pull beejak/mcp-sentinel:2.5.0

# Pull from GHCR
docker pull ghcr.io/beejak/mcp-sentinel:2.5.0

# Test
docker run --rm beejak/mcp-sentinel:2.5.0 --version
docker run --rm ghcr.io/beejak/mcp-sentinel:2.5.0 --version
```

---

## Automated Publishing (GitHub Actions)

**Create this GitHub Actions workflow for automatic builds on every release.**

### Step 1: Create Workflow File

Create `.github/workflows/docker-publish.yml`:

```yaml
# .github/workflows/docker-publish.yml
name: Build and Publish Docker Images

on:
  push:
    tags:
      - 'v*.*.*'  # Trigger on version tags (v2.5.0, v2.6.0, etc.)
  release:
    types: [published]
  workflow_dispatch:  # Allow manual trigger

env:
  DOCKER_HUB_USERNAME: beejak
  DOCKER_HUB_REPO: beejak/mcp-sentinel
  GHCR_REPO: ghcr.io/beejak/mcp-sentinel

jobs:
  build-and-push:
    name: Build and Push Multi-Arch Images
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write

    steps:
      # 1. Checkout code
      - name: Checkout repository
        uses: actions/checkout@v4

      # 2. Set up Docker Buildx (for multi-arch builds)
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      # 3. Login to Docker Hub
      - name: Login to Docker Hub
        uses: docker/login-action@v3
        with:
          username: ${{ env.DOCKER_HUB_USERNAME }}
          password: ${{ secrets.DOCKER_HUB_TOKEN }}

      # 4. Login to GitHub Container Registry
      - name: Login to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      # 5. Extract version from tag
      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: |
            ${{ env.DOCKER_HUB_REPO }}
            ${{ env.GHCR_REPO }}
          tags: |
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
            type=semver,pattern={{major}}
            type=raw,value=latest,enable={{is_default_branch}}

      # 6. Build and push multi-architecture images
      - name: Build and push Docker images
        uses: docker/build-push-action@v5
        with:
          context: .
          file: ./Dockerfile
          platforms: linux/amd64,linux/arm64
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
          build-args: |
            RUST_VERSION=1.70

      # 7. Create image digest summary
      - name: Image digest
        run: echo ${{ steps.meta.outputs.digest }}
```

### Step 2: Test the Workflow

#### Option A: Create a Release (Recommended)
```bash
# 1. Create and push a tag
git tag v2.5.0
git push origin v2.5.0

# 2. Go to GitHub → Releases → Draft a new release
# 3. Select the tag v2.5.0
# 4. Fill in release notes
# 5. Click "Publish release"
# → This triggers the workflow automatically
```

#### Option B: Manual Trigger
1. Go to: https://github.com/beejak/MCP_Scanner/actions
2. Select "Build and Publish Docker Images"
3. Click "Run workflow"
4. Select branch (main)
5. Click "Run workflow" button

### Step 3: Monitor Build Progress

1. Go to: https://github.com/beejak/MCP_Scanner/actions
2. Click on the running workflow
3. Watch the build logs
4. Build time: ~8-15 minutes (multi-arch takes longer)

### Step 4: Verify Published Images

After workflow completes successfully:

```bash
# Check Docker Hub
open https://hub.docker.com/r/beejak/mcp-sentinel/tags

# Check GHCR
open https://github.com/beejak/MCP_Scanner/pkgs/container/mcp-sentinel

# Pull and test
docker pull beejak/mcp-sentinel:2.5.0
docker pull ghcr.io/beejak/mcp-sentinel:2.5.0

# Test both architectures (if on Apple Silicon)
docker pull --platform linux/amd64 beejak/mcp-sentinel:2.5.0
docker pull --platform linux/arm64 beejak/mcp-sentinel:2.5.0
```

---

## Multi-Architecture Builds

### Supported Architectures

MCP Sentinel supports these architectures:
- **linux/amd64** - Intel/AMD 64-bit (most common)
- **linux/arm64** - ARM 64-bit (Apple Silicon, AWS Graviton, Raspberry Pi 4+)

### Build Multi-Arch Locally (Advanced)

```bash
# 1. Create and use a new builder
docker buildx create --name mcp-builder --use
docker buildx inspect --bootstrap

# 2. Build for multiple platforms
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag beejak/mcp-sentinel:2.5.0 \
  --tag ghcr.io/beejak/mcp-sentinel:2.5.0 \
  --push \
  .

# Note: --push is required for multi-arch builds
# Cannot use --load (local) with multiple platforms
```

### Test Multi-Arch Images

```bash
# Test AMD64
docker run --rm --platform linux/amd64 beejak/mcp-sentinel:2.5.0 --version

# Test ARM64 (if on Apple Silicon)
docker run --rm --platform linux/arm64 beejak/mcp-sentinel:2.5.0 --version

# Docker automatically selects the right architecture
docker run --rm beejak/mcp-sentinel:2.5.0 --version
```

---

## Tagging Strategy

### Version Tags

For release `v2.5.0`, create these tags:

| Tag | Purpose | Example |
|-----|---------|---------|
| `2.5.0` | Exact version | `beejak/mcp-sentinel:2.5.0` |
| `2.5` | Minor version | `beejak/mcp-sentinel:2.5` |
| `2` | Major version | `beejak/mcp-sentinel:2` |
| `latest` | Latest stable | `beejak/mcp-sentinel:latest` |

**Why multiple tags?**
- Users wanting stability: `2.5.0` (never changes)
- Users wanting patches: `2.5` (gets 2.5.1, 2.5.2 updates)
- Users wanting latest: `latest` (gets all updates)

### Create All Tags

```bash
VERSION=2.5.0
MAJOR=2
MINOR=2.5

# Docker Hub
docker tag mcp-sentinel:$VERSION beejak/mcp-sentinel:$VERSION
docker tag mcp-sentinel:$VERSION beejak/mcp-sentinel:$MINOR
docker tag mcp-sentinel:$VERSION beejak/mcp-sentinel:$MAJOR
docker tag mcp-sentinel:$VERSION beejak/mcp-sentinel:latest

docker push beejak/mcp-sentinel:$VERSION
docker push beejak/mcp-sentinel:$MINOR
docker push beejak/mcp-sentinel:$MAJOR
docker push beejak/mcp-sentinel:latest

# GHCR
docker tag mcp-sentinel:$VERSION ghcr.io/beejak/mcp-sentinel:$VERSION
docker tag mcp-sentinel:$VERSION ghcr.io/beejak/mcp-sentinel:$MINOR
docker tag mcp-sentinel:$VERSION ghcr.io/beejak/mcp-sentinel:$MAJOR
docker tag mcp-sentinel:$VERSION ghcr.io/beejak/mcp-sentinel:latest

docker push ghcr.io/beejak/mcp-sentinel:$VERSION
docker push ghcr.io/beejak/mcp-sentinel:$MINOR
docker push ghcr.io/beejak/mcp-sentinel:$MAJOR
docker push ghcr.io/beejak/mcp-sentinel:latest
```

---

## Best Practices

### 1. Build from Release Tags

```bash
# Always build from tagged releases, not from main branch
git checkout v2.5.0
docker build -t mcp-sentinel:2.5.0 .
```

### 2. Test Before Publishing

```bash
# Build
docker build -t mcp-sentinel:test .

# Test help
docker run --rm mcp-sentinel:test --help

# Test version
docker run --rm mcp-sentinel:test --version

# Test basic scan
docker run --rm -v $(pwd)/tests/fixtures:/workspace mcp-sentinel:test scan /workspace

# Test Semgrep integration
docker run --rm -v $(pwd)/tests/fixtures:/workspace mcp-sentinel:test scan /workspace --enable-semgrep

# If all tests pass → proceed with publishing
```

### 3. Image Size Optimization

Current image size: **~250-300 MB**

**Check image size:**
```bash
docker images | grep mcp-sentinel
```

**Further optimization (if needed):**
```dockerfile
# Option 1: Remove Semgrep (saves ~100 MB)
# Comment out Semgrep installation lines in Dockerfile

# Option 2: Use Alpine (more complex, requires musl)
FROM alpine:latest
# Requires compiling with musl target

# Option 3: Compress binary with UPX
RUN upx --best --lzma /usr/local/bin/mcp-sentinel
```

### 4. Security Scanning

Scan published images for vulnerabilities:

```bash
# Using Trivy
docker run --rm aquasec/trivy image beejak/mcp-sentinel:2.5.0

# Using Snyk
snyk container test beejak/mcp-sentinel:2.5.0
```

### 5. Documentation

Update these after publishing:
- `README.md` - Installation instructions
- `docs/DOCKER.md` - Pull commands
- `docs/CHEATSHEET.md` - Quick reference
- GitHub Release notes - Docker image links

---

## Troubleshooting

### Issue: "authentication required"

```bash
# Solution: Login again
docker login
docker login ghcr.io
```

### Issue: Multi-arch build fails

```bash
# Solution: Ensure buildx is set up
docker buildx ls
docker buildx create --name mcp-builder --use
docker buildx inspect --bootstrap
```

### Issue: "manifest unknown" when pulling

```bash
# Solution: Image wasn't pushed correctly
docker push beejak/mcp-sentinel:2.5.0

# Verify it exists
docker manifest inspect beejak/mcp-sentinel:2.5.0
```

### Issue: GHCR image is private

```bash
# Solution: Make package public
# 1. Go to: https://github.com/beejak/MCP_Scanner/pkgs/container/mcp-sentinel
# 2. Click "Package settings"
# 3. Scroll to "Danger Zone"
# 4. Change visibility to "Public"
```

### Issue: Workflow fails with "permission denied"

**Solution: Enable workflow permissions**
1. Go to: https://github.com/beejak/MCP_Scanner/settings/actions
2. Scroll to "Workflow permissions"
3. Select "Read and write permissions"
4. Check "Allow GitHub Actions to create and approve pull requests"
5. Click "Save"

### Issue: Build is too slow

```bash
# Solution: Use GitHub Actions cache
# Already configured in the workflow with:
cache-from: type=gha
cache-to: type=gha,mode=max

# First build: ~15 minutes
# Subsequent builds: ~5 minutes (cached dependencies)
```

---

## Quick Reference

### Commands You'll Use Most

```bash
# 1. Build locally
docker build -t mcp-sentinel:2.5.0 .

# 2. Test locally
docker run --rm mcp-sentinel:2.5.0 --version

# 3. Tag for registries
docker tag mcp-sentinel:2.5.0 beejak/mcp-sentinel:2.5.0
docker tag mcp-sentinel:2.5.0 ghcr.io/beejak/mcp-sentinel:2.5.0

# 4. Login
docker login
docker login ghcr.io

# 5. Push
docker push beejak/mcp-sentinel:2.5.0
docker push ghcr.io/beejak/mcp-sentinel:2.5.0

# 6. Verify
docker pull beejak/mcp-sentinel:2.5.0
docker run --rm beejak/mcp-sentinel:2.5.0 --version
```

### Registry URLs

- **Docker Hub**: https://hub.docker.com/r/beejak/mcp-sentinel
- **GHCR**: https://github.com/beejak/MCP_Scanner/pkgs/container/mcp-sentinel
- **GitHub Actions**: https://github.com/beejak/MCP_Scanner/actions

---

## Next Steps

### Immediate (First Time Setup)

1. ✅ Create Docker Hub account (if needed)
2. ✅ Generate Docker Hub Personal Access Token
3. ✅ Add `DOCKER_HUB_USERNAME` and `DOCKER_HUB_TOKEN` to GitHub Secrets
4. ✅ Create `.github/workflows/docker-publish.yml` (copy from above)
5. ✅ Create a release (or push a tag) to trigger the workflow
6. ✅ Monitor workflow execution
7. ✅ Verify images on Docker Hub and GHCR
8. ✅ Make GHCR package public
9. ✅ Test pulling and running images

### For Every Release

1. Update version in `Cargo.toml`
2. Update version in `Dockerfile` labels
3. Update version in `README.md`, `DOCKER.md`, `CHEATSHEET.md`
4. Create git tag: `git tag v2.X.X && git push origin v2.X.X`
5. Create GitHub release with notes
6. Workflow auto-publishes Docker images
7. Verify images are available
8. Announce release

---

**Questions or issues?** Open an issue at https://github.com/beejak/MCP_Scanner/issues

**Version:** 2.5.0
**Last Updated:** October 26, 2025
