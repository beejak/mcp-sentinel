# PyPI Publishing Guide

**Version**: 3.0.0
**Last Updated**: 2026-01-07
**Status**: Ready for Publishing

This guide covers how to publish MCP Sentinel to the Python Package Index (PyPI).

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Manual Publishing](#manual-publishing)
3. [Automated Publishing with GitHub Actions](#automated-publishing-with-github-actions)
4. [Version Management](#version-management)
5. [Post-Publication Checklist](#post-publication-checklist)
6. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### 1. PyPI Account Setup

**Create PyPI Account:**
1. Go to https://pypi.org/account/register/
2. Create an account with a strong password
3. Verify your email address
4. Enable 2FA (highly recommended)

**Create TestPyPI Account** (for testing):
1. Go to https://test.pypi.org/account/register/
2. Create a separate account (same credentials are fine)

### 2. Generate API Tokens

**PyPI API Token:**
1. Go to https://pypi.org/manage/account/token/
2. Click "Add API token"
3. Name: `mcp-sentinel-release`
4. Scope: `Entire account` (or specific to `mcp-sentinel` after first upload)
5. **SAVE THE TOKEN** - you won't see it again!

**TestPyPI API Token:**
1. Go to https://test.pypi.org/manage/account/token/
2. Same process as above
3. Name: `mcp-sentinel-test`

### 3. Configure Poetry

```bash
# Add PyPI credentials
poetry config pypi-token.pypi <your-pypi-token>

# Add TestPyPI credentials (for testing)
poetry config repositories.testpypi https://test.pypi.org/legacy/
poetry config pypi-token.testpypi <your-testpypi-token>
```

### 4. Install Build Tools

```bash
# Ensure Poetry is up to date
poetry self update

# Install build dependencies
poetry install
```

---

## Manual Publishing

### Step 1: Pre-Publication Checklist

```bash
# 1. Ensure you're on the main branch
git checkout main
git pull origin main

# 2. Verify version in pyproject.toml
grep "version" pyproject.toml
# Should show: version = "3.0.0"

# 3. Run all tests
poetry run pytest tests/ -v --cov=src

# 4. Check code quality
poetry run black src/ tests/
poetry run ruff check src/ tests/
poetry run mypy src/

# 5. Build documentation
cd docs
# Review all documentation files

# 6. Verify README renders correctly
# Visit: https://github.com/beejak/mcp-sentinel/blob/main/mcp-sentinel-python/README.md
```

### Step 2: Build the Package

```bash
# Clean previous builds
rm -rf dist/

# Build the package
poetry build

# Verify the build
ls -lh dist/
# You should see:
# - mcp_sentinel-3.0.0.tar.gz (source distribution)
# - mcp_sentinel-3.0.0-py3-none-any.whl (wheel)
```

### Step 3: Test on TestPyPI (Recommended)

```bash
# Publish to TestPyPI first
poetry publish -r testpypi

# Install from TestPyPI to test
pip install --index-url https://test.pypi.org/simple/ mcp-sentinel==3.0.0

# Verify installation
mcp-sentinel --version
mcp-sentinel --help

# Test basic functionality
mcp-sentinel scan ./test-project

# Uninstall test version
pip uninstall mcp-sentinel
```

### Step 4: Publish to PyPI

```bash
# Publish to PyPI (FINAL STEP - cannot be undone!)
poetry publish

# Output should show:
# Publishing mcp-sentinel (3.0.0) to PyPI
#  - Uploading mcp_sentinel-3.0.0.tar.gz 100%
#  - Uploading mcp_sentinel-3.0.0-py3-none-any.whl 100%
```

### Step 5: Verify Publication

```bash
# Wait 1-2 minutes for PyPI to process

# Check PyPI page
# Visit: https://pypi.org/project/mcp-sentinel/

# Test installation
pip install mcp-sentinel

# Verify version
mcp-sentinel --version
# Should show: mcp-sentinel, version 3.0.0

# Test functionality
mcp-sentinel scan ./test-project
```

---

## Automated Publishing with GitHub Actions

### GitHub Actions Workflow

Create `.github/workflows/publish-pypi.yml`:

```yaml
name: Publish to PyPI

on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install Poetry
        run: |
          curl -sSL https://install.python-poetry.org | python3 -
          echo "$HOME/.local/bin" >> $GITHUB_PATH

      - name: Install dependencies
        run: |
          cd mcp-sentinel-python
          poetry install

      - name: Run tests
        run: |
          cd mcp-sentinel-python
          poetry run pytest tests/ -v --cov=src

      - name: Build package
        run: |
          cd mcp-sentinel-python
          poetry build

      - name: Publish to PyPI
        env:
          POETRY_PYPI_TOKEN_PYPI: ${{ secrets.PYPI_API_TOKEN }}
        run: |
          cd mcp-sentinel-python
          poetry publish
```

### Setup GitHub Secrets

1. Go to your GitHub repository
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Name: `PYPI_API_TOKEN`
5. Value: Your PyPI API token
6. Click **Add secret**

### Trigger Automated Publishing

```bash
# When you create a GitHub release, the workflow will automatically:
# 1. Run tests
# 2. Build the package
# 3. Publish to PyPI

# To create a release:
# 1. Go to https://github.com/beejak/mcp-sentinel/releases
# 2. Click "Draft a new release"
# 3. Choose tag: v3.0.0
# 4. Add release notes
# 5. Click "Publish release"
```

---

## Version Management

### Semantic Versioning

MCP Sentinel follows [Semantic Versioning](https://semver.org/):

```
MAJOR.MINOR.PATCH

MAJOR: Breaking changes (e.g., 1.0.0 → 2.0.0)
MINOR: New features, backward compatible (e.g., 2.1.0 → 2.2.0)
PATCH: Bug fixes, backward compatible (e.g., 2.2.0 → 2.2.1)
```

### Updating Version

**Method 1: Poetry Command**
```bash
# Bump patch version (2.2.0 → 2.2.1)
poetry version patch

# Bump minor version (2.2.1 → 2.3.0)
poetry version minor

# Bump major version (2.3.0 → 3.0.0)
poetry version major

# Set specific version
poetry version 3.0.0
```

**Method 2: Manual Edit**
```bash
# Edit pyproject.toml
vim pyproject.toml

# Find and update:
version = "3.0.0"  # Update this line
```

### Version Update Checklist

- [ ] Update `version` in `pyproject.toml`
- [ ] Update `__version__` in `src/mcp_sentinel/__init__.py`
- [ ] Update version in documentation (README.md, docs/README.md)
- [ ] Update CHANGELOG.md with new version changes
- [ ] Create git tag: `git tag -a v3.0.0 -m "Release v3.0.0"`
- [ ] Push tag: `git push origin v3.0.0`

---

## Post-Publication Checklist

### Immediately After Publishing

- [ ] **Verify PyPI Page**: Visit https://pypi.org/project/mcp-sentinel/
- [ ] **Test Installation**: `pip install mcp-sentinel`
- [ ] **Check Version**: `mcp-sentinel --version`
- [ ] **Test Basic Functionality**: Run a test scan
- [ ] **Verify Documentation Links**: Ensure README renders correctly on PyPI

### Within 24 Hours

- [ ] **Monitor Downloads**: Check PyPI stats
- [ ] **Check for Issues**: Monitor GitHub issues for installation problems
- [ ] **Update Social Media**: Announce the release (if applicable)
- [ ] **Update Documentation**: Ensure all docs reference correct version
- [ ] **Create GitHub Release**: If not using automated workflow

### Package Metadata Verification

Visit https://pypi.org/project/mcp-sentinel/ and verify:

- [ ] **Correct Version**: Shows v3.0.0
- [ ] **README Rendering**: Markdown renders correctly
- [ ] **Links Work**: Homepage, documentation, repository links functional
- [ ] **Classifiers**: Python versions, license, development status correct
- [ ] **Keywords**: Security, MCP, scanner, vulnerability, LLM
- [ ] **Installation Command**: `pip install mcp-sentinel` works

---

## Troubleshooting

### Issue: "File already exists"

**Problem**: Trying to upload a version that already exists on PyPI.

**Solution**: You cannot replace an existing version. You must:
1. Bump the version number
2. Build and publish the new version

```bash
# Bump to next patch version
poetry version patch

# Rebuild and publish
poetry build
poetry publish
```

### Issue: "Invalid credentials"

**Problem**: API token is incorrect or expired.

**Solution**: Regenerate API token and update Poetry config:

```bash
# Go to https://pypi.org/manage/account/token/
# Generate new token

# Update Poetry config
poetry config pypi-token.pypi <new-token>
```

### Issue: "Package name already taken"

**Problem**: Another package with the name `mcp-sentinel` already exists.

**Solution**: Choose a different package name:

```bash
# Update pyproject.toml
name = "mcp-sentinel-scanner"  # Or another unique name

# Rebuild
poetry build
poetry publish
```

**Note**: As of Jan 2026, `mcp-sentinel` appears to be available, but always check first.

### Issue: "README not rendering on PyPI"

**Problem**: Markdown syntax not supported by PyPI.

**Solution**: Ensure README uses PyPI-supported Markdown:

```bash
# Check README with twine
pip install twine
twine check dist/*

# Fix any warnings
# Common issues:
# - Unsupported HTML tags
# - Missing blank lines
# - Incorrect link syntax
```

### Issue: "Build fails"

**Problem**: `poetry build` command fails.

**Solution**: Check dependencies and Python version:

```bash
# Verify Python version
python --version  # Should be 3.11+

# Update Poetry
poetry self update

# Clear cache
poetry cache clear pypi --all

# Reinstall dependencies
rm poetry.lock
poetry install

# Try building again
poetry build
```

### Issue: "Import errors after installation"

**Problem**: Package installs but imports fail.

**Solution**: Check package structure:

```bash
# Ensure src layout is correct
# src/mcp_sentinel/__init__.py should exist

# Verify MANIFEST.in includes all necessary files
cat MANIFEST.in

# Check installed package
pip show mcp-sentinel
pip show -f mcp-sentinel  # Shows all installed files
```

---

## Testing Different Installation Methods

### Install from PyPI

```bash
# Standard installation
pip install mcp-sentinel

# Specific version
pip install mcp-sentinel==3.0.0

# Upgrade to latest
pip install --upgrade mcp-sentinel
```

### Install from TestPyPI

```bash
# Install from TestPyPI
pip install --index-url https://test.pypi.org/simple/ mcp-sentinel

# With dependencies from PyPI
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ mcp-sentinel
```

### Install from GitHub

```bash
# Install directly from GitHub
pip install git+https://github.com/beejak/mcp-sentinel.git@main#subdirectory=mcp-sentinel-python

# Install specific tag
pip install git+https://github.com/beejak/mcp-sentinel.git@v3.0.0#subdirectory=mcp-sentinel-python
```

### Install in Development Mode

```bash
# Clone repository
git clone https://github.com/beejak/mcp-sentinel.git
cd mcp-sentinel/mcp-sentinel-python

# Install with Poetry
poetry install

# Or install with pip
pip install -e .
```

---

## Package Analytics

### PyPI Statistics

After publishing, you can track:

- **Total Downloads**: https://pypistats.org/packages/mcp-sentinel
- **Download Trends**: Daily, weekly, monthly downloads
- **Python Version Usage**: Which Python versions users are using
- **Download Sources**: pip, conda, etc.

### GitHub Analytics

- **Stars**: Repository popularity
- **Forks**: Community engagement
- **Issues**: User feedback and bug reports
- **Downloads**: Release download counts

---

## Best Practices

1. **Always test on TestPyPI first** before publishing to PyPI
2. **Never delete a published version** - it breaks dependent projects
3. **Use semantic versioning** consistently
4. **Keep CHANGELOG.md updated** for every release
5. **Tag releases in git** to match PyPI versions
6. **Automate with GitHub Actions** to reduce manual errors
7. **Monitor for issues** after publishing
8. **Test installation** on clean environments (Docker, VM)
9. **Document breaking changes** clearly in release notes
10. **Respond to issues promptly** to build community trust

---

## Security Considerations

1. **Never commit API tokens** to git
2. **Use GitHub Secrets** for automation
3. **Enable 2FA** on PyPI account
4. **Use scoped API tokens** when possible
5. **Rotate tokens** periodically (every 6-12 months)
6. **Review dependencies** for vulnerabilities before publishing
7. **Sign releases** with GPG (optional but recommended)

---

## Quick Reference

```bash
# Full publishing workflow
git checkout main
git pull
poetry run pytest tests/ -v
poetry version 3.0.0
poetry build
poetry publish -r testpypi  # Test first!
poetry publish              # Publish to PyPI
git tag -a v3.0.0 -m "Release v3.0.0"
git push origin v3.0.0
```

---

**Document Version**: 1.0.0
**Last Updated**: 2026-01-07
**Next Review**: When publishing next version

For questions or issues, see [GitHub Issues](https://github.com/beejak/mcp-sentinel/issues).
