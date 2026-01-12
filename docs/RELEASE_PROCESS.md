# Release Process Documentation

**Version**: 1.0.0
**Last Updated**: 2026-01-06
**Repository**: mcp-sentinel-python

This document defines the standard release process for MCP Sentinel Python Edition, ensuring consistent, high-quality releases with comprehensive documentation and performance tracking.

---

## Table of Contents

1. [Release Workflow Overview](#release-workflow-overview)
2. [Pre-Release Requirements](#pre-release-requirements)
3. [Performance Delta Documentation](#performance-delta-documentation)
4. [Code Quality & Sanitization](#code-quality--sanitization)
5. [Creating a Release](#creating-a-release)
6. [Post-Release Verification](#post-release-verification)
7. [Release Checklist Template](#release-checklist-template)

---

## Release Workflow Overview

### Standard Release Lifecycle

```
┌──────────────────────────────────────────────────────────────┐
│                  RELEASE WORKFLOW                             │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  1. Development Phase                                         │
│     └─> Feature implementation on feature branch             │
│                                                               │
│  2. Pre-Release Quality Assurance                             │
│     ├─> Run QA checklist (docs/QA_CHECKLIST.md)              │
│     ├─> Code sanitization & cleanup                          │
│     ├─> Performance benchmarking                             │
│     └─> Documentation updates                                │
│                                                               │
│  3. Performance Delta Documentation                           │
│     ├─> Compare with previous release                        │
│     ├─> Document improvements/regressions                    │
│     └─> Update CHANGELOG.md with metrics                     │
│                                                               │
│  4. Create Pull Request                                       │
│     ├─> Comprehensive PR description                         │
│     ├─> Include performance comparison                       │
│     └─> Link to related issues                               │
│                                                               │
│  5. Merge to Main                                             │
│     └─> After approval and CI passing                        │
│                                                               │
│  6. Create Git Tag                                            │
│     ├─> Follow semantic versioning                           │
│     ├─> Include release notes in tag message               │
│     └─> Push to remote repository                            │
│                                                               │
│  7. GitHub Release                                            │
│     ├─> Create release from tag                              │
│     ├─> Upload release assets (wheels, tarballs)           │
│     ├─> Write comprehensive release notes                   │
│     └─> Publish to PyPI if applicable                      │
│                                                               │
│  8. Post-Release Verification                               │
│     ├─> Verify installation works                          │
│     ├─> Check documentation is accessible                    │
│     └─> Monitor for issues                                  │
└──────────────────────────────────────────────────────────────┘
```

---

## Pre-Release Requirements

### Code Quality Gates

**Must Pass Before Release:**
1. **All tests pass** (`poetry run pytest`)
2. **Type checking passes** (`poetry run mypy src/`)
3. **Linting passes** (`poetry run ruff check src/`)
4. **Formatting passes** (`poetry run black --check src/`)
5. **Security scan passes** (`poetry run bandit -r src/`)
6. **Documentation builds** (`mkdocs build` if applicable)

### Documentation Requirements

**Required Documentation:**
- [ ] CHANGELOG.md updated with version entry
- [ ] README.md current (no outdated references)
- [ ] API documentation updated (if changed)
- [ ] Configuration examples current
- [ ] Migration guide (if breaking changes)

### Version Consistency Check

```bash
# Check version in pyproject.toml
grep '^version =' pyproject.toml

# Check for old version references
grep -r "0\.[0-9]\.[0-9]" README.md docs/ --exclude-dir=__pycache__

# Verify no hardcoded version in code
grep -r "__version__" src/ | head -5
```

---

## Performance Delta Documentation

### Benchmarking Requirements

**Performance Metrics to Track:**
1. **Scan Speed**: Time to scan 1000 files
2. **Memory Usage**: Peak memory during scan
3. **Binary Size**: Package/installation size
4. **API Latency**: Response time for API endpoints
5. **Test Execution Time**: Full test suite duration

### Performance Comparison Template

```markdown
## Performance Comparison: v{OLD} → v{NEW}

| Metric | v{OLD} | v{NEW} | Delta | % Change |
|--------|--------|--------|--------|----------|
| Scan Speed (1000 files) | 4.2s | 3.8s | -0.4s | -9.5% |
| Memory Usage (peak) | 85MB | 92MB | +7MB | +8.2% |
| Package Size | 2.1MB | 2.3MB | +0.2MB | +9.5% |
| Test Suite Time | 45s | 42s | -3s | -6.7% |

**Summary**: Performance improved in scan speed and test execution, with minor increases in memory and package size.
```

---

## Code Quality & Sanitization

### Pre-Release Cleanup Checklist

**Code Sanitization:**
- [ ] Remove debug print statements
- [ ] Remove TODO comments (or convert to issues)
- [ ] Remove commented-out code
- [ ] Update docstrings for accuracy
- [ ] Check for hardcoded secrets/credentials
- [ ] Verify error messages are user-friendly
- [ ] Check logging levels (no excessive debug logging)

**Security Review:**
- [ ] Run security scanner (bandit)
- [ ] Check for potential injection vulnerabilities
- [ ] Verify input validation
- [ ] Check file path handling
- [ ] Review dependency vulnerabilities (`poetry audit`)

### Code Quality Metrics

**Target Metrics:**
- Test coverage: ≥90% for critical modules
- Type coverage: 100% for public APIs
- Cyclomatic complexity: ≤10 for functions
- No functions >50 lines (preferably)
- Docstring coverage: 100% for public APIs

---

## Creating a Release

### Step 1: Final Verification

```bash
# 1. Ensure working directory is clean
git status

# 2. Run full test suite
poetry run pytest

# 3. Run quality checks
poetry run ruff check src/
poetry run black --check src/
poetry run mypy src/

# 4. Security scan
poetry run bandit -r src/

# 5. Build package
poetry build
```

### Step 2: Version Bump

```bash
# Update version in pyproject.toml
# Use semantic versioning (MAJOR.MINOR.PATCH)

# Example: Bump minor version
sed -i 's/version = "0.1.0"/version = "0.2.0"/' pyproject.toml

# Verify change
grep '^version =' pyproject.toml
```

### Step 3: Update Documentation

```bash
# Update CHANGELOG.md
# Add new version section with changes

# Update any version references in README
# Update API documentation if needed
```

### Step 4: Commit and Tag

```bash
# Commit version changes
git add pyproject.toml CHANGELOG.md README.md
git commit -m "Release v0.2.0 - [Brief description of changes]"

# Create annotated tag
git tag -a v0.2.0 -m "Release v0.2.0 - [Detailed release notes]"

# Push to remote
git push origin main
git push origin v0.2.0
```

---

## Post-Release Verification

### Installation Testing

```bash
# Test installation from PyPI (if published)
pip install mcp-sentinel==0.2.0

# Test basic functionality
mcp-sentinel --version
mcp-sentinel scan /path/to/test/project

# Test with different output formats
mcp-sentinel scan /path/to/project --output json
```

### Documentation Verification

- [ ] README.md renders correctly on GitHub
- [ ] All links work (no 404s)
- [ ] Code examples are valid
- [ ] Installation instructions work
- [ ] API documentation is accessible

### Issue Monitoring

**Post-Release Monitoring:**
- Monitor GitHub issues for bug reports
- Check download statistics (if available)
- Monitor CI/CD pipeline health
- Watch for security vulnerability reports

---

## Release Checklist Template

### Pre-Release Checklist

**Code Quality:**
- [ ] All tests pass (`poetry run pytest`)
- [ ] Type checking passes (`poetry run mypy src/`)
- [ ] Linting passes (`poetry run ruff check src/`)
- [ ] Formatting passes (`poetry run black --check src/`)
- [ ] Security scan passes (`poetry run bandit -r src/`)

**Documentation:**
- [ ] CHANGELOG.md updated
- [ ] README.md current
- [ ] Version references updated
- [ ] API documentation current

**Version Management:**
- [ ] Version bumped in pyproject.toml
- [ ] No hardcoded version strings in code
- [ ] Git history clean (no WIP commits)

### Release Execution

**Tag Creation:**
- [ ] Create annotated tag
- [ ] Tag message includes release summary
- [ ] Push tag to remote

**GitHub Release:**
- [ ] Create release from tag
- [ ] Upload release assets (if applicable)
- [ ] Write comprehensive release notes
- [ ] Set as "Latest Release"

### Post-Release

**Verification:**
- [ ] Installation works
- [ ] Basic functionality works
- [ ] Documentation accessible
- [ ] No critical issues reported

---

## Common Issues & Solutions

### Issue: Tests Pass Locally but Fail in CI
**Solution**: Ensure consistent environment (Python version, dependencies)
```bash
# Lock dependencies
poetry lock --no-update

# Test in clean environment
poetry install --no-dev
```

### Issue: Version Conflicts
**Solution**: Use semantic versioning consistently
```bash
# Check current version
grep '^version =' pyproject.toml

# Update all references
find . -name "*.md" -exec grep -l "old_version" {} \;
```

### Issue: Documentation Out of Sync
**Solution**: Automate documentation updates
```bash
# Generate API docs (if using tools)
poetry run pdoc src/mcp_sentinel --output-dir docs/api

# Check for broken links
poetry run pytest-check-links docs/
```

---

## Emergency Hotfix Process

**When Critical Bug Found in Release:**

1. **Assess Severity** (within 1 hour)
   - Determine impact and affected users
   - Check if workaround exists

2. **Create Hotfix Branch**
   ```bash
   git checkout -b hotfix/v0.2.1
   ```

3. **Fix and Test** (within 4 hours)
   - Minimal fix, no new features
   - Full test suite must pass
   - Security scan must pass

4. **Accelerated Release** (within 8 hours)
   - Skip non-critical documentation updates
   - Focus on fix verification
   - Communicate clearly in release notes

5. **Post-Hotfix Review**
   - Document root cause
   - Update tests to prevent recurrence
   - Review release process if needed

---

**Remember**: A delayed release with excellent quality beats a rushed release with issues. Take time to verify each step, but don't let perfect be the enemy of good.