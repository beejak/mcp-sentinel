# MCP Sentinel — Release Process

**Version**: v0.2.0

---

## Table of Contents

1. [Release Workflow](#release-workflow)
2. [Pre-Release Requirements](#pre-release-requirements)
3. [Creating a Release](#creating-a-release)
4. [Post-Release Verification](#post-release-verification)
5. [Release Checklist Template](#release-checklist-template)
6. [Emergency Hotfix Process](#emergency-hotfix-process)

---

## Release Workflow

```
Feature branch development
         │
         ▼
  Pull Request to master
  └─> CI must pass (all 334 tests, lint, self-scan)
         │
         ▼
  Merge to master
         │
         ▼
  Pre-release verification (this doc)
         │
         ▼
  Bump version in pyproject.toml + __init__.py
         │
         ▼
  Update CHANGELOG.md
         │
         ▼
  Commit + annotated git tag (vX.Y.Z)
         │
         ▼
  GitHub Release (from tag)
         │
         ▼
  PyPI publish (if applicable)
         │
         ▼
  Post-release smoke test
```

---

## Pre-Release Requirements

### Quality gates

All must pass before tagging:

```bash
# 1. Full test suite
pytest tests/ -v

# 2. Type checking
mypy src/mcp_sentinel --ignore-missing-imports

# 3. Linting
ruff check src/

# 4. Security scan of own source
bandit -r src/

# 5. Self-scan with MCP Sentinel
mcp-sentinel scan src/ --output json --json-file self-scan.json --no-progress
```

### Documentation requirements

- [ ] `CHANGELOG.md` has entry for this version
- [ ] `README.md` reflects current feature set and version badge
- [ ] `docs/TEST_COVERAGE.md` matches actual test suite
- [ ] `docs/CONFIGURATION.md` lists only real env vars
- [ ] `docs/CI_CD_INTEGRATION.md` uses correct CLI flags
- [ ] No docs reference removed features (AI engine, SAST, HTML output, Poetry, etc.)

### Version consistency

```bash
# Check pyproject.toml version
grep '^version' pyproject.toml

# Check __init__.py version
grep '__version__' src/mcp_sentinel/__init__.py

# Scan all docs for stale version strings
grep -r "v0\.1\." docs/ README.md
```

Both `pyproject.toml` and `src/mcp_sentinel/__init__.py` must have the same version.

---

## Creating a Release

### Step 1: Final verification

```bash
git status              # working tree must be clean
git log --oneline -5    # confirm latest commits look right

pytest tests/ -v        # all tests pass
ruff check src/         # linting clean
```

### Step 2: Bump version

Edit both files to the new version (e.g., `0.3.0`):

```bash
# pyproject.toml
sed -i 's/version = "0\.2\.0"/version = "0.3.0"/' pyproject.toml

# src/mcp_sentinel/__init__.py
sed -i 's/__version__ = ".*"/__version__ = "0.3.0"/' src/mcp_sentinel/__init__.py

# Verify
grep '^version' pyproject.toml
grep '__version__' src/mcp_sentinel/__init__.py
```

### Step 3: Update CHANGELOG.md

Add a new section at the top:

```markdown
## v0.3.0 — YYYY-MM-DD

### New
- ...

### Fixed
- ...

### Changed
- ...
```

### Step 4: Commit and tag

```bash
git add pyproject.toml src/mcp_sentinel/__init__.py CHANGELOG.md
git commit -m "Release v0.3.0"

git tag -a v0.3.0 -m "v0.3.0 — [one-line summary of changes]"
git push origin master
git push origin v0.3.0
```

### Step 5: GitHub Release

1. Go to repository → Releases → Draft a new release
2. Select the tag `v0.3.0`
3. Title: `v0.3.0 — [summary]`
4. Body: paste relevant CHANGELOG section
5. Attach wheel/tarball if publishing

### Step 6: PyPI (if applicable)

```bash
pip install build twine

python -m build          # creates dist/mcp_sentinel-0.3.0-py3-none-any.whl
twine check dist/*
twine upload dist/*      # requires PyPI credentials
```

Post-publish smoke test:

```bash
pip install mcp-sentinel==0.3.0
mcp-sentinel --version   # should print v0.3.0
mcp-sentinel scan .
```

---

## Post-Release Verification

```bash
# Install from PyPI (or local wheel) in a clean virtualenv
python -m venv /tmp/test-env
source /tmp/test-env/bin/activate
pip install mcp-sentinel==0.3.0

# Verify version
mcp-sentinel --version

# Smoke test scan
mcp-sentinel scan /path/to/sample-mcp-server

# JSON output
mcp-sentinel scan /path/to/sample-mcp-server --output json --json-file /tmp/test.json
python3 -c "import json; d=json.load(open('/tmp/test.json')); print(len(d['vulnerabilities']), 'findings')"

# SARIF output
mcp-sentinel scan /path/to/sample-mcp-server --output sarif --json-file /tmp/test.sarif
python3 -c "import json; d=json.load(open('/tmp/test.sarif')); print('SARIF version:', d.get('version', '?'))"
```

---

## Release Checklist Template

Copy this for each release:

```
### Pre-release

Code quality:
[ ] pytest tests/ — 0 failures
[ ] mypy src/mcp_sentinel — clean
[ ] ruff check src/ — clean
[ ] bandit -r src/ — clean
[ ] mcp-sentinel scan src/ — no regressions

Version:
[ ] pyproject.toml version bumped
[ ] src/mcp_sentinel/__init__.py version bumped
[ ] versions match

Documentation:
[ ] CHANGELOG.md updated
[ ] README.md badges/version current
[ ] docs/TEST_COVERAGE.md matches test suite

### Release execution

[ ] Commit: "Release vX.Y.Z"
[ ] Annotated tag: vX.Y.Z
[ ] Push tag to remote
[ ] GitHub Release created
[ ] PyPI publish (if applicable)

### Post-release

[ ] pip install mcp-sentinel==X.Y.Z works
[ ] mcp-sentinel --version shows correct version
[ ] Basic scan completes successfully
[ ] No critical issues reported within 24h
```

---

## Emergency Hotfix Process

For critical bugs found after release:

**1. Assess** (within 1 hour)
- Does it affect all users or a specific configuration?
- Is there a workaround?

**2. Create hotfix branch**

```bash
git checkout -b hotfix/v0.2.1 v0.2.0
```

**3. Fix, test, scan**

```bash
# Minimal fix — no new features
pytest tests/ -v           # must pass
mcp-sentinel scan src/     # no new self-scan regressions
```

**4. Bump patch version, tag, release**

```bash
# Bump: 0.2.0 → 0.2.1
git commit -m "Hotfix v0.2.1 — [one-line description]"
git tag -a v0.2.1 -m "v0.2.1 — [description]"
git push origin hotfix/v0.2.1
git push origin v0.2.1
# Merge hotfix back to master
```

**5. Post-hotfix**
- Document root cause in CHANGELOG
- Add regression test to prevent recurrence
- Review if detection in CI could have caught this earlier
