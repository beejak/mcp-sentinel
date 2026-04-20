# Pre-Release Checklist for MCP Sentinel

**PURPOSE**: This checklist MUST be completed before declaring any release "ready for publication". Use this as your final gate before creating tags and GitHub releases.

**Last Updated**: 2025-10-27 (after v2.6.0 lessons learned)

---

## ⚠️ CRITICAL: Read This First

**DO NOT** tell the user "the release is ready" until EVERY item below is checked ✅.

**v2.6.0 Lesson**: We had excellent code quality but poor release process. This checklist prevents that.

---

## Phase 1: Code & Testing ✅

### Code Quality
- [ ] All tests passing (`cargo test --all`)
- [ ] No compiler warnings (`cargo build --release 2>&1 | grep warning`)
- [ ] Test coverage ≥ 90% for new features
- [ ] No `unwrap()` calls in production code (only tests/static init)
- [ ] All `TODO` comments resolved or documented in issues
- [ ] No hardcoded secrets or credentials
- [ ] All `panic!()` calls reviewed and justified

### Testing
- [ ] Unit tests written for all new functions
- [ ] Integration tests for end-to-end workflows
- [ ] Manual testing of critical paths completed
- [ ] Edge cases tested (empty inputs, errors, large files)
- [ ] Performance regression testing done
- [ ] Backward compatibility verified (old commands still work)

### Logging & Observability
- [ ] Strategic logging points added (debug, info, warn, error)
- [ ] No excessive logging that impacts performance
- [ ] Error messages are clear and actionable
- [ ] All errors include context (file, line, operation)

---

## Phase 2: Documentation ✅

### Release Notes
- [ ] RELEASE_NOTES_vX.Y.Z.md created with comprehensive details
- [ ] Summary section explains what's new in 2-3 paragraphs
- [ ] All new features documented with examples
- [ ] Performance metrics included (before/after)
- [ ] Breaking changes clearly called out (or confirmed none)
- [ ] Migration guide included
- [ ] Known limitations documented

### README.md Updates
- [ ] Badge version updated to new version
- [ ] "What's New" section updated
- [ ] Feature list updated with new capabilities
- [ ] Installation instructions current
- [ ] Quick start examples work with new version
- [ ] No references to old version (grep for "v{previous}")

### API/CLI Documentation
- [ ] All new CLI flags documented in --help
- [ ] Code examples updated
- [ ] Configuration file examples updated
- [ ] API changes documented (if library)

### Changelog
- [ ] CHANGELOG.md updated with new version entry
- [ ] All changes categorized (Added/Changed/Fixed/Deprecated/Removed/Security)
- [ ] Issue/PR references included where applicable

---

## Phase 3: Version Consistency ✅

### Version Number Updates
- [ ] Cargo.toml version field updated
- [ ] README.md badge updated
- [ ] Release notes filename matches version
- [ ] No references to previous version in user-facing docs
- [ ] Run: `grep -r "v{old_version}" --exclude-dir=target --exclude-dir=.git`
- [ ] Version referenced in code (if any) updated

### Verification Script
```bash
# Run this to check version consistency
NEW_VERSION="X.Y.Z"
OLD_VERSION="X.Y.Z"

echo "Checking for old version references..."
grep -r "$OLD_VERSION" README.md RELEASE_NOTES*.md docs/ 2>/dev/null | grep -v "previous\|history\|compared"

echo "Verifying new version is referenced..."
grep -r "$NEW_VERSION" README.md Cargo.toml 2>/dev/null | head -5
```

---

## Phase 4: Git & Branch Management ✅

### Local Repository
- [ ] All changes committed (no uncommitted files)
- [ ] On correct branch (usually `main`)
- [ ] Local branch is clean: `git status` shows "working tree clean"
- [ ] All commits have meaningful messages
- [ ] No temp/debug commits in history

### Remote Synchronization
- [ ] **CRITICAL**: Local `main` synced with `origin/main`
  - Run: `git fetch origin && git log origin/main..main`
  - Should show NO commits (or you're ahead)
- [ ] If ahead, push BEFORE tagging: `git push origin main`
- [ ] Verify push succeeded: `git log origin/main -1`

### Tag Preparation
- [ ] Tag name follows convention: `vX.Y.Z` (lowercase v)
- [ ] Tag message prepared with release summary
- [ ] Tag will point to HEAD of main branch
- [ ] **DO NOT CREATE TAG YET** - verify everything first

---

## Phase 5: GitHub Preparation ✅

### Repository State
- [ ] GitHub Actions CI passing on main branch
- [ ] No open critical bugs in issue tracker
- [ ] All PRs for this release merged
- [ ] Branch protection rules won't block push

### GitHub Token
- [ ] GitHub personal access token ready
- [ ] Token has required permissions (repo, write:packages)
- [ ] Token tested with simple API call
- [ ] Token saved securely for release process

### Release Draft (Optional but Recommended)
- [ ] Draft release created on GitHub
- [ ] Release notes preview looks good
- [ ] Assets prepared (if any: binaries, docs)

---

## Phase 6: Pre-Release Verification ✅

### Build Verification
```bash
# Clean build from scratch
cargo clean
cargo build --release

# Check binary size
ls -lh target/release/mcp-sentinel

# Verify version in binary
./target/release/mcp-sentinel --version
```

- [ ] Clean build succeeds
- [ ] Binary runs and shows correct version
- [ ] Binary size reasonable (check for bloat)

### Integration Smoke Test
```bash
# Run quick scan on test repository
./target/release/mcp-sentinel scan ./tests/fixtures/vulnerable-server

# Verify output format
./target/release/mcp-sentinel scan ./tests/fixtures/vulnerable-server --output json
```

- [ ] Scanner runs successfully
- [ ] Finds expected vulnerabilities
- [ ] Output formats work (terminal, JSON, SARIF)
- [ ] Performance acceptable

### Documentation Verification
- [ ] README.md renders correctly on GitHub preview
- [ ] All links in docs work (no 404s)
- [ ] Code examples in docs are valid syntax
- [ ] Images/diagrams load correctly

---

## Phase 7: Release Execution ✅

### Step 1: Final Sync
```bash
# Ensure absolutely up to date
git fetch origin
git pull origin main
git status  # Should be "nothing to commit, working tree clean"
```

- [ ] Local and remote in perfect sync
- [ ] No uncommitted changes

### Step 2: Create Tag
```bash
# Create annotated tag
git tag -a vX.Y.Z -m "Release vX.Y.Z - [Feature Summary]

Phase X.Y Complete:
- [Major Feature 1]
- [Major Feature 2]
- [Major Feature 3]

Stats: +X lines, Y% test coverage, Z new tests

🤖 Generated with Compyle"

# Verify tag
git show vX.Y.Z --quiet
```

- [ ] Tag created successfully
- [ ] Tag points to correct commit (HEAD of main)
- [ ] Tag message looks good

### Step 3: Push Everything
```bash
# Push main branch (if not already pushed)
git push origin main

# Push tag
git push origin vX.Y.Z

# Verify on GitHub
# Visit: https://github.com/beejak/MCP_Scanner/tags
```

- [ ] Main branch pushed successfully
- [ ] Tag pushed successfully
- [ ] Tag visible on GitHub
- [ ] Tag shows correct commit

### Step 4: Create GitHub Release
```bash
# Option A: Via API
curl -X POST \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/repos/beejak/MCP_Scanner/releases \
  -d @release_payload.json

# Option B: Via GitHub UI
# Visit: https://github.com/beejak/MCP_Scanner/releases/new
```

- [ ] Release created successfully
- [ ] Release shows correct tag
- [ ] Release notes look good
- [ ] Release set as "Latest" (not draft/prerelease)

### Step 5: Verify Release
```bash
# Check latest release via API
curl -s https://api.github.com/repos/beejak/MCP_Scanner/releases/latest | \
  grep '"tag_name"'
```

- [ ] Correct version returned by `/releases/latest` endpoint
- [ ] Release visible at top of `/releases` page
- [ ] Release badge on README shows new version
- [ ] No "orphaned commit" errors
- [ ] Download links work

---

## Phase 8: Post-Release ✅

### Communication
- [ ] Release announced (if applicable: Discord, Twitter, blog)
- [ ] Changelog updated on website (if applicable)
- [ ] Documentation site updated (if applicable)
- [ ] Community notified of major features

### Monitoring
- [ ] Watch for GitHub issues related to new release
- [ ] Monitor download counts
- [ ] Check for user feedback
- [ ] Be ready to hotfix if critical bugs found

### Cleanup
- [ ] Delete old release artifacts (if any)
- [ ] Archive old release notes (keep accessible)
- [ ] Update roadmap with completed items
- [ ] Plan next release cycle

### Lessons Learned
- [ ] Add any new issues to this checklist
- [ ] Document what worked well
- [ ] Update process based on feedback

---

## 🚨 Common Pitfalls (From v2.6.0)

### ❌ DON'T:
1. Create tags before pushing main branch
2. Assume GitHub will auto-set "Latest" correctly
3. Skip version reference sweep in docs
4. Rush the process - take time to verify each step
5. Use expired/untested GitHub tokens

### ✅ DO:
1. Sync main to origin FIRST
2. Verify tag points to main branch
3. Check GitHub UI to confirm "Latest" status
4. Run grep to find ALL version references
5. Test the release process in order

---

## ✅ Final Confirmation

**Before declaring "Release is Ready":**

I have completed:
- [ ] ALL Phase 1 items (Code & Testing)
- [ ] ALL Phase 2 items (Documentation)
- [ ] ALL Phase 3 items (Version Consistency)
- [ ] ALL Phase 4 items (Git & Branch Management)
- [ ] ALL Phase 5 items (GitHub Preparation)
- [ ] ALL Phase 6 items (Pre-Release Verification)
- [ ] ALL Phase 7 items (Release Execution)

**If ANY checkbox above is unchecked, the release is NOT ready.**

**Signature**: ____________________ Date: __________

---

## Quick Reference: Critical Commands

```bash
# 1. Sync main
git fetch origin && git pull origin main

# 2. Push main if ahead
git push origin main

# 3. Create tag
git tag -a vX.Y.Z -m "Release message"

# 4. Push tag
git push origin vX.Y.Z

# 5. Verify latest
curl -s https://api.github.com/repos/beejak/MCP_Scanner/releases/latest | grep tag_name

# 6. Check for orphaned commit
git branch --contains vX.Y.Z | grep main
# Should show "main" - if not, tag is orphaned!
```

---

**Remember**: A delayed release with excellent quality beats a rushed release with issues. Take your time, follow this checklist, and ship with confidence.
