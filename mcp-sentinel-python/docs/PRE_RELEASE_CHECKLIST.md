# Pre-Release Checklist

**Version**: 1.0.0
**Date**: 2026-01-06
**Repository**: mcp-sentinel-python
**Status**: Production Ready Checklist

---

## 🚨 CRITICAL CHECKS (Must Pass)

### Code Quality - CRITICAL
- [ ] **ALL TESTS PASS** - No exceptions, no skipped tests without justification
  ```bash
  poetry run pytest
  ```
- [ ] **TYPE CHECKING PASSES** - Zero mypy errors
  ```bash
  poetry run mypy src/
  ```
- [ ] **LINTING PASSES** - Zero ruff errors
  ```bash
  poetry run ruff check src/
  ```
- [ ] **FORMATTING PASSES** - Black formatting check passes
  ```bash
  poetry run black --check src/
  ```
- [ ] **SECURITY SCAN PASSES** - Zero bandit high-severity issues
  ```bash
  poetry run bandit -r src/
  ```

### Functionality - CRITICAL
- [ ] **BASIC SCAN WORKS** - Can scan a directory without crashing
  ```bash
  poetry run mcp-sentinel scan src/
  ```
- [ ] **HELP COMMAND WORKS** - All help text displays correctly
  ```bash
  poetry run mcp-sentinel --help
  poetry run mcp-sentinel scan --help
  ```
- [ ] **VERSION COMMAND WORKS** - Version displays correctly
  ```bash
  poetry run mcp-sentinel version
  ```
- [ ] **CONFIG VALIDATION** - Invalid configurations are rejected
  ```bash
  poetry run mcp-sentinel validate --config invalid.toml
  ```

### Security - CRITICAL
- [ ] **NO HARDCODED SECRETS** - Search for API keys, passwords, tokens
  ```bash
  grep -r "sk-" src/ || true
  grep -r "password" src/ || true
  grep -r "api_key" src/ || true
  ```
- [ ] **PATH TRAVERSAL PROTECTION** - Cannot access files outside target directory
- [ ] **INPUT VALIDATION** - All user inputs are validated
- [ ] **SAFE ERROR MESSAGES** - No sensitive information in error messages

---

## 📋 DETAILED CHECKLIST

### 1. Code Quality Verification

#### Testing
- [ ] Unit tests pass (80%+ coverage on critical modules)
- [ ] Integration tests pass
- [ ] E2E tests pass
- [ ] No test is marked as `@pytest.mark.skip` without justification
- [ ] All tests have proper assertions (no empty tests)
- [ ] Test execution time < 5 minutes total

#### Code Standards
- [ ] All functions have docstrings (public APIs)
- [ ] Type hints on all public functions
- [ ] No functions > 50 lines (preferably)
- [ ] Cyclomatic complexity ≤ 10 for functions
- [ ] No commented-out code
- [ ] No debug print statements
- [ ] Consistent naming conventions

#### Static Analysis
- [ ] mypy passes with strict settings
- [ ] ruff passes with all rules enabled
- [ ] black formatting is applied
- [ ] bandit security scan passes
- [ ] No pylint warnings (if used)

### 2. Functionality Testing

#### CLI Functionality
- [ ] `mcp-sentinel scan <directory>` works
- [ ] `mcp-sentinel scan --output json <directory>` works
- [ ] `mcp-sentinel scan --include "*.py" <directory>` works
- [ ] `mcp-sentinel scan --exclude "test_*" <directory>` works
- [ ] `mcp-sentinel config show` works
- [ ] `mcp-sentinel validate` works
- [ ] `mcp-sentinel version` shows correct version

#### Configuration
- [ ] Default configuration loads
- [ ] Custom TOML configuration files work
- [ ] Environment variables override config files
- [ ] Invalid configurations show helpful errors
- [ ] Configuration validation catches all errors

#### Output Formats
- [ ] JSON output is valid JSON
- [ ] Console output is readable
- [ ] Progress indication works for long operations
- [ ] Error messages are user-friendly
- [ ] Output file creation works

### 3. Performance Testing

#### Speed Benchmarks
- [ ] Small project (10 files) scans in < 2 seconds
- [ ] Medium project (100 files) scans in < 10 seconds
- [ ] Large project (1000 files) scans in < 60 seconds
- [ ] No individual file scan takes > 1 second

#### Memory Usage
- [ ] Memory usage < 100MB for typical projects
- [ ] No memory leaks during long-running scans
- [ ] Memory usage scales linearly with file count
- [ ] Garbage collection works properly

#### Resource Usage
- [ ] CPU usage reasonable (< 80% on multi-core)
- [ ] Disk I/O is efficient
- [ ] Network usage (if any) is minimal
- [ ] Concurrent file operations work correctly

### 4. Security Verification

#### Input Validation
- [ ] Path traversal attacks are prevented
- [ ] Command injection is impossible
- [ ] File size limits are enforced
- [ ] Malicious file content is handled safely
- [ ] Invalid UTF-8 content is handled

#### Access Control
- [ ] Cannot access files outside specified directory
- [ ] Symbolic links are handled safely
- [ ] Hidden files are handled according to policy
- [ ] Permission errors are handled gracefully

#### Secret Safety
- [ ] No secrets in logs or error messages
- [ ] Configuration files don't contain secrets
- [ ] Test data doesn't contain real secrets
- [ ] Documentation doesn't expose internal details

### 5. Documentation Verification

#### Code Documentation
- [ ] All public APIs have docstrings
- [ ] Complex algorithms are documented
- [ ] Configuration options are documented
- [ ] Error conditions are documented

#### User Documentation
- [ ] README.md is current and accurate
- [ ] Installation instructions work
- [ ] Usage examples are correct
- [ ] Configuration guide is complete
- [ ] Troubleshooting section exists

#### Developer Documentation
- [ ] Architecture documentation is current
- [ ] Contributing guidelines are clear
- [ ] Development setup instructions work
- [ ] Testing documentation is complete

### 6. Release Preparation

#### Version Management
- [ ] Version is updated in pyproject.toml
- [ ] Version is updated in __init__.py
- [ ] CHANGELOG.md is updated
- [ ] No hardcoded version strings in code
- [ ] Git tag is ready to be created

#### Package Building
- [ ] `poetry build` succeeds
- [ ] Package can be installed from wheel
- [ ] Package size is reasonable (< 10MB)
- [ ] All dependencies are properly declared
- [ ] License file is included

#### Distribution
- [ ] PyPI upload credentials are ready
- [ ] Release notes are written
- [ ] GitHub release draft is prepared
- [ ] Documentation is ready for publication

---

## 🔧 MANUAL TESTING SCENARIOS

### Scenario 1: Fresh Installation
```bash
# Create clean environment
python -m venv test_env
source test_env/bin/activate  # or test_env\Scripts\activate on Windows

# Install from PyPI (if publishing)
pip install mcp-sentinel

# Test basic functionality
mcp-sentinel --version
mcp-sentinel scan /path/to/test/project
```

### Scenario 2: Configuration Testing
```bash
# Test with custom config
cat > test_config.toml << EOF
max_concurrent_files = 5
output_format = "json"
include_patterns = ["*.py"]
exclude_patterns = ["test_*"]
EOF

mcp-sentinel scan --config test_config.toml /path/to/project
```

### Scenario 3: Error Handling
```bash
# Test with invalid directory
mcp-sentinel scan /nonexistent/path

# Test with permission issues
mkdir test_dir && chmod 000 test_dir
mcp-sentinel scan test_dir
chmod 755 test_dir && rm -rf test_dir

# Test with invalid config
echo "invalid toml content" > bad_config.toml
mcp-sentinel scan --config bad_config.toml /path/to/project
```

### Scenario 4: Performance Testing
```bash
# Create large test project
mkdir large_project
cd large_project
for i in {1..100}; do echo "x = $i" > "file_$i.py"; done
cd ..

# Time the scan
time mcp-sentinel scan large_project

# Clean up
rm -rf large_project
```

---

## 🎯 SUCCESS CRITERIA

### Release is Ready When:
1. **All critical checks pass** (red section above)
2. **90%+ of detailed checklist items are checked**
3. **No known security vulnerabilities**
4. **Performance meets targets**
5. **Documentation is complete and accurate**
6. **Package builds and installs successfully**

### Release Should Be Delayed When:
1. **Any critical check fails**
2. **Performance is significantly degraded**
3. **Security vulnerabilities are found**
4. **Basic functionality is broken**
5. **Documentation is incomplete or inaccurate**

---

## 📞 EMERGENCY CONTACTS

**If Critical Issues Found:**
1. **Security Issues**: Report immediately, do not release
2. **Performance Issues**: Evaluate impact vs. timeline
3. **Functionality Issues**: Must be fixed before release
4. **Documentation Issues**: Can be fixed post-release if minor

**Escalation Path:**
1. Fix issues in development branch
2. Re-run full checklist
3. Get approval from team lead
4. Proceed with release process

---

**Final Verification:**
```bash
# Run this complete test suite before release
poetry run pytest tests/unit/ tests/integration/ tests/e2e/
poetry run mypy src/
poetry run ruff check src/
poetry run black --check src/
poetry run bandit -r src/
poetry build
```

**Remember**: This checklist is your safety net. A thorough review now prevents issues later.