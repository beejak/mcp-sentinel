# Contributing Guidelines

**Version**: 2.0.0
**Date**: 2026-01-07
**Repository**: mcp-sentinel-python
**Status**: Phase 3 Complete - 100% Detector Parity ✅

Welcome to MCP Sentinel Python Edition! This document provides comprehensive guidelines for contributing to the project.

**Current Project Status:**
- ✅ **8/8 Detectors Implemented** (100% parity with Rust version)
- ✅ **274 Comprehensive Tests** with ~95% average coverage
- ✅ **98 Vulnerability Patterns** across all detectors
- ✅ **Enterprise-grade Documentation** and code quality

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Workflow](#development-workflow)
4. [Testing Requirements](#testing-requirements)
5. [Code Style & Standards](#code-style--standards)
6. [Pull Request Process](#pull-request-process)
7. [Release Process](#release-process)
8. [Issue Reporting](#issue-reporting)
9. [Security Issues](#security-issues)
10. [Community Guidelines](#community-guidelines)

---

## Code of Conduct

### Our Standards

- **Be respectful and inclusive**
- **Welcome newcomers and help them get started**
- **Focus on constructive feedback**
- **Respect different viewpoints and experiences**
- **Show empathy towards other community members**

### Unacceptable Behavior

- Harassment, discrimination, or hate speech
- Personal attacks or trolling
- Publishing others' private information
- Any conduct that could reasonably be considered inappropriate

---

## Getting Started

### Prerequisites

- **Python 3.11+** (we use modern Python features)
- **Poetry 1.7+** for dependency management
- **Git** for version control
- **Pre-commit** for code quality hooks

### Development Environment Setup

```bash
# 1. Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/mcp-sentinel-python.git
cd mcp-sentinel-python

# 2. Install Poetry if not already installed
curl -sSL https://install.python-poetry.org | python3 -

# 3. Install dependencies
poetry install --with dev

# 4. Install pre-commit hooks
poetry run pre-commit install

# 5. Verify installation
poetry run mcp-sentinel --version
```

### Verify Your Setup

```bash
# Run the test suite
poetry run pytest

# Run type checking
poetry run mypy src/

# Run linting
poetry run ruff check src/

# Run formatting check
poetry run black --check src/
```

---

## Development Workflow

### Branch Strategy

We use a **trunk-based development** approach:

- `main` - Production-ready code
- `feature/*` - New features
- `bugfix/*` - Bug fixes
- `hotfix/*` - Critical production fixes

### Creating a Branch

```bash
# Create and switch to feature branch
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b bugfix/issue-description
```

### Making Changes

1. **Write tests first** (TDD approach)
2. **Implement your changes**
3. **Run tests frequently**
4. **Commit with clear messages**

### Commit Message Guidelines

**Format**: `type(scope): description`

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or modifying tests
- `chore`: Maintenance tasks

**Examples**:
```
feat(detector): add JWT token detection pattern
fix(scanner): handle permission errors gracefully
docs(readme): update installation instructions
test(secrets): add test for AWS session tokens
```

---

## Testing Requirements

### Test-Driven Development (TDD)

1. **Write a failing test** for your feature/bug
2. **Implement the minimum code** to make the test pass
3. **Refactor** to improve code quality
4. **Repeat** until feature is complete

### Test Coverage Requirements

**Minimum Coverage Targets**:
- **Critical modules**: 95% coverage
- **Core business logic**: 90% coverage
- **Utilities**: 80% coverage
- **CLI**: Manual + integration tests

### Running Tests

```bash
# Run all tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=mcp_sentinel --cov-report=html

# Run specific test file
poetry run pytest tests/unit/test_secrets_detector.py

# Run tests in watch mode (during development)
poetry run pytest-watch

# Run only unit tests (fast feedback)
poetry run pytest tests/unit/

# Run integration tests
poetry run pytest tests/integration/

# Run E2E tests
poetry run pytest tests/e2e/
```

### Writing Good Tests

**Characteristics of Good Tests**:
- **Fast**: Unit tests should run in < 1 second
- **Isolated**: No dependencies on external systems
- **Repeatable**: Same results every time
- **Self-verifying**: Clear pass/fail criteria
- **Timely**: Written before or with the code

**Example Test Structure**:
```python
def test_secret_detection_with_high_confidence():
    """Test that high-confidence secrets are detected correctly."""
    # Arrange
    detector = SecretsDetector()
    content = 'API_KEY = "sk-1234567890abcdef"'
    
    # Act
    results = detector.detect(Path("test.py"), content)
    
    # Assert
    assert len(results) == 1
    assert results[0].type == "openai_api_key"
    assert results[0].confidence > 0.8
```

---

## Code Style & Standards

### Type Hints

**Required**: All public functions must have type hints

```python
from typing import List, Optional, Union
from pathlib import Path

async def scan_directory(
    path: Path,
    config: Config,
    include_patterns: Optional[List[str]] = None
) -> ScanResults:
    """Scan directory for vulnerabilities with given configuration."""
    pass
```

### Docstrings

**Required**: All public functions and classes must have docstrings

**Format**: Google style

```python
def detect_secrets(content: str, file_path: Path) -> List[Secret]:
    """Detect secrets in file content.
    
    Args:
        content: The file content to scan.
        file_path: Path to the file being scanned.
        
    Returns:
        List of detected secrets with confidence scores.
        
    Raises:
        DetectionError: If scanning fails due to invalid content.
    """
    pass
```

### Code Formatting

We use **Black** for code formatting:

```bash
# Format code
poetry run black src/ tests/

# Check formatting (CI requirement)
poetry run black --check src/ tests/
```

**Black Configuration** (in pyproject.toml):
```toml
[tool.black]
line-length = 88
target-version = ['py311']
include = '\.pyi?$'
extend-exclude = '''
/(
  # directories
  \.eggs
  | \.git
  | \.hg
  | \.mypy_cache
  | \.tox
  | \.venv
  | build
  | dist
)/
'''
```

### Linting

We use **Ruff** for linting:

```bash
# Run linting
poetry run ruff check src/ tests/

# Fix auto-fixable issues
poetry run ruff --fix src/ tests/
```

### Type Checking

We use **mypy** for static type checking:

```bash
# Run type checking
poetry run mypy src/

# With strict settings (CI requirement)
poetry run mypy --strict src/
```

---

## Pull Request Process

### Before Submitting

1. **Sync with main branch**:
   ```bash
   git checkout main
   git pull origin main
   git checkout your-feature-branch
   git rebase main
   ```

2. **Run all quality checks**:
   ```bash
   # Run tests
   poetry run pytest
   
   # Run type checking
   poetry run mypy src/
   
   # Run linting
   poetry run ruff check src/ tests/
   
   # Run formatting
   poetry run black src/ tests/
   
   # Run security scan
   poetry run bandit -r src/
   ```

3. **Update documentation** if needed

### Creating the Pull Request

1. **Push your branch**:
   ```bash
   git push origin your-feature-branch
   ```

2. **Create PR on GitHub** with:
   - **Clear title** describing the change
   - **Detailed description** of what and why
   - **Screenshots** if UI changes
   - **Test coverage** information
   - **Breaking changes** clearly marked

### PR Template

```markdown
## Description
Brief description of the changes made.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed
- [ ] New tests added for new functionality

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] No breaking changes (or clearly documented)

## Screenshots (if applicable)
Add screenshots here.

## Related Issues
Closes #123
```

### Review Process

1. **Automated checks** must pass (CI/CD)
2. **Code review** by at least one maintainer
3. **Testing** verification
4. **Documentation** review
5. **Approval** and merge

---

## Release Process

### Version Numbering

We follow **Semantic Versioning** (SemVer):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

**Pre-Release**:
- [ ] All tests pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped in pyproject.toml
- [ ] Security scan passes
- [ ] Performance benchmarks met

**Release**:
- [ ] Create git tag
- [ ] Build package (`poetry build`)
- [ ] Create GitHub release
- [ ] Publish to PyPI (if applicable)

**Post-Release**:
- [ ] Verify installation works
- [ ] Monitor for issues
- [ ] Update documentation links

---

## Issue Reporting

### Bug Reports

**Include**:
- **Environment**: OS, Python version, package versions
- **Steps to reproduce**
- **Expected behavior**
- **Actual behavior**
- **Error messages/logs**
- **Screenshots** if applicable

**Template**:
```markdown
**Environment**
- OS: [e.g., Ubuntu 22.04]
- Python: [e.g., 3.11.2]
- mcp-sentinel: [e.g., 0.1.0]

**Steps to Reproduce**
1. 
2. 
3. 

**Expected Behavior**

**Actual Behavior**

**Error Messages**
```

### Feature Requests

**Include**:
- **Use case** description
- **Proposed solution**
- **Alternatives considered**
- **Additional context**

---

## Security Issues

### Reporting Security Vulnerabilities

**DO NOT** create public issues for security problems.

**Instead**:
1. Email security concerns to: [security email]
2. Use "Security Issue" in subject line
3. Provide detailed description
4. Include reproduction steps if possible
5. Allow time for investigation before disclosure

### Security Best Practices for Contributors

- **Never commit secrets** (API keys, passwords, tokens)
- **Use environment variables** for sensitive data
- **Validate all inputs** thoroughly
- **Follow secure coding practices**
- **Run security scans** before submitting PRs

---

## Community Guidelines

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Pull Requests**: Code contributions and reviews

### Getting Help

1. **Check documentation** first
2. **Search existing issues**
3. **Ask in discussions** for general questions
4. **Create detailed issues** for bugs

### Recognition

Contributors are recognized in:
- **CHANGELOG.md** for significant contributions
- **Contributors** section in README
- **Release notes** for major contributions

---

## Common Development Tasks

### Adding a New Detector

**Quality Standards** (based on Phase 2 & 3 implementations):
- **Minimum 90% test coverage** (target: 95%+)
- **Comprehensive test suite** (50+ tests recommended)
- **Real-world attack samples** as test fixtures
- **Full metadata**: CWE, CVSS, MITRE ATT&CK IDs
- **Detailed remediation guidance** (8+ steps)
- **False positive prevention** logic
- **Multi-language support** where applicable

**Implementation Steps**:

```python
# 1. Create detector in src/mcp_sentinel/detectors/
class NewVulnerabilityDetector(BaseDetector):
    """
    Detector for [vulnerability type].

    Detects N critical patterns:
    1. Pattern category 1
    2. Pattern category 2
    ...
    """

    def __init__(self):
        super().__init__(name="NewVulnerabilityDetector", enabled=True)
        self.patterns: Dict[str, List[Pattern]] = self._compile_patterns()

    def _compile_patterns(self) -> Dict[str, List[Pattern]]:
        """Compile regex patterns for detection."""
        return {
            "category1": [
                re.compile(r"pattern1", re.IGNORECASE),
                re.compile(r"pattern2", re.IGNORECASE),
            ],
            "category2": [
                re.compile(r"pattern3", re.IGNORECASE),
            ],
        }

    def is_applicable(self, file_path: Path, file_type: Optional[str] = None) -> bool:
        """Check if detector applies to file type."""
        # Define applicable file types
        return file_type in ["python", "javascript", ...]

    async def detect(self, file_path: Path, content: str, file_type: Optional[str] = None) -> List[Vulnerability]:
        """Detect vulnerabilities in content."""
        vulnerabilities: List[Vulnerability] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            if self._is_comment(line, file_type):
                continue

            for category, patterns in self.patterns.items():
                for pattern in patterns:
                    matches = pattern.finditer(line)
                    for match in matches:
                        if not self._is_likely_false_positive(line, match.group(0), category):
                            vuln = self._create_vulnerability(
                                category=category,
                                matched_text=match.group(0),
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=line.strip(),
                            )
                            vulnerabilities.append(vuln)

        return vulnerabilities

    def _is_likely_false_positive(self, line: str, matched_text: str, category: str) -> bool:
        """Implement false positive detection logic."""
        # Check for sanitization, test files, etc.
        return False

    def _create_vulnerability(self, ...) -> Vulnerability:
        """Create vulnerability with full metadata."""
        return Vulnerability(
            type=VulnerabilityType.NEW_TYPE,
            title="...",
            description="...",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe_id="CWE-XXX",
            cvss_score=7.5,
            remediation="...",
            references=[...],
            detector=self.name,
            engine="static",
            mitre_attack_ids=[...],
        )

# 2. Add comprehensive tests in tests/unit/
# See test_xss.py, test_config_security.py, test_path_traversal.py for examples

# 3. Update detectors/__init__.py to export new detector
# 4. Register in scanner.py
# 5. Update ARCHITECTURE.md
# 6. Add to CHANGELOG.md
```

**Reference Implementations**:
- [`XSSDetector`](../src/mcp_sentinel/detectors/xss.py) - 6 pattern categories, 18 patterns, 100% coverage
- [`ConfigSecurityDetector`](../src/mcp_sentinel/detectors/config_security.py) - 8 categories, 35 patterns, 96.49% coverage
- [`PathTraversalDetector`](../src/mcp_sentinel/detectors/path_traversal.py) - 5 categories, 22 patterns, 96.67% coverage

### Adding a New CLI Command

```python
# 1. Add command in src/mcp_sentinel/cli/commands.py
@app.command()
def new_command():
    """New command implementation."""
    pass

# 2. Add tests in tests/integration/test_cli.py
def test_new_command():
    """Test new command."""
    pass

# 3. Update documentation
# 4. Add examples to README
```

### Updating Dependencies

```bash
# Update specific dependency
poetry update package-name

# Update all dependencies
poetry update

# Check for security vulnerabilities
poetry audit

# Update lock file
poetry lock
```

---

## Resources

### Documentation
- [Architecture Documentation](docs/ARCHITECTURE.md)
- [Testing Strategy](docs/QA_CHECKLIST.md)
- [Release Process](docs/RELEASE_PROCESS.md)

### Tools
- [Poetry Documentation](https://python-poetry.org/docs/)
- [pytest Documentation](https://docs.pytest.org/)
- [mypy Documentation](https://mypy.readthedocs.io/)
- [Black Documentation](https://black.readthedocs.io/)
- [Ruff Documentation](https://beta.ruff.rs/docs/)

### Python Resources
- [Python 3.11 Features](https://docs.python.org/3/whatsnew/3.11.html)
- [Asyncio Documentation](https://docs.python.org/3/library/asyncio.html)
- [Type Hints Guide](https://docs.python.org/3/library/typing.html)

---

**Thank you for contributing to MCP Sentinel Python Edition!** 🚀

Your contributions help make the project better for everyone. If you have questions, don't hesitate to ask in our discussions or create an issue.