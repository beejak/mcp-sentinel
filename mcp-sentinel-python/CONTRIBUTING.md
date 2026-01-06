# Contributing to MCP Sentinel

Thank you for your interest in contributing to MCP Sentinel! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Testing](#testing)
- [Code Style](#code-style)
- [Pull Request Process](#pull-request-process)

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code. Please be respectful and constructive in all interactions.

## Getting Started

### Prerequisites

- Python 3.11 or higher
- Poetry 1.7+
- Git

### Setup Development Environment

1. Fork and clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/mcp-sentinel-python.git
cd mcp-sentinel-python
```

2. Install dependencies:
```bash
poetry install --with dev
```

3. Install pre-commit hooks:
```bash
poetry run pre-commit install
```

4. Create a branch for your feature:
```bash
git checkout -b feature/your-feature-name
```

## Development Workflow

### Running the Scanner

```bash
# Run from source
poetry run mcp-sentinel scan /path/to/project

# Or use python -m
poetry run python -m mcp_sentinel scan /path/to/project
```

### Running Tests

```bash
# Run all tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=mcp_sentinel --cov-report=html

# Run specific test file
poetry run pytest tests/unit/test_secrets_detector.py

# Run tests in watch mode
poetry run pytest-watch
```

### Code Quality

```bash
# Format code
poetry run black src/ tests/
poetry run ruff --fix src/ tests/

# Type checking
poetry run mypy src/

# Security scanning
poetry run bandit -r src/
```

## Testing

### Test Structure

- `tests/unit/` - Unit tests for individual components
- `tests/integration/` - Integration tests
- `tests/e2e/` - End-to-end tests
- `tests/fixtures/` - Test data and fixtures

### Writing Tests

- Use pytest fixtures from `conftest.py`
- Aim for >90% code coverage
- Test both success and failure cases
- Use descriptive test names

Example:
```python
import pytest
from mcp_sentinel.detectors.secrets import SecretsDetector

@pytest.mark.asyncio
async def test_detect_aws_key():
    """Test detection of AWS access keys."""
    detector = SecretsDetector()
    content = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'

    vulns = await detector.detect(Path("test.py"), content)

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.CRITICAL
```

## Code Style

### Python Style Guide

We follow PEP 8 with some modifications enforced by Black:

- Line length: 100 characters
- Use double quotes for strings
- Use trailing commas in multi-line structures

### Type Hints

- All public functions must have type hints
- Use `from typing import ...` for complex types
- Aim for mypy strict mode compliance

Example:
```python
from typing import List, Optional
from pathlib import Path

async def scan_file(
    file_path: Path,
    detectors: Optional[List[BaseDetector]] = None
) -> List[Vulnerability]:
    """Scan a single file."""
    ...
```

### Docstrings

Use Google-style docstrings:

```python
def example_function(param1: str, param2: int) -> bool:
    """
    Short description of function.

    Longer description if needed.

    Args:
        param1: Description of param1
        param2: Description of param2

    Returns:
        Description of return value

    Raises:
        ValueError: When something is wrong
    """
    ...
```

## Pull Request Process

### Before Submitting

1. ✅ Run tests: `poetry run pytest`
2. ✅ Check code style: `poetry run black --check src/ tests/`
3. ✅ Check linting: `poetry run ruff check src/ tests/`
4. ✅ Check types: `poetry run mypy src/`
5. ✅ Update documentation if needed
6. ✅ Add tests for new functionality

### PR Guidelines

1. **Title**: Use a clear, descriptive title
   - Good: "Add DOM-based XSS detector"
   - Bad: "Fixed stuff"

2. **Description**: Include:
   - What changes were made
   - Why the changes were necessary
   - How to test the changes
   - Any breaking changes

3. **Commits**:
   - Use clear commit messages
   - Reference issues when applicable (#123)

4. **Size**: Keep PRs focused and reasonably sized
   - Large features should be broken into smaller PRs

### Example PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
How to test these changes

## Checklist
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Code follows style guidelines
- [ ] All tests passing
```

## Adding New Detectors

To add a new vulnerability detector:

1. Create a new file in `src/mcp_sentinel/detectors/`
2. Inherit from `BaseDetector`
3. Implement the `detect()` method
4. Add tests in `tests/unit/`
5. Register in `detectors/__init__.py`
6. Update documentation

Example:
```python
from mcp_sentinel.detectors.base import BaseDetector

class MyDetector(BaseDetector):
    def __init__(self):
        super().__init__(name="MyDetector", enabled=True)

    async def detect(self, file_path, content, file_type=None):
        # Detection logic here
        vulnerabilities = []
        # ...
        return vulnerabilities
```

## Adding New Integrations

To add a new enterprise integration:

1. Create directory: `src/mcp_sentinel/integrations/my_integration/`
2. Implement the integration class
3. Add configuration to `core/config.py`
4. Add tests
5. Document usage

## Questions?

- Open an issue for bugs or feature requests
- Join our Discord for discussions
- Check existing issues and PRs first

Thank you for contributing to MCP Sentinel! 🎉
