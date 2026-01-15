# Django Project Security Scanning with MCP Sentinel

Complete guide to scanning Django applications for security vulnerabilities using MCP Sentinel's multi-engine analysis.

## Table of Contents
1. [Quick Start](#quick-start)
2. [Django-Specific Vulnerabilities](#django-specific-vulnerabilities)
3. [Configuration](#configuration)
4. [Best Practices](#best-practices)
5. [CI/CD Integration](#cicd-integration)
6. [Common Issues & Fixes](#common-issues--fixes)

---

## Quick Start

### 1. Install MCP Sentinel

```bash
# Install in your Django project
cd your-django-project/
pip install mcp-sentinel

# Or add to requirements.txt
echo "mcp-sentinel>=4.3.0" >> requirements.txt
pip install -r requirements.txt
```

### 2. Run Your First Scan

```bash
# Scan entire Django project
mcp-sentinel scan . --engines static,sast

# Scan specific app
mcp-sentinel scan myapp/

# Generate HTML report
mcp-sentinel scan . --output html --json-file security-report.html
```

### 3. View Results

```bash
# Open HTML report
python -m webbrowser security-report.html  # Or double-click the file
```

---

## Django-Specific Vulnerabilities

MCP Sentinel detects these common Django security issues:

### 1. SQL Injection

**Vulnerable Code:**
```python
# views.py - DANGEROUS
from django.db import connection

def search_users(request):
    query = request.GET.get('q')
    with connection.cursor() as cursor:
        # SQL injection vulnerability!
        cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
        results = cursor.fetchall()
    return JsonResponse({'users': results})
```

**MCP Sentinel Detection:**
- **Static Engine**: Detects string formatting in SQL
- **SAST Engine**: Semgrep rule `python.django.security.injection.sql`
- **Semantic Engine**: Tracks taint from `request.GET` to SQL execution
- **AI Engine**: Understands the context and suggests parameterized queries

**Fix:**
```python
# Use Django ORM (safe)
from django.contrib.auth.models import User

def search_users(request):
    query = request.GET.get('q', '')
    users = User.objects.filter(username__icontains=query)
    return JsonResponse({'users': list(users.values())})

# Or use parameterized queries
def search_users_raw(request):
    query = request.GET.get('q', '')
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE name = %s", [query])
        results = cursor.fetchall()
    return JsonResponse({'users': results})
```

### 2. DEBUG Mode in Production

**Vulnerable Code:**
```python
# settings.py - DANGEROUS
DEBUG = True  # Never do this in production!
ALLOWED_HOSTS = ['*']  # Too permissive
```

**MCP Sentinel Detection:**
- **Static Engine**: Detects `DEBUG = True` in settings files
- **Config Security Detector**: Flags debug mode and wildcard hosts

**Fix:**
```python
# settings.py - SECURE
import os

DEBUG = os.getenv('DJANGO_DEBUG', 'False') == 'True'
ALLOWED_HOSTS = os.getenv('DJANGO_ALLOWED_HOSTS', 'localhost').split(',')

# Or use different settings files
# settings/production.py
DEBUG = False
ALLOWED_HOSTS = ['yourdomain.com', 'www.yourdomain.com']
```

### 3. XSS via Unsafe Templates

**Vulnerable Code:**
```python
# views.py
from django.shortcuts import render
from django.utils.safestring import mark_safe

def display_comment(request, comment_id):
    comment = Comment.objects.get(id=comment_id)
    # DANGEROUS: Disables XSS protection
    safe_content = mark_safe(comment.content)
    return render(request, 'comment.html', {'content': safe_content})
```

```html
<!-- comment.html - DANGEROUS -->
<div>{{ content|safe }}</div>  <!-- XSS vulnerability! -->
```

**MCP Sentinel Detection:**
- **XSS Detector**: Finds `mark_safe()` usage and `|safe` template filter
- **Semantic Engine**: Tracks unsafe data flow to template
- **AI Engine**: Understands business context and recommends sanitization

**Fix:**
```python
# views.py - SECURE
def display_comment(request, comment_id):
    comment = Comment.objects.get(id=comment_id)
    # Django auto-escapes by default
    return render(request, 'comment.html', {'content': comment.content})
```

```html
<!-- comment.html - SECURE -->
<div>{{ content }}</div>  <!-- Auto-escaped by Django -->

<!-- Or use bleach for allowed HTML -->
{% load bleach_tags %}
<div>{{ content|bleach }}</div>
```

### 4. Hardcoded Secrets

**Vulnerable Code:**
```python
# settings.py - DANGEROUS
SECRET_KEY = 'django-insecure-hardcoded-key-12345'
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'mydb',
        'USER': 'admin',
        'PASSWORD': 'admin123',  # Hardcoded password!
        'HOST': 'localhost',
    }
}

# AWS credentials (DANGEROUS)
AWS_ACCESS_KEY_ID = 'AKIA1234567890EXAMPLE'
AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
```

**MCP Sentinel Detection:**
- **Secrets Detector**: Finds Django `SECRET_KEY`, database passwords, AWS keys
- **Pattern matching**: High-entropy strings, credential patterns
- **Semantic analysis**: Tracks secret usage across files

**Fix:**
```python
# settings.py - SECURE
import os
from pathlib import Path

# Load from environment variables
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("DJANGO_SECRET_KEY environment variable must be set")

# Use django-environ for better management
import environ
env = environ.Env()
environ.Env.read_env(Path(__file__).resolve().parent / '.env')

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': env('DB_NAME'),
        'USER': env('DB_USER'),
        'PASSWORD': env('DB_PASSWORD'),
        'HOST': env('DB_HOST', default='localhost'),
    }
}

AWS_ACCESS_KEY_ID = env('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = env('AWS_SECRET_ACCESS_KEY')
```

### 5. CSRF Protection Disabled

**Vulnerable Code:**
```python
# views.py - DANGEROUS
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt  # Never do this unless absolutely necessary
def api_endpoint(request):
    if request.method == 'POST':
        # Process data without CSRF protection
        data = request.POST
        # ... process data
```

**MCP Sentinel Detection:**
- **Config Security Detector**: Flags `@csrf_exempt` decorator
- **Static analysis**: Finds disabled CSRF middleware
- **AI Engine**: Understands when CSRF exemption is justified (e.g., API with token auth)

**Fix:**
```python
# For APIs, use proper authentication instead
from rest_framework.decorators import api_view, authentication_classes
from rest_framework.authentication import TokenAuthentication

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
def api_endpoint(request):
    # Token authentication provides CSRF protection
    data = request.data
    # ... process data

# For regular views, keep CSRF enabled
def form_view(request):
    if request.method == 'POST':
        # CSRF token automatically validated
        form = MyForm(request.POST)
        if form.is_valid():
            form.save()
```

---

## Configuration

### Project-Specific Config

Create `.mcp-sentinel.yaml` in your Django project root:

```yaml
# .mcp-sentinel.yaml for Django projects

engines:
  static: true
  sast: true
  semantic: true
  ai: false  # Enable for production scans

scan:
  # Include Django-specific files
  include_patterns:
    - "**/*.py"
    - "**/settings/*.py"
    - "**/templates/**/*.html"
    - "**/urls.py"
    - "**/views.py"
    - "**/models.py"
    - "**/forms.py"

  # Exclude common Django directories
  exclude_patterns:
    - "**/venv/**"
    - "**/env/**"
    - "**/.venv/**"
    - "**/migrations/**"  # Auto-generated migration files
    - "**/staticfiles/**"
    - "**/media/**"
    - "**/__pycache__/**"
    - "**/node_modules/**"  # If using frontend tools
    - "**/dist/**"
    - "**/.git/**"
    - "**/htmlcov/**"  # Coverage reports

  # Filter by severity
  min_severity: medium  # Or 'high' for CI/CD

reporting:
  formats: [terminal, html, sarif]
  output_dir: ./security-reports

  html:
    include_executive_summary: true
    show_risk_score: true
    animated_charts: true

  sarif:
    github_code_scanning: true
```

### Environment Variables

Add to your `.env` file (never commit this!):

```bash
# .env
ANTHROPIC_API_KEY=your-api-key-here  # For AI-powered scanning
```

---

## Best Practices

### 1. Pre-Commit Hook

Add MCP Sentinel to your pre-commit checks:

**.pre-commit-config.yaml**:
```yaml
repos:
  - repo: local
    hooks:
      - id: mcp-sentinel
        name: MCP Sentinel Security Scan
        entry: mcp-sentinel scan
        args: ['--engines', 'static', '--severity', 'critical', '--severity', 'high']
        language: system
        pass_filenames: false
        always_run: true
```

### 2. Django Settings Organization

Scan different environments:

```bash
# Development settings
DJANGO_SETTINGS_MODULE=myproject.settings.dev mcp-sentinel scan .

# Production settings (more strict)
DJANGO_SETTINGS_MODULE=myproject.settings.prod mcp-sentinel scan . \
  --severity critical --severity high
```

### 3. Regular Scans

Run comprehensive scans weekly:

```bash
# Full multi-engine scan with AI
mcp-sentinel scan . \
  --engines all \
  --output html \
  --json-file weekly-scan-$(date +%Y-%m-%d).html
```

### 4. Django-Admin Scanning

Specifically scan admin configuration:

```bash
# Scan admin files for security issues
mcp-sentinel scan "**/admin.py" --engines static,semantic
```

---

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/django-security.yml`:

```yaml
name: Django Security Scan

on:
  pull_request:
    paths:
      - '**.py'
      - '**/settings/**'
      - '**/requirements*.txt'
  push:
    branches: [main, master]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install mcp-sentinel semgrep bandit
          pip install -r requirements.txt

      - name: Run MCP Sentinel
        run: |
          mcp-sentinel scan . \
            --engines static,sast,semantic \
            --output sarif \
            --json-file results.sarif

      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### GitLab CI

Create `.gitlab-ci.yml`:

```yaml
security-scan:
  image: python:3.11
  stage: test
  script:
    - pip install mcp-sentinel semgrep bandit
    - pip install -r requirements.txt
    - mcp-sentinel scan . --engines static,sast --output json --json-file security.json
  artifacts:
    reports:
      sast: security.json
    paths:
      - security.json
    expire_in: 1 week
```

---

## Common Issues & Fixes

### Issue 1: Too Many False Positives

**Problem**: Scan finds Django test files as vulnerabilities

**Solution**: Exclude test directories
```yaml
# .mcp-sentinel.yaml
scan:
  exclude_patterns:
    - "**/tests/**"
    - "**/test_*.py"
    - "**/*_test.py"
```

### Issue 2: Third-Party Package Warnings

**Problem**: Security warnings in installed packages

**Solution**: Focus on your code
```bash
# Scan only your app directories
mcp-sentinel scan myapp/ otherapp/ --engines all
```

### Issue 3: Settings File Secrets

**Problem**: Local development secrets flagged

**Solution**: Use environment-specific configs
```python
# settings/local.py (add to .gitignore)
from .base import *

DEBUG = True
SECRET_KEY = 'local-dev-key-not-for-production'

# settings/production.py (secrets from env vars)
from .base import *
import os

DEBUG = False
SECRET_KEY = os.environ['SECRET_KEY']
```

### Issue 4: Django ORM False Positives

**Problem**: Django ORM queries flagged as SQL injection

**Solution**: MCP Sentinel's semantic engine understands Django ORM patterns. If you see false positives with raw SQL:

```python
# Use Django's built-in protection
from django.db.models import Q

# Safe: Django ORM handles escaping
User.objects.filter(Q(username__icontains=query) | Q(email__icontains=query))

# If you must use raw SQL, use parameterization
User.objects.raw('SELECT * FROM auth_user WHERE username = %s', [username])
```

---

## Django Security Checklist

Use this checklist with MCP Sentinel results:

- [ ] `DEBUG = False` in production (Config Security)
- [ ] Strong `SECRET_KEY` from environment (Secrets Detector)
- [ ] HTTPS enforced (`SECURE_SSL_REDIRECT = True`)
- [ ] Database credentials in environment variables
- [ ] CSRF protection enabled (no `@csrf_exempt` without reason)
- [ ] XSS protection (avoid `mark_safe`, `|safe` filters)
- [ ] SQL injection prevented (use Django ORM)
- [ ] Secure session cookies (`SESSION_COOKIE_SECURE = True`)
- [ ] Content Security Policy configured
- [ ] Admin interface protected (custom URL, 2FA)

Run comprehensive scan:
```bash
mcp-sentinel scan . --engines all --severity critical --severity high
```

---

## Next Steps

1. **Run your first scan**: `mcp-sentinel scan .`
2. **Fix critical issues**: Start with CRITICAL and HIGH severity
3. **Set up CI/CD**: Add GitHub Actions workflow
4. **Schedule regular scans**: Weekly full scans with AI engine
5. **Monitor trends**: Track security improvements over time

## Resources

- [Django Security Docs](https://docs.djangoproject.com/en/stable/topics/security/)
- [OWASP Django Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Django_Security_Cheat_Sheet.html)
- [MCP Sentinel Documentation](../README.md)
- [Example Reports](../examples/)

---

**Need Help?** Open an issue on [GitHub](https://github.com/beejak/mcp-sentinel/issues)
