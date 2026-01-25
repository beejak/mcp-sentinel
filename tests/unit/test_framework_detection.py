
import pytest
from pathlib import Path
import tempfile
import shutil

from mcp_sentinel.engines.static.static_engine import StaticAnalysisEngine
from mcp_sentinel.models.vulnerability import Severity

@pytest.fixture
def temp_framework_project():
    """Create a temporary project directory with framework-specific vulnerabilities."""
    temp_dir = Path(tempfile.mkdtemp())

    # Django Vulnerabilities
    django_file = temp_dir / "views.py"
    django_file.write_text(
        """
from django.shortcuts import render
from django.contrib.auth.models import User
from django.utils.safestring import mark_safe

def user_detail(request, user_id):
    # Django SQL Injection via raw()
    users = User.objects.raw(f"SELECT * FROM users WHERE id = {user_id}")
    
    # Django XSS via mark_safe()
    user_input = request.GET.get('name')
    content = mark_safe(f"<div>{user_input}</div>")
    
    return render(request, 'detail.html', {'users': users, 'content': content})
"""
    )

    # FastAPI Vulnerabilities
    fastapi_file = temp_dir / "main.py"
    fastapi_file.write_text(
        """
from fastapi import FastAPI
import uvicorn
import os

app = FastAPI()

if __name__ == "__main__":
    # FastAPI Debug Mode Enabled
    uvicorn.run("main:app", reload=True)
"""
    )

    # Flask Vulnerabilities
    flask_file = temp_dir / "app.py"
    flask_file.write_text(
        """
from flask import Flask
import os

app = Flask(__name__)

# Flask Weak Secret Key
app.config['SECRET_KEY'] = 'dev'

if __name__ == "__main__":
    # Flask Debug Mode Enabled
    app.run(debug=True)
"""
    )

    yield temp_dir
    shutil.rmtree(temp_dir)

@pytest.mark.asyncio
async def test_django_detection(temp_framework_project):
    """Test detection of Django vulnerabilities."""
    engine = StaticAnalysisEngine()
    
    django_file = temp_framework_project / "views.py"
    content = django_file.read_text()
    
    vulns = await engine.scan_file(django_file, content, "python")
    
    # Should find:
    # 1. SQL Injection (User.objects.raw)
    # 2. XSS (mark_safe)
    
    sqli_found = any("raw" in v.description.lower() or "sql" in v.description.lower() for v in vulns)
    xss_found = any("mark_safe" in v.description.lower() or "xss" in v.description.lower() for v in vulns)
    
    assert sqli_found, "Django SQL Injection not detected"
    assert xss_found, "Django mark_safe XSS not detected"

@pytest.mark.asyncio
async def test_fastapi_detection(temp_framework_project):
    """Test detection of FastAPI vulnerabilities."""
    engine = StaticAnalysisEngine()
    
    fastapi_file = temp_framework_project / "main.py"
    content = fastapi_file.read_text()
    
    vulns = await engine.scan_file(fastapi_file, content, "python")
    
    # Should find:
    # 1. Debug Mode (reload=True)
    
    debug_found = any("reload=true" in v.description.lower() or "debug" in v.description.lower() for v in vulns)
    
    assert debug_found, "FastAPI debug mode not detected"

@pytest.mark.asyncio
async def test_flask_detection(temp_framework_project):
    """Test detection of Flask vulnerabilities."""
    engine = StaticAnalysisEngine()
    
    flask_file = temp_framework_project / "app.py"
    content = flask_file.read_text()
    
    vulns = await engine.scan_file(flask_file, content, "python")
    
    # Should find:
    # 1. Debug Mode (debug=True)
    # 2. Weak Secret Key
    
    debug_found = any("debug=true" in v.description.lower() for v in vulns)
    secret_found = any("secret_key" in v.description.lower() or "hardcoded" in v.description.lower() for v in vulns)
    
    assert debug_found, "Flask debug mode not detected"
    assert secret_found, "Flask weak secret key not detected"
