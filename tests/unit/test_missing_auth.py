"""Tests for MissingAuthDetector."""
import pytest
from pathlib import Path

from mcp_sentinel.detectors.missing_auth import MissingAuthDetector
from mcp_sentinel.models.vulnerability import Severity, VulnerabilityType


@pytest.fixture
def detector():
    return MissingAuthDetector()


# ---------------------------------------------------------------------------
# Flask routes without auth
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detect_flask_route_no_auth(detector):
    content = '''
@app.route("/data", methods=["GET"])
def get_data():
    return jsonify(db.get_all())
'''
    vulns = await detector.detect(Path("app.py"), content)
    assert any(v.type == VulnerabilityType.MISSING_AUTH for v in vulns)


@pytest.mark.asyncio
async def test_detect_flask_admin_route_no_auth(detector):
    content = '''
@app.route("/admin/users")
def list_users():
    return jsonify(User.query.all())
'''
    vulns = await detector.detect(Path("app.py"), content)
    missing = [v for v in vulns if v.type == VulnerabilityType.MISSING_AUTH]
    assert len(missing) > 0


@pytest.mark.asyncio
async def test_flask_route_with_login_required_suppressed(detector):
    content = '''
@login_required
@app.route("/data")
def get_data():
    return jsonify(db.get_all())
'''
    vulns = await detector.detect(Path("app.py"), content)
    missing = [v for v in vulns if v.type == VulnerabilityType.MISSING_AUTH]
    assert len(missing) == 0


@pytest.mark.asyncio
async def test_flask_route_with_auth_required_suppressed(detector):
    content = '''
@auth_required
@app.route("/profile")
def profile():
    return current_user
'''
    vulns = await detector.detect(Path("app.py"), content)
    missing = [v for v in vulns if v.type == VulnerabilityType.MISSING_AUTH]
    assert len(missing) == 0


# ---------------------------------------------------------------------------
# FastAPI routes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detect_fastapi_router_no_auth(detector):
    content = '''
@router.get("/items")
async def list_items():
    return db.get_items()
'''
    vulns = await detector.detect(Path("routes.py"), content)
    assert any(v.type == VulnerabilityType.MISSING_AUTH for v in vulns)


@pytest.mark.asyncio
async def test_fastapi_route_with_depends_suppressed(detector):
    content = '''
@router.get("/items")
async def list_items(user=Depends(get_current_user)):
    return db.get_items(user)
'''
    vulns = await detector.detect(Path("routes.py"), content)
    missing = [v for v in vulns if v.type == VulnerabilityType.MISSING_AUTH]
    assert len(missing) == 0


@pytest.mark.asyncio
async def test_fastapi_debug_route_no_auth(detector):
    content = '''
@router.get("/debug/state")
async def get_state():
    return app.state.__dict__
'''
    vulns = await detector.detect(Path("routes.py"), content)
    missing = [v for v in vulns if v.type == VulnerabilityType.MISSING_AUTH]
    assert len(missing) > 0


# ---------------------------------------------------------------------------
# Express.js routes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detect_express_route_no_auth(detector):
    content = '''
app.get("/api/users", async (req, res) => {
    const users = await db.find();
    res.json(users);
});
'''
    vulns = await detector.detect(Path("server.js"), content)
    assert any(v.type == VulnerabilityType.MISSING_AUTH for v in vulns)


@pytest.mark.asyncio
async def test_express_admin_route_no_auth(detector):
    content = '''
router.delete("/admin/user/:id", async (req, res) => {
    await User.deleteOne({ _id: req.params.id });
    res.sendStatus(200);
});
'''
    vulns = await detector.detect(Path("admin.js"), content)
    missing = [v for v in vulns if v.type == VulnerabilityType.MISSING_AUTH]
    assert len(missing) > 0


@pytest.mark.asyncio
async def test_express_route_with_auth_middleware_suppressed(detector):
    content = '''
app.get("/api/profile", authMiddleware, async (req, res) => {
    res.json(req.user);
});
'''
    vulns = await detector.detect(Path("server.js"), content)
    missing = [v for v in vulns if v.type == VulnerabilityType.MISSING_AUTH]
    assert len(missing) == 0


# ---------------------------------------------------------------------------
# MCP tool definitions with system operations
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detect_mcp_tool_exec_no_auth(detector):
    content = '''
{
    "name": "run_shell_exec",
    "description": "Execute a shell command",
    "parameters": {"command": {"type": "string"}}
}
'''
    vulns = await detector.detect(Path("tools.json"), content)
    missing = [v for v in vulns if v.type == VulnerabilityType.MISSING_AUTH]
    assert len(missing) > 0
    assert missing[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_detect_mcp_tool_system_no_auth(detector):
    content = 'name = "execute_system_command"'
    vulns = await detector.detect(Path("tool.py"), content)
    missing = [v for v in vulns if v.type == VulnerabilityType.MISSING_AUTH]
    assert len(missing) > 0


# ---------------------------------------------------------------------------
# Sensitive path detection
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sensitive_internal_path_flagged(detector):
    content = '@app.route("/internal/config")\ndef get_config():\n    return config'
    vulns = await detector.detect(Path("app.py"), content)
    missing = [v for v in vulns if v.type == VulnerabilityType.MISSING_AUTH]
    assert len(missing) > 0


# ---------------------------------------------------------------------------
# is_applicable
# ---------------------------------------------------------------------------

def test_applicable_python(detector):
    assert detector.is_applicable(Path("app.py")) is True

def test_applicable_javascript(detector):
    assert detector.is_applicable(Path("server.js")) is True

def test_applicable_typescript(detector):
    assert detector.is_applicable(Path("routes.ts")) is True

def test_applicable_json(detector):
    assert detector.is_applicable(Path("tools.json")) is True

def test_not_applicable_go(detector):
    assert detector.is_applicable(Path("server.go")) is False

def test_not_applicable_yaml(detector):
    assert detector.is_applicable(Path("config.yaml")) is False
