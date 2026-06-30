"""
Tests for ContextFloodingDetector.

Validates detection of patterns that can flood the LLM context window:
unbounded file reads, uncapped directory walks, queries without LIMIT,
and list tools missing pagination parameters.
"""

import pytest
from pathlib import Path

from mcp_sentinel.detectors.context_flooding import ContextFloodingDetector
from mcp_sentinel.models.vulnerability import Confidence, Severity, VulnerabilityType


@pytest.fixture
def detector():
    return ContextFloodingDetector()


FIXTURE = Path(__file__).parent.parent / "fixtures" / "vulnerable_context_flooding.py"


# ---------------------------------------------------------------------------
# Fixture file — end-to-end ground truth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fixture_has_findings(detector):
    content = FIXTURE.read_text()
    vulns = await detector.detect(Path("mcp_tools.py"), content, "python")
    assert len(vulns) >= 4, f"Expected ≥4 findings from fixture, got {len(vulns)}"
    assert all(v.type == VulnerabilityType.CONTEXT_FLOODING for v in vulns)


@pytest.mark.asyncio
async def test_fixture_has_no_critical_false_positives(detector):
    """Safe patterns in the fixture should not produce findings."""
    content = FIXTURE.read_text()
    vulns = await detector.detect(Path("mcp_tools.py"), content, "python")
    # None should be CRITICAL — context flooding is MEDIUM/LOW by design
    critical = [v for v in vulns if v.severity == Severity.CRITICAL]
    assert len(critical) == 0


# ---------------------------------------------------------------------------
# Unbounded file reads (CWE-400)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unbounded_open_read(detector):
    content = "return open(path).read()"
    vulns = await detector.detect(Path("tool.py"), content, "python")
    hits = [v for v in vulns if "Unbounded File Read" in v.title]
    assert len(hits) >= 1
    assert hits[0].severity == Severity.MEDIUM
    assert hits[0].cwe_id == "CWE-400"


@pytest.mark.asyncio
async def test_unbounded_path_read_text(detector):
    content = "content = Path(config_path).read_text()"
    vulns = await detector.detect(Path("server.py"), content, "python")
    hits = [v for v in vulns if "Unbounded File Read" in v.title]
    assert len(hits) >= 1


@pytest.mark.asyncio
async def test_aiofiles_open_flagged(detector):
    content = "import aiofiles\nasync with aiofiles.open(log_file) as f:\n    data = await f.read()"
    vulns = await detector.detect(Path("server.py"), content, "python")
    hits = [v for v in vulns if "Unbounded File Read" in v.title]
    assert len(hits) >= 1


@pytest.mark.asyncio
async def test_safe_read_with_limit(detector):
    content = "return open(path).read(65536)"
    vulns = await detector.detect(Path("safe.py"), content, "python")
    hits = [v for v in vulns if "Unbounded File Read" in v.title]
    assert len(hits) == 0


@pytest.mark.asyncio
async def test_safe_read_with_max_bytes(detector):
    content = "data = open(path).read(MAX_BYTES)"
    vulns = await detector.detect(Path("safe.py"), content, "python")
    hits = [v for v in vulns if "Unbounded File Read" in v.title]
    assert len(hits) == 0


# ---------------------------------------------------------------------------
# Unbounded directory walk (CWE-770)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_os_walk_flagged(detector):
    content = "for root, dirs, files in os.walk(directory):\n    process(files)"
    vulns = await detector.detect(Path("tool.py"), content, "python")
    hits = [v for v in vulns if "Directory Walk" in v.title]
    assert len(hits) >= 1
    assert hits[0].severity == Severity.MEDIUM
    assert hits[0].cwe_id == "CWE-770"


@pytest.mark.asyncio
async def test_rglob_flagged(detector):
    content = "files = list(Path(base).rglob('*.py'))"
    vulns = await detector.detect(Path("lister.py"), content, "python")
    hits = [v for v in vulns if "Directory Walk" in v.title]
    assert len(hits) >= 1


@pytest.mark.asyncio
async def test_glob_double_star_flagged(detector):
    content = "import glob\nresults = glob.glob(f'{base}/**/*.yaml')"
    vulns = await detector.detect(Path("scanner.py"), content, "python")
    hits = [v for v in vulns if "Directory Walk" in v.title]
    assert len(hits) >= 1


# ---------------------------------------------------------------------------
# Database queries without LIMIT (CWE-770)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetchall_flagged(detector):
    content = 'rows = cursor.execute("SELECT * FROM users").fetchall()'
    vulns = await detector.detect(Path("db.py"), content, "python")
    hits = [v for v in vulns if "Database Query" in v.title]
    assert len(hits) >= 1
    assert hits[0].severity == Severity.MEDIUM
    assert hits[0].cwe_id == "CWE-770"
    assert hits[0].confidence == Confidence.LOW


@pytest.mark.asyncio
async def test_sqlalchemy_all_flagged(detector):
    content = "return session.query(Event).all()"
    vulns = await detector.detect(Path("repo.py"), content, "python")
    hits = [v for v in vulns if "Database Query" in v.title]
    assert len(hits) >= 1


@pytest.mark.asyncio
async def test_safe_query_with_limit(detector):
    # LIMIT on same line suppresses the fetchall finding
    content = 'rows = cursor.execute("SELECT * FROM users LIMIT 50").fetchall()'
    vulns = await detector.detect(Path("safe.py"), content, "python")
    hits = [v for v in vulns if "Database Query" in v.title]
    assert len(hits) == 0


# ---------------------------------------------------------------------------
# Missing pagination on list tools (CWE-770)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_function_no_pagination(detector):
    content = "def list_documents(user_id: str) -> list:\n    return db.query(...)"
    vulns = await detector.detect(Path("tools.py"), content, "python")
    hits = [v for v in vulns if "Pagination" in v.title]
    assert len(hits) >= 1
    assert hits[0].severity == Severity.LOW


@pytest.mark.asyncio
async def test_get_all_function_no_pagination(detector):
    content = "async def get_all_messages(channel_id: str) -> list:\n    return await db.fetch(...)"
    vulns = await detector.detect(Path("tools.py"), content, "python")
    hits = [v for v in vulns if "Pagination" in v.title]
    assert len(hits) >= 1


@pytest.mark.asyncio
async def test_fetch_all_function_no_pagination(detector):
    content = "def fetch_all_records(table: str) -> list:\n    return db.execute(...)"
    vulns = await detector.detect(Path("tools.py"), content, "python")
    hits = [v for v in vulns if "Pagination" in v.title]
    assert len(hits) >= 1


@pytest.mark.asyncio
async def test_safe_list_with_limit_param(detector):
    content = "def list_documents(user_id: str, limit: int = 50, cursor: str = None) -> dict:"
    vulns = await detector.detect(Path("safe.py"), content, "python")
    hits = [v for v in vulns if "Pagination" in v.title]
    assert len(hits) == 0


@pytest.mark.asyncio
async def test_safe_list_with_offset_param(detector):
    content = "def list_users(org_id: str, limit: int = 25, offset: int = 0) -> list:"
    vulns = await detector.detect(Path("safe.py"), content, "python")
    hits = [v for v in vulns if "Pagination" in v.title]
    assert len(hits) == 0


@pytest.mark.asyncio
async def test_safe_get_with_max_results(detector):
    content = "async def get_all_events(stream_id: str, max_results: int = 100) -> list:"
    vulns = await detector.detect(Path("safe.py"), content, "python")
    hits = [v for v in vulns if "Pagination" in v.title]
    assert len(hits) == 0


# ---------------------------------------------------------------------------
# File type filtering
# ---------------------------------------------------------------------------


def test_applicable_python(detector):
    assert detector.is_applicable(Path("server.py"))


def test_applicable_typescript(detector):
    assert detector.is_applicable(Path("tools.ts"))


def test_not_applicable_json(detector):
    assert not detector.is_applicable(Path("config.json"))


def test_not_applicable_yaml(detector):
    assert not detector.is_applicable(Path("schema.yaml"))


# ---------------------------------------------------------------------------
# Test file suppression
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_skips_test_files(detector):
    content = "return open(path).read()\nfor root, dirs, files in os.walk(base): pass"
    vulns = await detector.detect(Path("tests/unit/test_tool.py"), content, "python")
    assert len(vulns) == 0


# ---------------------------------------------------------------------------
# Metadata completeness
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_finding_metadata_complete(detector):
    content = "return open(path).read()"
    vulns = await detector.detect(Path("tool.py"), content, "python")
    assert len(vulns) >= 1
    v = vulns[0]
    assert v.type == VulnerabilityType.CONTEXT_FLOODING
    assert v.title
    assert v.description
    assert v.cwe_id
    assert v.cvss_score and v.cvss_score > 0
    assert v.remediation
    assert len(v.references) >= 1
    assert v.detector == "ContextFloodingDetector"
    assert v.engine == "static"
    assert v.owasp_asi_id == "ASI06"
    assert v.line_number == 1
