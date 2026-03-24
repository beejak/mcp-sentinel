"""
Tests for ComplianceReportGenerator.
"""

import pytest

from mcp_sentinel.models.vulnerability import Confidence, Severity, VulnerabilityType
from mcp_sentinel.reporting.generators.compliance_generator import ComplianceReportGenerator


def _make_vuln(vuln_type: VulnerabilityType, severity: Severity, owasp_asi_id: str = None):
    """Create a minimal Vulnerability for testing."""
    from mcp_sentinel.models.vulnerability import Vulnerability

    v = Vulnerability(
        type=vuln_type,
        title="Test",
        description="Test",
        severity=severity,
        confidence=Confidence.HIGH,
        file_path="test.py",
        line_number=1,
        detector="TestDetector",
        engine="static",
    )
    # Override owasp_asi_id for targeted tests
    if owasp_asi_id is not None:
        v = v.model_copy(update={"owasp_asi_id": owasp_asi_id})
    return v


@pytest.fixture
def generator():
    return ComplianceReportGenerator()


# ---------------------------------------------------------------------------
# Empty scan
# ---------------------------------------------------------------------------


def test_empty_scan_produces_all_categories(generator):
    report = generator.generate([])
    assert "categories" in report
    # All 10 ASI categories must be present
    for i in range(1, 11):
        asi_id = f"ASI{i:02d}"
        assert asi_id in report["categories"], f"{asi_id} missing from report"


def test_empty_scan_all_counts_zero(generator):
    report = generator.generate([])
    for cat in report["categories"].values():
        assert cat["finding_count"] == 0


def test_empty_scan_max_severity_null(generator):
    report = generator.generate([])
    for cat in report["categories"].values():
        assert cat["max_severity"] is None


def test_empty_scan_summary_correct(generator):
    report = generator.generate([])
    assert report["summary"]["categories_with_findings"] == 0
    assert report["total_findings"] == 0


# ---------------------------------------------------------------------------
# Single finding
# ---------------------------------------------------------------------------


def test_single_finding_counted(generator):
    vuln = _make_vuln(VulnerabilityType.PROMPT_INJECTION, Severity.HIGH)
    report = generator.generate([vuln])
    asi01 = report["categories"]["ASI01"]
    assert asi01["finding_count"] == 1
    assert asi01["max_severity"] == "high"
    assert asi01["severity_breakdown"]["high"] == 1
    assert report["total_findings"] == 1


def test_single_finding_summary(generator):
    vuln = _make_vuln(VulnerabilityType.PROMPT_INJECTION, Severity.HIGH)
    report = generator.generate([vuln])
    assert report["summary"]["categories_with_findings"] == 1


# ---------------------------------------------------------------------------
# Multiple findings across categories
# ---------------------------------------------------------------------------


def test_multiple_categories(generator):
    vulns = [
        _make_vuln(VulnerabilityType.PROMPT_INJECTION, Severity.HIGH),  # ASI01
        _make_vuln(VulnerabilityType.SECRET_EXPOSURE, Severity.CRITICAL),  # ASI02
        _make_vuln(VulnerabilityType.PATH_TRAVERSAL, Severity.MEDIUM),  # ASI09
    ]
    report = generator.generate(vulns)
    assert report["categories"]["ASI01"]["finding_count"] == 1
    assert report["categories"]["ASI02"]["finding_count"] == 1
    assert report["categories"]["ASI09"]["finding_count"] == 1
    assert report["summary"]["categories_with_findings"] == 3


def test_severity_breakdown_multiple_findings(generator):
    vulns = [
        _make_vuln(VulnerabilityType.PATH_TRAVERSAL, Severity.HIGH),
        _make_vuln(VulnerabilityType.PATH_TRAVERSAL, Severity.MEDIUM),
        _make_vuln(VulnerabilityType.PATH_TRAVERSAL, Severity.HIGH),
    ]
    report = generator.generate(vulns)
    breakdown = report["categories"]["ASI09"]["severity_breakdown"]
    assert breakdown["high"] == 2
    assert breakdown["medium"] == 1
    assert breakdown["critical"] == 0


# ---------------------------------------------------------------------------
# Max severity tracking
# ---------------------------------------------------------------------------


def test_max_severity_is_highest(generator):
    vulns = [
        _make_vuln(VulnerabilityType.CODE_INJECTION, Severity.LOW),
        _make_vuln(VulnerabilityType.CODE_INJECTION, Severity.CRITICAL),
        _make_vuln(VulnerabilityType.CODE_INJECTION, Severity.MEDIUM),
    ]
    report = generator.generate(vulns)
    assert report["categories"]["ASI04"]["max_severity"] == "critical"


def test_max_severity_high_then_critical(generator):
    vulns = [
        _make_vuln(VulnerabilityType.SSRF, Severity.HIGH),
        _make_vuln(VulnerabilityType.SSRF, Severity.CRITICAL),
    ]
    report = generator.generate(vulns)
    assert report["categories"]["ASI05"]["max_severity"] == "critical"


# ---------------------------------------------------------------------------
# Metadata fields
# ---------------------------------------------------------------------------


def test_report_has_framework_field(generator):
    report = generator.generate([])
    assert report["framework"] == "OWASP Agentic AI Top 10 2026"


def test_report_has_generated_at(generator):
    report = generator.generate([])
    assert "generated_at" in report
    assert "2026" in report["generated_at"]


def test_report_target_and_scan_id(generator):
    report = generator.generate([], target="/some/path", scan_id="abc123")
    assert report["scan_target"] == "/some/path"
    assert report["scan_id"] == "abc123"


def test_report_framework_url(generator):
    report = generator.generate([])
    assert "owasp.org" in report["framework_url"]


# ---------------------------------------------------------------------------
# Category metadata
# ---------------------------------------------------------------------------


def test_category_has_name_and_description(generator):
    report = generator.generate([])
    cat = report["categories"]["ASI01"]
    assert cat["name"] == "Prompt Injection"
    assert len(cat["description"]) > 10


def test_category_has_detector_flag(generator):
    report = generator.generate([])
    for cat in report["categories"].values():
        assert "has_detector" in cat


def test_zero_finding_category_has_note(generator):
    report = generator.generate([])
    for cat in report["categories"].values():
        assert "note" in cat


# ---------------------------------------------------------------------------
# Risk distribution in summary
# ---------------------------------------------------------------------------


def test_risk_distribution_sums_correctly(generator):
    vulns = [
        _make_vuln(VulnerabilityType.SECRET_EXPOSURE, Severity.CRITICAL),
        _make_vuln(VulnerabilityType.PROMPT_INJECTION, Severity.HIGH),
        _make_vuln(VulnerabilityType.PATH_TRAVERSAL, Severity.MEDIUM),
    ]
    report = generator.generate(vulns)
    dist = report["summary"]["risk_distribution"]
    assert dist["critical"] == 1
    assert dist["high"] == 1
    assert dist["medium"] == 1
    assert dist["low"] == 0


# ---------------------------------------------------------------------------
# Vuln with no owasp_asi_id is skipped gracefully
# ---------------------------------------------------------------------------


def test_vuln_without_owasp_id_is_skipped(generator):
    vuln = _make_vuln(VulnerabilityType.SECRET_EXPOSURE, Severity.CRITICAL, owasp_asi_id=None)
    # Override to None explicitly
    vuln = vuln.model_copy(update={"owasp_asi_id": None})
    report = generator.generate([vuln])
    # Finding appears in total but not in any category count
    # (total_findings counts all passed in, categories only those with asi_id)
    assert report["total_findings"] == 1
    for cat in report["categories"].values():
        assert cat["finding_count"] == 0
