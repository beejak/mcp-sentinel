"""Tests for OWASP Agentic AI Top 10 mapping module."""

import pytest

from mcp_sentinel.models.owasp_mapping import (
    OWASP_ASI_CATALOGUE,
    annotate,
    build_compliance_summary,
    get_asi_id,
    get_asi_name,
)
from mcp_sentinel.models.vulnerability import (
    Confidence,
    Severity,
    Vulnerability,
    VulnerabilityType,
)


# ---------------------------------------------------------------------------
# Catalogue completeness
# ---------------------------------------------------------------------------


def test_catalogue_has_ten_entries():
    assert len(OWASP_ASI_CATALOGUE) == 10


def test_catalogue_ids_are_sequential():
    for i in range(1, 11):
        key = f"ASI{i:02d}"
        assert key in OWASP_ASI_CATALOGUE, f"{key} missing from catalogue"


def test_catalogue_entries_have_name_and_description():
    for asi_id, entry in OWASP_ASI_CATALOGUE.items():
        assert "name" in entry, f"{asi_id} missing 'name'"
        assert "description" in entry, f"{asi_id} missing 'description'"
        assert entry["name"], f"{asi_id} 'name' is empty"


# ---------------------------------------------------------------------------
# get_asi_id / get_asi_name
# ---------------------------------------------------------------------------


def test_get_asi_id_prompt_injection():
    assert get_asi_id(VulnerabilityType.PROMPT_INJECTION) == "ASI01"


def test_get_asi_id_tool_poisoning():
    assert get_asi_id(VulnerabilityType.TOOL_POISONING) == "ASI01"


def test_get_asi_id_secret_exposure():
    assert get_asi_id(VulnerabilityType.SECRET_EXPOSURE) == "ASI02"


def test_get_asi_id_supply_chain():
    assert get_asi_id(VulnerabilityType.SUPPLY_CHAIN) == "ASI03"


def test_get_asi_id_code_injection():
    assert get_asi_id(VulnerabilityType.CODE_INJECTION) == "ASI04"


def test_get_asi_id_missing_auth():
    assert get_asi_id(VulnerabilityType.MISSING_AUTH) == "ASI04"


def test_get_asi_id_ssrf():
    assert get_asi_id(VulnerabilityType.SSRF) == "ASI05"


def test_get_asi_id_network_binding():
    assert get_asi_id(VulnerabilityType.NETWORK_BINDING) == "ASI06"


def test_get_asi_id_weak_crypto():
    assert get_asi_id(VulnerabilityType.WEAK_CRYPTO) == "ASI07"


def test_get_asi_id_insecure_deserialization():
    assert get_asi_id(VulnerabilityType.INSECURE_DESERIALIZATION) == "ASI08"


def test_get_asi_id_path_traversal():
    assert get_asi_id(VulnerabilityType.PATH_TRAVERSAL) == "ASI09"


def test_get_asi_id_mcp_sampling():
    assert get_asi_id(VulnerabilityType.MCP_SAMPLING) == "ASI10"


def test_get_asi_name_asi01():
    assert get_asi_name("ASI01") == "Prompt Injection"


def test_get_asi_name_unknown():
    assert get_asi_name("ASI99") is None


# ---------------------------------------------------------------------------
# annotate()
# ---------------------------------------------------------------------------


def test_annotate_returns_tuple():
    asi_id, asi_name = annotate(VulnerabilityType.PATH_TRAVERSAL)
    assert asi_id == "ASI09"
    assert asi_name == "Improper Error Handling / Path Traversal"


def test_annotate_mcp_sampling():
    asi_id, asi_name = annotate(VulnerabilityType.MCP_SAMPLING)
    assert asi_id == "ASI10"
    assert asi_name == "Inadequate Audit and Monitoring"


# ---------------------------------------------------------------------------
# build_compliance_summary()
# ---------------------------------------------------------------------------


def _make_vuln(vuln_type: VulnerabilityType, severity: Severity) -> Vulnerability:
    asi_id, asi_name = annotate(vuln_type)
    return Vulnerability(
        type=vuln_type,
        title="Test",
        description="Test",
        severity=severity,
        confidence=Confidence.HIGH,
        file_path="test.py",
        line_number=1,
        detector="test",
        engine="static",
        owasp_asi_id=asi_id,
        owasp_asi_name=asi_name,
    )


def test_compliance_summary_empty():
    result = build_compliance_summary([])
    assert result == {}


def test_compliance_summary_counts():
    vulns = [
        _make_vuln(VulnerabilityType.PROMPT_INJECTION, Severity.HIGH),
        _make_vuln(VulnerabilityType.PROMPT_INJECTION, Severity.CRITICAL),
        _make_vuln(VulnerabilityType.SECRET_EXPOSURE, Severity.MEDIUM),
    ]
    summary = build_compliance_summary(vulns)
    assert "ASI01" in summary
    assert summary["ASI01"]["count"] == 2
    assert summary["ASI01"]["high"] == 1
    assert summary["ASI01"]["critical"] == 1
    assert "ASI02" in summary
    assert summary["ASI02"]["count"] == 1
    assert summary["ASI02"]["medium"] == 1


def test_compliance_summary_sorted():
    vulns = [
        _make_vuln(VulnerabilityType.PATH_TRAVERSAL, Severity.HIGH),
        _make_vuln(VulnerabilityType.PROMPT_INJECTION, Severity.LOW),
    ]
    summary = build_compliance_summary(vulns)
    keys = list(summary.keys())
    assert keys == sorted(keys)


def test_compliance_summary_excludes_no_mapping():
    """Vulns with no owasp_asi_id (shouldn't happen in practice) are skipped."""

    class _VulnNoASI:
        owasp_asi_id = None
        owasp_asi_name = None
        severity = Severity.HIGH

    summary = build_compliance_summary([_VulnNoASI()])  # type: ignore[list-item]
    assert summary == {}


# ---------------------------------------------------------------------------
# All VulnerabilityTypes are mapped
# ---------------------------------------------------------------------------


def test_all_vulnerability_types_have_mapping():
    unmapped = [vt for vt in VulnerabilityType if get_asi_id(vt) is None]
    assert unmapped == [], f"Unmapped vulnerability types: {unmapped}"
