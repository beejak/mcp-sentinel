"""Executive Go/No-Go and action queue (rule-based)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from mcp_sentinel.models.executive_assessment import ExecutivePolicy
from mcp_sentinel.models.scan_result import ScanResult
from mcp_sentinel.models.vulnerability import (
    Confidence,
    Severity,
    Vulnerability,
    VulnerabilityType,
)
from mcp_sentinel.reporting.executive_assessment import (
    build_executive_assessment,
    load_executive_policy,
    triage_for_vulnerability,
)


def _v(**kwargs) -> Vulnerability:
    base = {
        "type": VulnerabilityType.PROMPT_INJECTION,
        "title": "Test finding",
        "description": "d",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "file_path": "a.py",
        "line_number": 1,
        "detector": "X",
        "engine": "static",
        "timestamp": datetime.now(UTC),
    }
    base.update(kwargs)
    return Vulnerability(**base)


def test_empty_scan_go():
    r = ScanResult(target=".", vulnerabilities=[])
    ea = build_executive_assessment(r, ExecutivePolicy())
    assert ea.verdict == "go"
    assert ea.verdict_reasons == []
    assert ea.action_queue == []


def test_no_go_on_critical():
    r = ScanResult(
        target=".",
        vulnerabilities=[_v(severity=Severity.CRITICAL, title="RCE")],
    )
    ea = build_executive_assessment(r, ExecutivePolicy())
    assert ea.verdict == "no_go"
    assert any("critical" in x.lower() for x in ea.verdict_reasons)


def test_policy_disable_critical_still_go_with_critical():
    r = ScanResult(
        target=".",
        vulnerabilities=[_v(severity=Severity.CRITICAL)],
    )
    pol = ExecutivePolicy(no_go_if_critical=False)
    ea = build_executive_assessment(r, pol)
    assert ea.verdict == "go"


def test_no_go_high_count_threshold():
    highs = [_v(severity=Severity.HIGH, title=f"h{i}", line_number=i) for i in range(3)]
    r = ScanResult(target=".", vulnerabilities=highs)
    pol = ExecutivePolicy(no_go_if_critical=False, no_go_if_high_count_at_least=3)
    ea = build_executive_assessment(r, pol)
    assert ea.verdict == "no_go"


def test_no_go_vulnerability_type():
    r = ScanResult(
        target=".",
        vulnerabilities=[
            _v(
                type=VulnerabilityType.CODE_INJECTION,
                severity=Severity.MEDIUM,
                title="eval",
            )
        ],
    )
    pol = ExecutivePolicy(
        no_go_if_critical=False,
        no_go_vulnerability_types=["code_injection"],
    )
    ea = build_executive_assessment(r, pol)
    assert ea.verdict == "no_go"
    assert any("code_injection" in x for x in ea.verdict_reasons)


def test_action_queue_order_critical_first():
    r = ScanResult(
        target=".",
        vulnerabilities=[
            _v(severity=Severity.MEDIUM, title="m", line_number=2),
            _v(severity=Severity.CRITICAL, title="c", line_number=3),
        ],
    )
    ea = build_executive_assessment(r, ExecutivePolicy())
    assert ea.action_queue[0].severity == "critical"
    assert ea.action_queue[0].title == "c"


def test_load_policy_yaml(tmp_path: Path):
    p = tmp_path / "pol.yaml"
    p.write_text(
        "no_go_if_critical: false\nno_go_if_high_count_at_least: 5\naction_queue_top_n: 3\n",
        encoding="utf-8",
    )
    pol = load_executive_policy(p)
    assert pol.no_go_if_critical is False
    assert pol.no_go_if_high_count_at_least == 5
    assert pol.action_queue_top_n == 3


def test_load_policy_none():
    assert load_executive_policy(None).no_go_if_critical is True


def test_triage_prioritize_critical():
    v = _v(severity=Severity.CRITICAL)
    assert triage_for_vulnerability(v) == "prioritize"


def test_scan_result_json_embeds_executive():
    r = ScanResult(
        target=".",
        vulnerabilities=[_v(severity=Severity.CRITICAL)],
    )
    r.executive_assessment = build_executive_assessment(r, ExecutivePolicy())
    data = r.model_dump(mode="json")
    assert "executive_assessment" in data
    assert data["executive_assessment"]["verdict"] == "no_go"


def test_recalculate_statistics_after_filter_semantics():
    r = ScanResult(
        target=".",
        vulnerabilities=[
            _v(severity=Severity.CRITICAL, line_number=1),
            _v(severity=Severity.LOW, line_number=2),
        ],
    )
    r.vulnerabilities = [r.vulnerabilities[1]]
    r.recalculate_statistics_from_findings()
    assert r.statistics.critical_count == 0
    assert r.statistics.low_count == 1
    assert r.statistics.total_vulnerabilities == 1


def test_invalid_yaml_mapping_raises(tmp_path: Path):
    p = tmp_path / "bad.yaml"
    p.write_text("- item\n", encoding="utf-8")
    with pytest.raises(ValueError, match="mapping"):
        load_executive_policy(p)
