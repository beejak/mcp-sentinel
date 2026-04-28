"""
Rule-based executive decision support: Go / No-Go, triage labels, and action queue.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from mcp_sentinel.models.executive_assessment import (
    ActionItem,
    ExecutiveAssessment,
    ExecutivePolicy,
    TriageLabel,
    Verdict,
)
from mcp_sentinel.models.scan_result import ScanResult
from mcp_sentinel.models.vulnerability import (
    Severity,
    Vulnerability,
    VulnerabilityType,
)


def load_executive_policy(path: str | Path | None) -> ExecutivePolicy:
    """Load policy from YAML or return defaults."""
    if not path:
        return ExecutivePolicy()
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if raw is None:
        return ExecutivePolicy()
    if not isinstance(raw, dict):
        raise ValueError(f"Executive policy must be a YAML mapping, got {type(raw).__name__}")
    return ExecutivePolicy.model_validate(raw)


def _has_threat_intel_match(v: Vulnerability) -> bool:
    if not v.threat_intel or not isinstance(v.threat_intel, dict):
        return False
    vm = v.threat_intel.get("vulnerable_mcp")
    if isinstance(vm, dict) and vm.get("matched_records"):
        return len(vm["matched_records"]) > 0
    return bool(v.threat_intel)


def triage_for_vulnerability(v: Vulnerability) -> TriageLabel:
    if v.severity == Severity.CRITICAL:
        return "prioritize"
    if v.severity == Severity.HIGH:
        return "prioritize" if _has_threat_intel_match(v) else "review"
    if v.severity == Severity.MEDIUM:
        return "review"
    return "informational"


def _default_type_hints() -> dict[str, str]:
    return {
        "code_injection": "Validate sinks and user-controlled data paths; remove eval/exec patterns.",
        "secret_exposure": "Rotate exposed secrets; use a secret manager or environment injection.",
        "prompt_injection": "Harden system prompts, tool allowlists, and input boundaries.",
        "tool_poisoning": "Review tool descriptions and Unicode/normalization for deceptive metadata.",
        "supply_chain": "Pin dependencies and verify package integrity.",
        "config_security": "Disable debug in production; tighten CORS, TLS, and auth settings.",
        "xss": "Encode output and avoid unsafe HTML insertion.",
        "path_traversal": "Canonicalize paths and restrict file operations to allowed roots.",
        "weak_crypto": "Upgrade algorithms and key lengths per current standards.",
        "insecure_deserialization": "Avoid unsafe pickle/yaml.load; use safe formats and schemas.",
        "prototype_pollution": "Freeze objects, validate keys, avoid unsafe merge helpers.",
    }


def _suggested_next_step(v: Vulnerability) -> str:
    if v.remediation and v.remediation.strip():
        line = v.remediation.strip().split("\n", 1)[0].strip()
        return line[:280]
    hints = _default_type_hints()
    return hints.get(v.type.value, "Review finding context; validate exploitability; apply defense in depth.")


def _summary_one_liner(v: Vulnerability) -> str:
    base = (v.title or v.type.value).strip()
    if len(base) > 120:
        base = base[:117] + "..."
    return base


def _sort_for_action_queue(vulns: list[Vulnerability]) -> list[Vulnerability]:
    rank = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }

    def key(v: Vulnerability) -> tuple:
        ti = 0 if _has_threat_intel_match(v) else 1
        return (rank[v.severity], ti, -v.risk_score(), v.file_path, v.line_number)

    return sorted(vulns, key=key)


def build_executive_assessment(result: ScanResult, policy: ExecutivePolicy) -> ExecutiveAssessment:
    """Compute verdict, reasons, and top-N action queue from current findings."""
    vulns = list(result.vulnerabilities)
    reasons: list[str] = []

    if policy.no_go_if_critical and any(v.severity == Severity.CRITICAL for v in vulns):
        reasons.append("One or more critical-severity findings.")

    if policy.no_go_if_high_count_at_least is not None:
        hc = sum(1 for v in vulns if v.severity == Severity.HIGH)
        thr = policy.no_go_if_high_count_at_least
        if hc >= thr:
            reasons.append(
                f"High-severity count ({hc}) meets or exceeds configured threshold ({thr})."
            )

    allowed_types = {t.value for t in VulnerabilityType}
    for vt in policy.no_go_vulnerability_types:
        if vt not in allowed_types:
            continue
        n = sum(1 for v in vulns if v.type.value == vt)
        if n:
            reasons.append(f"Finding(s) of type '{vt}' present ({n}).")

    if policy.risk_score_no_go_at_least is not None:
        rs = result.risk_score()
        thr = policy.risk_score_no_go_at_least
        if rs >= thr:
            reasons.append(
                f"Aggregate risk score ({rs:.1f}) meets or exceeds threshold ({thr:.1f})."
            )

    if policy.no_go_if_threat_intel_match and any(_has_threat_intel_match(v) for v in vulns):
        reasons.append("One or more findings matched external threat-intelligence records.")

    verdict: Verdict = "no_go" if reasons else "go"

    top_n = policy.action_queue_top_n
    action_queue: list[ActionItem] = []
    for v in _sort_for_action_queue(vulns)[:top_n]:
        triage = triage_for_vulnerability(v)
        action_queue.append(
            ActionItem(
                vulnerability_id=v.id,
                file_path=v.file_path,
                line_number=v.line_number,
                title=v.title,
                severity=v.severity.value,
                vulnerability_type=v.type.value,
                triage=triage,
                engine=v.engine,
                summary=_summary_one_liner(v),
                suggested_next_step=_suggested_next_step(v),
            )
        )

    policy_dump = policy.model_dump()
    return ExecutiveAssessment(
        verdict=verdict,
        verdict_reasons=reasons,
        policy=policy_dump,
        action_queue=action_queue,
    )
