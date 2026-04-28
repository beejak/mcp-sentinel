"""Pydantic models for rule-based executive decision support (Go / No-Go)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

DISCLAIMER = (
    "Decision support only: based on static/SAST rules and configured thresholds. "
    "Not a guarantee of security or production readiness. Review false positives and "
    "complement with dynamic testing and threat modeling as appropriate."
)

TriageLabel = Literal["prioritize", "review", "informational"]
Verdict = Literal["go", "no_go"]


class ExecutivePolicy(BaseModel):
    """Configurable Go / No-Go rules (YAML-serializable)."""

    model_config = ConfigDict(extra="ignore")

    no_go_if_critical: bool = True
    no_go_if_high_count_at_least: int | None = None
    no_go_vulnerability_types: list[str] = Field(default_factory=list)
    risk_score_no_go_at_least: float | None = None
    no_go_if_threat_intel_match: bool = False
    action_queue_top_n: int = Field(default=10, ge=1, le=500)


class ActionItem(BaseModel):
    """One prioritized row for remediation focus."""

    model_config = ConfigDict(extra="ignore")

    vulnerability_id: str
    file_path: str
    line_number: int
    title: str
    severity: str
    vulnerability_type: str
    triage: TriageLabel
    engine: str
    summary: str
    suggested_next_step: str


class ExecutiveAssessment(BaseModel):
    """Structured executive block for JSON / HTML / PDF."""

    model_config = ConfigDict(extra="ignore")

    verdict: Verdict
    verdict_reasons: list[str] = Field(default_factory=list)
    triage_legend: dict[str, str] = Field(
        default_factory=lambda: {
            "prioritize": "Address before release or treat as release blocker per policy.",
            "review": "Schedule validation; may be acceptable with compensating controls.",
            "informational": "Lower urgency; track for hygiene or noise review.",
        }
    )
    disclaimer: str = DISCLAIMER
    policy: dict[str, Any] = Field(default_factory=dict)
    action_queue: list[ActionItem] = Field(default_factory=list)
