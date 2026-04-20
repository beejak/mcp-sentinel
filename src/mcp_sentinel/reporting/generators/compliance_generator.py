"""
OWASP Agentic AI Top 10 Compliance Report Generator.

Produces a structured JSON-serialisable summary showing which ASI categories
have findings, their severity breakdown, and which categories have no detector
coverage.

Example output structure::

    {
      "framework": "OWASP Agentic AI Top 10 2026",
      "generated_at": "2026-03-24T12:00:00Z",
      "scan_target": "/path/to/server",
      "total_findings": 7,
      "categories": {
        "ASI01": {
          "name": "Prompt Injection",
          "description": "...",
          "finding_count": 3,
          "max_severity": "HIGH",
          "severity_breakdown": {"critical": 0, "high": 2, "medium": 1, "low": 0, "info": 0},
          "has_detector": true
        },
        ...
        "ASI09": {
          "name": "Improper Error Handling / Path Traversal",
          "description": "...",
          "finding_count": 0,
          "max_severity": null,
          "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
          "has_detector": true,
          "note": "No findings in this scan"
        }
      },
      "summary": {
        "categories_with_findings": 4,
        "categories_with_detectors": 10,
        "categories_without_detectors": [],
        "risk_distribution": {"critical": 1, "high": 4, "medium": 2, "low": 0, "info": 0}
      }
    }
"""

from datetime import datetime, timezone
from typing import Any, Optional

from mcp_sentinel.models.owasp_mapping import OWASP_ASI_CATALOGUE
from mcp_sentinel.models.vulnerability import Severity

# ASI categories that have at least one detector in this version
_CATEGORIES_WITH_DETECTORS: frozenset[str] = frozenset(OWASP_ASI_CATALOGUE.keys())

_SEVERITY_ORDER: list[str] = ["critical", "high", "medium", "low", "info"]


class ComplianceReportGenerator:
    """
    Generate an OWASP Agentic AI Top 10 compliance summary.

    Usage::

        generator = ComplianceReportGenerator()
        report = generator.generate(scan_result)
        # report is a plain dict — serialise with json.dumps(report)
    """

    def generate(
        self,
        vulnerabilities: list,  # list[Vulnerability] — avoids circular import
        target: Optional[str] = None,
        scan_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Build and return the compliance report dict.

        Args:
            vulnerabilities: All findings from the scan (may be pre-filtered by severity).
            target: Scan target path string (for metadata only).
            scan_id: Optional scan identifier.
        """
        categories: dict[str, dict[str, Any]] = {}

        # Initialise all ASI categories
        for asi_id, info in sorted(OWASP_ASI_CATALOGUE.items()):
            categories[asi_id] = {
                "name": info["name"],
                "description": info["description"],
                "finding_count": 0,
                "max_severity": None,
                "severity_breakdown": {s: 0 for s in _SEVERITY_ORDER},
                "has_detector": asi_id in _CATEGORIES_WITH_DETECTORS,
            }

        # Tally findings
        for vuln in vulnerabilities:
            asi_id = vuln.owasp_asi_id
            if not asi_id or asi_id not in categories:
                continue

            cat = categories[asi_id]
            cat["finding_count"] += 1

            sev = vuln.severity.value.lower()
            cat["severity_breakdown"][sev] = cat["severity_breakdown"].get(sev, 0) + 1

            # Track max severity
            if cat["max_severity"] is None:
                cat["max_severity"] = sev
            else:
                current_idx = _SEVERITY_ORDER.index(cat["max_severity"])
                new_idx = _SEVERITY_ORDER.index(sev)
                if new_idx < current_idx:  # lower index = higher severity
                    cat["max_severity"] = sev

        # Add notes for zero-finding categories
        for asi_id, cat in categories.items():
            if cat["finding_count"] == 0:
                if cat["has_detector"]:
                    cat["note"] = "No findings in this scan — detectors active"
                else:
                    cat["note"] = "No detector for this category"

        # Summary statistics
        categories_with_findings = sum(
            1 for c in categories.values() if c["finding_count"] > 0
        )
        categories_without_detectors = [
            asi_id for asi_id, c in categories.items() if not c["has_detector"]
        ]
        risk_distribution: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
        for vuln in vulnerabilities:
            sev = vuln.severity.value.lower()
            risk_distribution[sev] = risk_distribution.get(sev, 0) + 1

        return {
            "framework": "OWASP Agentic AI Top 10 2026",
            "framework_url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_target": target or "",
            "scan_id": scan_id or "",
            "total_findings": len(vulnerabilities),
            "categories": categories,
            "summary": {
                "categories_with_findings": categories_with_findings,
                "categories_with_detectors": len(_CATEGORIES_WITH_DETECTORS),
                "categories_without_detectors": categories_without_detectors,
                "risk_distribution": risk_distribution,
            },
        }


def _severity_score(sev_str: Optional[str]) -> int:
    """Return a sortable score — lower is more severe (used for max tracking)."""
    if sev_str is None:
        return 999
    try:
        return _SEVERITY_ORDER.index(sev_str)
    except ValueError:
        return 999
