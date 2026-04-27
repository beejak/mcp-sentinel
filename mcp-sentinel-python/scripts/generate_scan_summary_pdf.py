"""
One-off / manual: build a PDF summary of MCP Sentinel scan JSONs in reports/
and documented ad-hoc runs. Run from repo root:

    python scripts/generate_scan_summary_pdf.py

Output: reports/MCP_SENTINEL_SCAN_HISTORY.pdf
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS = REPO_ROOT / "reports"
OUT_PDF = REPORTS / "MCP_SENTINEL_SCAN_HISTORY.pdf"

# Ephemeral runs (reports deleted after testing) — documented for traceability.
EPHEMERAL_SCANS = [
    {
        "repo": "githejie/mcp-server-calculator",
        "context": "One-off clone; pip install -e; static scan; purged",
        "engines": "static",
        "files": 6,
        "total": 0,
        "critical": 0,
        "high": 0,
    },
    {
        "repo": "beejak/mcp-agent (fork)",
        "context": "Sparse N/A — full fork; pip install -e; static scan; purged",
        "engines": "static",
        "files": 756,
        "total": 134,
        "critical": 11,
        "high": 60,
    },
    {
        "repo": "modelcontextprotocol/servers → src/fetch",
        "context": "Sparse clone; pip install; pytest 19p/1f; static scan; purged",
        "engines": "static",
        "files": 6,
        "total": 0,
        "critical": 0,
        "high": 0,
    },
    {
        "repo": "modelcontextprotocol/servers → src/everything",
        "context": "Sparse clone; npm test 95 passed; node_modules removed; static; purged",
        "engines": "static",
        "files": 48,
        "total": 60,
        "critical": 0,
        "high": None,
    },
    {
        "repo": "modelcontextprotocol/servers → src/filesystem",
        "context": "Sparse clone; npm test 146 passed; node_modules removed; static; purged",
        "engines": "static",
        "files": 19,
        "total": 26,
        "critical": 9,
        "high": None,
    },
]


def load_json_summaries() -> list[dict]:
    rows: list[dict] = []
    for p in sorted(REPORTS.glob("*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        st = data.get("statistics") or {}
        rows.append(
            {
                "repo": p.stem,
                "context": str(data.get("target", ""))[:70],
                "engines": "static (+SAST if used in run)",
                "files": st.get("scanned_files"),
                "total": st.get("total_vulnerabilities"),
                "critical": st.get("critical_count"),
                "high": st.get("high_count"),
            }
        )
    return rows


def fmt_n(v: object) -> str:
    if v is None:
        return "—"
    return str(v)


def build_pdf() -> None:
    REPORTS.mkdir(parents=True, exist_ok=True)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "Title2",
        parent=styles["Title"],
        fontSize=16,
        spaceAfter=12,
    )
    body = styles["Normal"]
    small = ParagraphStyle(
        "Small",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#333333"),
    )

    story: list = []

    story.append(
        Paragraph(
            "MCP Sentinel — Scan history &amp; benchmark summary",
            title_style,
        )
    )
    story.append(
        Paragraph(
            f"Generated (UTC): {datetime.now(UTC).strftime('%Y-%m-%d %H:%M')}Z · "
            f"Package: {REPO_ROOT.name}",
            small,
        )
    )
    story.append(Spacer(1, 0.15 * inch))

    story.append(
        Paragraph(
            "<b>Why the CLI prints &quot;Aborted&quot; on critical findings</b><br/>"
            "After writing JSON/SARIF/HTML or printing to the terminal, the CLI calls "
            "<font name='Courier'>raise click.Abort()</font> when "
            "<font name='Courier'>has_critical_findings()</font> is true. "
            "That sets exit code <b>1</b> so CI jobs fail — the findings are still in the "
            "report file. The word &quot;Aborted&quot; is Click&apos;s default message, not "
            "an indication that reporting was skipped.",
            body,
        )
    )
    story.append(Spacer(1, 0.12 * inch))

    story.append(Paragraph("<b>On-disk JSON reports (reports/*.json)</b>", body))
    disk_rows = load_json_summaries()
    data = [["Report file", "Target (truncated)", "Files", "Total", "Crit", "High"]]
    for r in disk_rows:
        data.append(
            [
                r["repo"],
                r["context"],
                fmt_n(r["files"]),
                fmt_n(r["total"]),
                fmt_n(r["critical"]),
                fmt_n(r["high"]),
            ]
        )
    if len(data) == 1:
        data.append(["(none)", "", "", "", "", ""])

    t = Table(data, colWidths=[1.2 * inch, 2.4 * inch, 0.55 * inch, 0.55 * inch, 0.45 * inch, 0.45 * inch])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4472C4")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(t)
    story.append(Spacer(1, 0.15 * inch))

    story.append(Paragraph("<b>Ephemeral / purged runs (no JSON retained)</b>", body))
    data2 = [["Repository", "Notes", "Files", "Total", "Crit", "High"]]
    for r in EPHEMERAL_SCANS:
        data2.append(
            [
                r["repo"],
                r["context"][:55] + "…" if len(r["context"]) > 55 else r["context"],
                fmt_n(r["files"]),
                fmt_n(r["total"]),
                fmt_n(r["critical"]),
                fmt_n(r["high"]),
            ]
        )
    t2 = Table(data2, colWidths=[1.35 * inch, 2.25 * inch, 0.55 * inch, 0.5 * inch, 0.45 * inch, 0.45 * inch])
    t2.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2E75B6")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(t2)
    story.append(Spacer(1, 0.15 * inch))

    story.append(Paragraph("<b>Scanner performance (high level)</b>", body))
    story.append(
        Paragraph(
            "• <b>Strengths:</b> Fast static pass; good on intentional Python sinks (secrets, exec, traversal) "
            "and MCP-shaped samples (Vulnerable-MCP-Server aligns with detector intent). "
            "JSON/SARIF/HTML suitable for triage.<br/>"
            "• <b>Limits:</b> Pattern heuristics produce false positives on TypeScript "
            "<font name='Courier'>../</font> imports and chat &quot;role&quot; JSON; no runtime/stdio "
            "MCP protocol testing in this Python scanner by default.<br/>"
            "• <b>Gap vs &quot;real world&quot; 2025–2026:</b> supply-chain &amp; OAuth rug-pull patterns, "
            "host-run container escape checks, and model-bundle admission are better covered by "
            "complementary tools (see README &quot;Complementary scanners&quot;).",
            body,
        )
    )
    story.append(Spacer(1, 0.1 * inch))

    story.append(Paragraph("<b>Where to watch for MCP security &amp; scanner ecosystem news</b>", body))
    story.append(
        Paragraph(
            "• MCP spec / servers monorepo: github.com/modelcontextprotocol/servers<br/>"
            "• OWASP LLM / GenAI guidance &amp; Top 10 updates<br/>"
            "• SlowMist MCP Security Checklist (GitHub)<br/>"
            "• Puliczek awesome-mcp-security<br/>"
            "• CVE &amp; GitHub Advisory feeds for npm/PyPI deps used by MCP servers<br/>"
            "• For dynamic/runtime: GarikPetrosyan评测-style tooling, institutional blogs (Anthropic security, "
            "etc.) — incorporate as separate pipeline stages, not only static patterns.",
            body,
        )
    )
    story.append(Spacer(1, 0.1 * inch))

    story.append(Paragraph("<b>Roadmap (from README — verify on main branch)</b>", body))
    story.append(
        Paragraph(
            "• Phase 4.2: Semantic engine (tree-sitter, taint)<br/>"
            "• Phase 4.3: AI-assisted analysis<br/>"
            "• Phase 4.x: SAST normalization (Semgrep/Bandit already partially integrated)<br/>"
            "• Enterprise items in README Roadmap section",
            small,
        )
    )

    doc = SimpleDocTemplate(
        str(OUT_PDF),
        pagesize=letter,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
    )
    doc.build(story)
    print(f"Wrote {OUT_PDF}")


if __name__ == "__main__":
    try:
        build_pdf()
    except Exception as e:
        print(f"Failed: {e}", file=sys.stderr)
        sys.exit(1)
