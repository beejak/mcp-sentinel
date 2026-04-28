"""PDF executive summary generator (ReportLab; works on Windows without GTK)."""

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from mcp_sentinel import __version__
from mcp_sentinel.models.executive_assessment import ExecutiveAssessment
from mcp_sentinel.models.scan_result import ScanResult


class PDFGenerator:
    """Generate a compact PDF summary from a ScanResult."""

    _MAX_ROWS = 80

    def generate_story(self, result: ScanResult) -> list:
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            name="SentinelTitle",
            parent=styles["Heading1"],
            fontSize=18,
            spaceAfter=12,
        )
        meta_style = ParagraphStyle(
            name="SentinelMeta",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#444444"),
        )

        story: list = []
        story.append(Paragraph("MCP Sentinel Security Report", title_style))
        story.append(
            Paragraph(
                f"Version {__version__} · Target: {result.target}",
                meta_style,
            )
        )
        story.append(Spacer(1, 0.15 * inch))

        ea = result.executive_assessment
        if isinstance(ea, ExecutiveAssessment):
            vtext = "NO-GO (policy)" if ea.verdict == "no_go" else "GO (policy)"
            vstyle = ParagraphStyle(
                name="VerdictStyle",
                parent=styles["Normal"],
                fontSize=14,
                textColor=colors.HexColor("#c0392b") if ea.verdict == "no_go" else colors.HexColor("#27ae60"),
                spaceAfter=8,
            )
            story.append(Paragraph(f"<b>Executive verdict:</b> {vtext}", vstyle))
            if ea.verdict_reasons:
                story.append(
                    Paragraph(
                        "<b>Reasons:</b> " + "; ".join(ea.verdict_reasons),
                        meta_style,
                    )
                )
            story.append(
                Paragraph(
                    f"<i>{ea.disclaimer}</i>",
                    meta_style,
                )
            )
            story.append(Spacer(1, 0.12 * inch))
            if ea.action_queue:
                aq_rows = [["Triage", "Sev", "Title", "Location", "Next step"]]
                for a in ea.action_queue[:25]:
                    loc = f"{a.file_path}:{a.line_number}"
                    aq_rows.append(
                        [
                            a.triage[:12],
                            a.severity[:8],
                            (a.title or "")[:48],
                            (loc or "")[:56],
                            (a.suggested_next_step or "")[:72],
                        ]
                    )
                aq_tbl = Table(
                    aq_rows,
                    repeatRows=1,
                    colWidths=[0.85 * inch, 0.55 * inch, 1.55 * inch, 1.35 * inch, 2.2 * inch],
                )
                aq_tbl.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                            ("FONTSIZE", (0, 0), (-1, -1), 7),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("LEFTPADDING", (0, 0), (-1, -1), 3),
                        ]
                    )
                )
                story.append(Paragraph("Action queue (top)", styles["Heading2"]))
                story.append(aq_tbl)
                story.append(Spacer(1, 0.15 * inch))

        stats = result.statistics
        summary_data = [
            ["Status", result.status],
            ["Files scanned", str(stats.scanned_files)],
            ["Total findings", str(stats.total_vulnerabilities)],
            ["Critical", str(stats.critical_count)],
            ["High", str(stats.high_count)],
            ["Medium", str(stats.medium_count)],
            ["Low", str(stats.low_count)],
            ["Risk score", f"{result.risk_score():.1f}/100"],
        ]
        tbl = Table(summary_data, colWidths=[2 * inch, 3.5 * inch])
        tbl.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f4f8")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(tbl)
        story.append(Spacer(1, 0.25 * inch))

        story.append(Paragraph("Findings (truncated)", styles["Heading2"]))
        story.append(
            Paragraph(
                f"Showing up to {self._MAX_ROWS} rows. Use HTML or JSON export for the full list.",
                meta_style,
            )
        )
        story.append(Spacer(1, 0.1 * inch))

        vulns = result.vulnerabilities[: self._MAX_ROWS]
        if not vulns:
            story.append(Paragraph("No vulnerabilities in this scan.", styles["Normal"]))
            return story

        rows = [["Severity", "Type", "Title", "Location"]]
        for v in vulns:
            loc = v.file_path or ""
            line = getattr(v, "line_number", None)
            if line:
                loc = f"{loc}:{line}"
            rows.append(
                [
                    getattr(v.severity, "value", str(v.severity)),
                    getattr(v.type, "value", str(v.type)),
                    (v.title or "")[:72],
                    (loc or "")[:96],
                ]
            )

        f_tbl = Table(rows, repeatRows=1, colWidths=[0.85 * inch, 1 * inch, 2.4 * inch, 2.25 * inch])
        f_tbl.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(f_tbl)
        return story

    def save_to_file(self, result: ScanResult, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
        )
        doc.build(self.generate_story(result))
