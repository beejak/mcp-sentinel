"""CLI scan exit behavior (critical findings and tool baseline workflow)."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_sentinel.cli.main import cli


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def tmp_with_critical_exec(tmp_path: Path) -> Path:
    """Minimal Python that triggers CodeInjection exec() → CRITICAL."""
    p = tmp_path / "sink.py"
    p.write_text("def f(u):\n    exec(u)\n", encoding="utf-8")
    return tmp_path


def test_scan_fails_exit_on_critical_by_default(runner: CliRunner, tmp_with_critical_exec: Path):
    out = tmp_with_critical_exec / "out.json"
    result = runner.invoke(
        cli,
        [
            "scan",
            str(tmp_with_critical_exec),
            "--engines",
            "static",
            "--output",
            "json",
            "--json-file",
            str(out),
            "--no-progress",
        ],
    )
    assert result.exit_code != 0
    assert out.is_file()


def test_scan_no_fail_on_critical_exits_zero(runner: CliRunner, tmp_with_critical_exec: Path):
    out = tmp_with_critical_exec / "out2.json"
    result = runner.invoke(
        cli,
        [
            "scan",
            str(tmp_with_critical_exec),
            "--engines",
            "static",
            "--output",
            "json",
            "--json-file",
            str(out),
            "--no-progress",
            "--no-fail-on-critical",
        ],
    )
    assert result.exit_code == 0
    assert out.is_file()


def test_scan_tool_baseline_update_and_alerts(runner: CliRunner, tmp_path: Path):
    (tmp_path / "safe.py").write_text("print('ok')\n", encoding="utf-8")
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        """
{
  "mcpServers": {
    "filesystem": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "/tmp"]}
  }
}
""".strip(),
        encoding="utf-8",
    )

    out1 = tmp_path / "first.json"
    result1 = runner.invoke(
        cli,
        [
            "scan",
            str(tmp_path),
            "--engines",
            "static",
            "--output",
            "json",
            "--json-file",
            str(out1),
            "--no-progress",
            "--update-tool-baseline",
        ],
    )
    assert result1.exit_code == 0
    assert (tmp_path / ".mcp-sentinel-tool-baseline.json").is_file()

    cfg.write_text(
        """
{
  "mcpServers": {
    "filesystem": {"command": "uvx", "args": ["@modelcontextprotocol/server-filesystem", "/tmp"]}
  }
}
""".strip(),
        encoding="utf-8",
    )

    out2 = tmp_path / "second.json"
    result2 = runner.invoke(
        cli,
        [
            "scan",
            str(tmp_path),
            "--engines",
            "static",
            "--output",
            "json",
            "--json-file",
            str(out2),
            "--no-progress",
        ],
    )
    assert result2.exit_code == 0
    payload = json.loads(out2.read_text(encoding="utf-8"))
    assert payload["config"]["tool_definition_changes"]["changed"] == 1
    assert any(
        v["detector"] == "ToolDefinitionVersioning" for v in payload["vulnerabilities"]
    )


def test_scan_writes_pdf(runner: CliRunner, tmp_path: Path):
    (tmp_path / "safe.py").write_text("print('ok')\n", encoding="utf-8")
    out_pdf = tmp_path / "report.pdf"
    result = runner.invoke(
        cli,
        [
            "scan",
            str(tmp_path),
            "--engines",
            "static",
            "--output",
            "pdf",
            "--json-file",
            str(out_pdf),
            "--no-progress",
            "--no-fail-on-critical",
        ],
    )
    assert result.exit_code == 0
    assert out_pdf.is_file()
    assert out_pdf.stat().st_size > 500


def test_scan_html_and_extra_pdf(runner: CliRunner, tmp_path: Path):
    (tmp_path / "safe.py").write_text("print('ok')\n", encoding="utf-8")
    html_out = tmp_path / "report.html"
    pdf_out = tmp_path / "summary.pdf"
    result = runner.invoke(
        cli,
        [
            "scan",
            str(tmp_path),
            "--engines",
            "static",
            "--output",
            "html",
            "--json-file",
            str(html_out),
            "--pdf-file",
            str(pdf_out),
            "--no-progress",
            "--no-fail-on-critical",
        ],
    )
    assert result.exit_code == 0
    assert html_out.is_file()
    assert pdf_out.is_file()


def test_scan_generates_incident_summary_by_default(
    runner: CliRunner, tmp_with_critical_exec: Path
):
    out = tmp_with_critical_exec / "critical.json"
    incidents = tmp_with_critical_exec / "critical-incidents.md"
    result = runner.invoke(
        cli,
        [
            "scan",
            str(tmp_with_critical_exec),
            "--engines",
            "static",
            "--output",
            "json",
            "--json-file",
            str(out),
            "--no-progress",
            "--no-fail-on-critical",
        ],
    )
    assert result.exit_code == 0
    assert out.is_file()
    assert incidents.is_file()
    body = incidents.read_text(encoding="utf-8")
    assert "MCP Sentinel Incident Summary" in body
    assert "code injection class" in body
