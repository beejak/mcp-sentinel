"""CLI scan exit behavior (critical findings vs --no-fail-on-critical)."""

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
