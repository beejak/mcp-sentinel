"""
CLI entry point for MCP Sentinel.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import click
import questionary
from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from mcp_sentinel import __version__
from mcp_sentinel.core.logger import setup_logging
from mcp_sentinel.core.multi_engine_scanner import MultiEngineScanner
from mcp_sentinel.engines.base import ScanProgress
from mcp_sentinel.models.scan_result import ScanResult
from mcp_sentinel.reporting.generators import ComplianceReportGenerator, SARIFGenerator

console = Console()


@click.group()
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARN", "ERROR", "FATAL"], case_sensitive=False),
    default="INFO",
    help="Logging verbosity. Use DEBUG to trace which files are scanned and which patterns fire. Use WARN/ERROR to suppress informational output in scripts.",
)
@click.option(
    "--log-file",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write logs to a file in addition to stderr. Useful for keeping a machine-readable audit trail while still viewing terminal output.",
)
@click.version_option(version=__version__, prog_name="mcp-sentinel")
def cli(log_level: str, log_file: Optional[str]) -> None:
    """
    MCP Sentinel - Security Scanner for MCP Servers

    Detects security threats in MCP server code using static analysis:
    - Hardcoded secrets (AWS keys, API tokens, passwords, private keys)
    - Code injection (eval, exec, subprocess abuse, SQL f-strings)
    - Prompt injection and AI manipulation attacks
    - Tool poisoning (invisible Unicode, sensitive path targeting, override directives)
    - Path traversal and unsafe file operations
    - Configuration security misconfigurations
    - SSRF (unvalidated URLs in HTTP clients, cloud metadata endpoints)
    - Network binding on all interfaces (0.0.0.0)
    - Missing authentication on routes and endpoints
    - Supply chain attacks (encoded payloads, install-time exfiltration)
    - Weak cryptography (MD5/SHA-1, ECB mode, insecure random, broken ciphers)
    - Insecure deserialization (pickle, yaml.load, ObjectInputStream)

    Output formats: terminal (default), json, sarif (GitHub Code Scanning)

    Compliance: every finding is annotated with its OWASP Agentic AI Top 10
    (ASI01–ASI10) category. Use --compliance-file to export a full ASI coverage
    report alongside your scan results.

    Documentation: https://github.com/beejak/mcp-sentinel
    """
    setup_logging(log_level=log_level, log_file=log_file)


@cli.command()
@click.argument("target", type=click.Path(exists=True), required=False)
@click.option(
    "-o",
    "--output",
    type=click.Choice(["terminal", "json", "sarif"]),
    default="terminal",
    help=(
        "Output format. "
        "'terminal' prints a colour-coded table — best for interactive use. "
        "'json' writes structured findings to --json-file (or stdout) — use this for scripting or feeding results into other tools. "
        "'sarif' writes a SARIF 2.1.0 file — use this for GitHub Code Scanning, GitLab SAST, or Azure DevOps."
    ),
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    multiple=True,
    help=(
        "Only show findings at or matching the given severity. "
        "Repeatable: --severity critical --severity high. "
        "Omit to show all severities. "
        "Useful for hard-gating a CI pipeline on critical/high while reviewing medium/low separately."
    ),
)
@click.option(
    "--json-file",
    type=click.Path(),
    help=(
        "File path to write json or sarif output to. "
        "Required when --output is sarif (for GitHub upload). "
        "If omitted with --output json, findings are printed to stdout."
    ),
)
@click.option(
    "--no-progress",
    is_flag=True,
    help=(
        "Suppress the animated progress bar. "
        "Use this in CI environments to keep logs clean, "
        "or when piping output to another tool."
    ),
)
@click.option(
    "--compliance-file",
    type=click.Path(),
    default=None,
    help=(
        "Write an OWASP Agentic AI Top 10 compliance report (JSON) to this file. "
        "The report lists all ASI01–ASI10 categories with finding counts, "
        "severity breakdown, and coverage gaps. "
        "Compatible with any compliance dashboard that accepts structured JSON."
    ),
)
def scan(
    target: Optional[str],
    output: str,
    severity: tuple[str, ...],
    json_file: str,
    no_progress: bool,
    compliance_file: Optional[str],
) -> None:
    """
    Scan a directory or file for security vulnerabilities.

    TARGET is the path to scan — a directory or a single file. If omitted,
    mcp-sentinel will prompt you interactively.

    Runs 13 pattern-based detectors covering: hardcoded secrets, code
    injection, prompt injection, tool poisoning, path traversal, config
    security, SSRF, network binding, missing auth, supply chain attacks,
    weak cryptography, insecure deserialization, and MCP sampling misuse.
    Every finding is annotated with its OWASP Agentic AI Top 10 (ASI01–ASI10)
    category. Severity is calibrated based on server context (filesystem
    access, network access, STDIO transport).

    \b
    Common workflows:

    \b
      Interactive review (default terminal output):
        mcp-sentinel scan /path/to/mcp-server

    \b
      CI pipeline — fail on critical/high, suppress noise:
        mcp-sentinel scan . --severity critical --severity high --no-progress

    \b
      GitHub Code Scanning integration (upload SARIF to Security tab):
        mcp-sentinel scan . --output sarif --json-file results.sarif

    \b
      Export all findings as JSON for scripting or external tools:
        mcp-sentinel scan . --output json --json-file results.json

    \b
      Scan a single file with debug logging to understand pattern matches:
        mcp-sentinel --log-level debug scan server.py

    \b
      Keep an audit log while reviewing interactively:
        mcp-sentinel --log-file audit.log scan .

    \b
      Export OWASP Agentic AI Top 10 compliance report:
        mcp-sentinel scan . --compliance-file compliance.json
    """
    if not target:
        target = questionary.path("Target directory to scan:").ask()
        if not target:
            console.print("[red]Operation cancelled.[/red]")
            sys.exit(0)

        if not Path(target).exists():
            console.print(f"[red]Error: Path '{target}' does not exist.[/red]")
            sys.exit(1)

    console.print(
        Panel.fit(
            f"[bold cyan]MCP Sentinel v{__version__}[/bold cyan]\n"
            f"Scanning: [yellow]{target}[/yellow]\n"
            f"Engine: [green]static[/green]",
            box=box.ROUNDED,
        )
    )

    if no_progress:
        with console.status("[bold green]Scanning for vulnerabilities..."):
            result = asyncio.run(_run_scan(target, None))
    else:
        result = asyncio.run(_run_scan(target, console))

    if severity:
        severity_set = set(severity)
        result.vulnerabilities = [
            v for v in result.vulnerabilities if v.severity.value in severity_set
        ]
        result.statistics.total_vulnerabilities = len(result.vulnerabilities)

    if output == "terminal":
        _print_terminal_results(result)
    elif output == "json":
        _print_json_results(result, json_file)
    elif output == "sarif":
        _print_sarif_results(result, json_file)

    # Always write compliance report when requested (regardless of output format)
    if compliance_file:
        _write_compliance_report(result, compliance_file)

    if result.has_critical_findings():
        raise click.Abort()


async def _run_scan(
    target: str,
    console_for_progress: Optional[Console] = None,
) -> ScanResult:
    """Run the scan asynchronously."""
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

    engine_progress = {}

    def progress_callback(engine_name: str, progress: ScanProgress) -> None:
        engine_progress[engine_name] = progress

    scanner = MultiEngineScanner(
        progress_callback=progress_callback if console_for_progress else None,
    )

    if console_for_progress:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console_for_progress,
        ) as progress:
            task_id = progress.add_task("[cyan]Scanning...", total=100)
            scan_task = asyncio.create_task(scanner.scan(target))

            while not scan_task.done():
                if engine_progress:
                    avg_progress = sum(
                        p.progress_percentage for p in engine_progress.values()
                    ) / len(engine_progress)
                    progress.update(task_id, completed=avg_progress)
                await asyncio.sleep(0.1)

            result = await scan_task
            progress.update(task_id, completed=100)
            return result
    else:
        return await scanner.scan(target)


def _print_terminal_results(result: ScanResult) -> None:
    """Print results to terminal."""
    console.print("\n")

    summary_table = Table(title="Scan Summary", box=box.ROUNDED)
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="yellow")

    summary_table.add_row("Target", result.target)
    summary_table.add_row("Status", result.status.upper())
    summary_table.add_row(
        "Files Scanned", f"{result.statistics.scanned_files}/{result.statistics.total_files}"
    )
    summary_table.add_row("Duration", f"{result.statistics.scan_duration_seconds:.2f}s")
    summary_table.add_row("Total Vulnerabilities", str(result.statistics.total_vulnerabilities))

    console.print(summary_table)
    console.print("\n")

    severity_colors = {
        "CRITICAL": "red",
        "HIGH": "orange1",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "green",
    }

    severity_table = Table(title="Vulnerabilities by Severity", box=box.ROUNDED)
    severity_table.add_column("Severity", style="bold")
    severity_table.add_column("Count", justify="right")

    for level, count in [
        ("CRITICAL", result.statistics.critical_count),
        ("HIGH", result.statistics.high_count),
        ("MEDIUM", result.statistics.medium_count),
        ("LOW", result.statistics.low_count),
        ("INFO", result.statistics.info_count),
    ]:
        if count > 0:
            color = severity_colors[level]
            severity_table.add_row(
                f"[{color}]{level}[/]",
                f"[{color}]{count}[/]",
            )

    console.print(severity_table)
    console.print("\n")

    # OWASP Agentic AI Top 10 summary (only when there are findings)
    if result.vulnerabilities:
        _print_owasp_summary(result.vulnerabilities)

    if result.vulnerabilities:
        console.print("[bold]Detailed Findings:[/bold]\n")

        for i, vuln in enumerate(result.vulnerabilities, 1):
            severity_color = severity_colors.get(vuln.severity.value.upper(), "white")

            console.print(
                f"[bold]{i}. [{severity_color}]{vuln.severity.value.upper()}[/][/bold] - {escape(vuln.title)}"
            )
            console.print(f"   File: [cyan]{escape(vuln.file_path)}:{vuln.line_number}[/cyan]")
            console.print(f"   {escape(vuln.description)}")

            if vuln.code_snippet:
                console.print(f"   Code: [dim]{escape(vuln.code_snippet)}[/dim]")

            if vuln.remediation:
                console.print(f"   [bold green]Remediation:[/bold green] {escape(vuln.remediation)}")

            if vuln.remediation_steps:
                console.print("   [bold green]Steps to Fix:[/bold green]")
                for step in vuln.remediation_steps:
                    console.print(f"   - {escape(step)}")

            if vuln.diff:
                console.print("   [bold green]Suggested Change:[/bold green]")
                syntax = Syntax(vuln.diff, "diff", theme="monokai", line_numbers=False)
                console.print(syntax)

            console.print()

    risk_score = result.risk_score()
    risk_color = "red" if risk_score >= 70 else "yellow" if risk_score >= 40 else "green"

    console.print(
        Panel.fit(
            f"[bold]Risk Score: [{risk_color}]{risk_score:.1f}/100[/][/bold]",
            box=box.ROUNDED,
        )
    )

    if result.statistics.total_vulnerabilities == 0:
        console.print("\n[bold green]No vulnerabilities found![/bold green]")
    else:
        console.print(
            f"\n[bold yellow]Found {result.statistics.total_vulnerabilities} vulnerabilities[/bold yellow]"
        )


def _print_owasp_summary(vulnerabilities: list) -> None:
    """Print a compact OWASP Agentic AI Top 10 category breakdown."""
    from mcp_sentinel.models.owasp_mapping import build_compliance_summary

    summary = build_compliance_summary(vulnerabilities)
    if not summary:
        return

    owasp_table = Table(title="OWASP Agentic AI Top 10 Coverage", box=box.ROUNDED)
    owasp_table.add_column("ASI ID", style="cyan", width=7)
    owasp_table.add_column("Category", style="bold")
    owasp_table.add_column("Findings", justify="right")
    owasp_table.add_column("Max Severity", justify="center")

    severity_colors = {
        "critical": "red",
        "high": "orange1",
        "medium": "yellow",
        "low": "blue",
        "info": "green",
    }

    for asi_id in sorted(summary.keys()):
        cat = summary[asi_id]
        count = int(cat["count"])
        # Determine max severity
        max_sev = None
        for sev in ("critical", "high", "medium", "low", "info"):
            if int(cat.get(sev, 0)) > 0:
                max_sev = sev
                break
        color = severity_colors.get(max_sev or "", "white")
        owasp_table.add_row(
            asi_id,
            str(cat["name"]),
            str(count),
            f"[{color}]{(max_sev or '').upper()}[/]" if max_sev else "-",
        )

    console.print(owasp_table)
    console.print("\n")


def _write_compliance_report(result: ScanResult, output_file: str) -> None:
    """Write OWASP Agentic AI Top 10 compliance report as JSON."""
    generator = ComplianceReportGenerator()
    report = generator.generate(
        vulnerabilities=result.vulnerabilities,
        target=result.target,
        scan_id=result.scan_id if hasattr(result, "scan_id") else None,
    )
    try:
        with open(output_file, "w") as f:
            f.write(json.dumps(report, indent=2))
        console.print(
            f"\n[bold green]OWASP compliance report saved to {output_file}[/bold green]"
        )
    except Exception as e:
        console.print(f"\n[bold red]Error saving compliance report: {e}[/bold red]")


def _print_json_results(result: ScanResult, output_file: Optional[str] = None) -> None:
    """Print results as JSON."""
    json_output = result.model_dump_json(indent=2)

    if output_file:
        try:
            with open(output_file, "w") as f:
                f.write(json_output)
            console.print(f"\n[bold green]JSON report saved to {output_file}[/bold green]")
        except Exception as e:
            console.print(f"\n[bold red]Error saving JSON report: {e}[/bold red]")
    else:
        print(json_output)


def _print_sarif_results(result: ScanResult, output_file: Optional[str] = None) -> None:
    """Print results as SARIF."""
    generator = SARIFGenerator()
    sarif_output = generator.generate(result)

    if isinstance(sarif_output, dict):
        sarif_str = json.dumps(sarif_output, indent=2)
    else:
        sarif_str = str(sarif_output)

    if output_file:
        try:
            with open(output_file, "w") as f:
                f.write(sarif_str)
            console.print(f"\n[bold green]SARIF report saved to {output_file}[/bold green]")
        except Exception as e:
            console.print(f"\n[bold red]Error saving SARIF report: {e}[/bold red]")
    else:
        click.echo(sarif_str)


if __name__ == "__main__":
    cli()
