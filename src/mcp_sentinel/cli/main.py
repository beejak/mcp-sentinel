"""
CLI entry point for MCP Sentinel.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional, Set

import click
import questionary
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from mcp_sentinel import __version__
from mcp_sentinel.core.logger import setup_logging
from mcp_sentinel.core.multi_engine_scanner import MultiEngineScanner
from mcp_sentinel.engines.base import EngineType, ScanProgress
from mcp_sentinel.models.scan_result import ScanResult
from mcp_sentinel.reporting.generators import SARIFGenerator

console = Console()


@click.group()
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARN", "ERROR", "FATAL"], case_sensitive=False),
    default="INFO",
    help="Set logging level",
)
@click.option(
    "--log-file",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Log detailed output to file",
)
@click.version_option(version=__version__, prog_name="mcp-sentinel")
def cli(log_level: str, log_file: Optional[str]):
    """
    MCP Sentinel - Security Scanner for MCP Servers

    Detects security threats in MCP server code using static analysis:
    - Hardcoded secrets (AWS keys, API tokens, passwords)
    - Prompt injection and AI manipulation attacks
    - Tool poisoning (invisible Unicode, homoglyphs, RTLO)
    - Code injection (eval, exec, subprocess abuse)
    - Path traversal and unsafe file operations
    - Configuration security misconfigurations

    Output formats: terminal (default), json, sarif (GitHub Code Scanning)

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
    help="Output format: terminal (colored, default), json (structured), sarif (GitHub Code Scanning)",
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    multiple=True,
    help="Filter by severity level (can be used multiple times)",
)
@click.option(
    "--json-file",
    type=click.Path(),
    help="Output file path for json/sarif formats (e.g., results.sarif, scan.json)",
)
@click.option(
    "--no-progress",
    is_flag=True,
    help="Disable progress output",
)
def scan(
    target: Optional[str],
    output: str,
    severity: tuple,
    json_file: str,
    no_progress: bool,
):
    """
    Scan a directory or file for security vulnerabilities.

    TARGET: Path to directory or file to scan (optional, will prompt if missing)

    Examples:

        \b
        # Scan current directory
        mcp-sentinel scan .

        \b
        # Generate SARIF for GitHub Code Scanning
        mcp-sentinel scan . --output sarif --json-file results.sarif

        \b
        # Filter critical and high severity only
        mcp-sentinel scan . --severity critical --severity high

        \b
        # Output structured JSON
        mcp-sentinel scan . --output json --json-file scan.json
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

    if result.has_critical_findings():
        raise click.Abort()


async def _run_scan(
    target: str,
    console_for_progress: Optional[Console] = None,
) -> ScanResult:
    """Run the scan asynchronously."""
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

    engine_progress = {}

    def progress_callback(engine_name: str, progress: ScanProgress):
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


def _print_terminal_results(result: ScanResult):
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

    if result.vulnerabilities:
        console.print("[bold]Detailed Findings:[/bold]\n")

        for i, vuln in enumerate(result.vulnerabilities, 1):
            severity_color = severity_colors.get(vuln.severity.value.upper(), "white")

            console.print(
                f"[bold]{i}. [{severity_color}]{vuln.severity.value.upper()}[/][/bold] - {vuln.title}"
            )
            console.print(f"   File: [cyan]{vuln.file_path}:{vuln.line_number}[/cyan]")
            console.print(f"   {vuln.description}")

            if vuln.code_snippet:
                console.print(f"   Code: [dim]{vuln.code_snippet}[/dim]")

            if vuln.remediation:
                console.print(f"   [bold green]Remediation:[/bold green] {vuln.remediation}")

            if vuln.remediation_steps:
                console.print("   [bold green]Steps to Fix:[/bold green]")
                for step in vuln.remediation_steps:
                    console.print(f"   - {step}")

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


def _print_json_results(result: ScanResult, output_file: Optional[str] = None):
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


def _print_sarif_results(result: ScanResult, output_file: Optional[str] = None):
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
