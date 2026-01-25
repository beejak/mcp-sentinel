"""
CLI entry point for MCP Sentinel.
"""

import asyncio
import sys
import os
from pathlib import Path
from typing import Optional, Set

import click
import questionary
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcp_sentinel import __version__
from mcp_sentinel.core.multi_engine_scanner import MultiEngineScanner
from mcp_sentinel.core.scanner import Scanner
from mcp_sentinel.engines.base import EngineType, ScanProgress
from mcp_sentinel.models.scan_result import ScanResult
from mcp_sentinel.reporting.generators import HTMLGenerator, SARIFGenerator
from mcp_sentinel.core.logger import setup_logging

console = Console()


@click.group()
@click.option(
    "--log-level", 
    type=click.Choice(["DEBUG", "INFO", "WARN", "ERROR", "FATAL"], case_sensitive=False), 
    default="INFO", 
    help="Set logging level"
)
@click.option(
    "--log-file", 
    type=click.Path(dir_okay=False, writable=True), 
    default=None, 
    help="Log detailed output to file"
)
@click.version_option(version=__version__, prog_name="mcp-sentinel")
def cli(log_level: str, log_file: Optional[str]):
    """
    MCP Sentinel - Multi-Engine Security Scanner for MCP Servers

    4 Analysis Engines (Phase 4.3):
    - Static Analysis: Pattern-based detection (8 specialized detectors)
    - SAST: Semgrep + Bandit industry-standard tools
    - Semantic Analysis: AST-based taint tracking & control flow
    - AI Analysis: Claude 3.5 Sonnet for complex vulnerabilities

    Comprehensive Detection Coverage:
    - Hardcoded Secrets (AWS, API keys, passwords, tokens)
    - Code Injection (SQL, command, eval, template)
    - Prompt Injection & AI manipulation attacks
    - XSS vulnerabilities (DOM, stored, reflected)
    - Configuration security & misconfigurations
    - Path traversal & directory access attacks
    - Tool poisoning & invisible Unicode manipulation
    - Supply chain risks (typosquatting, malicious packages)

    Professional Reporting (4 formats):
    - Terminal: Rich colored output with progress tracking
    - JSON: Structured data for CI/CD integration
    - SARIF 2.1.0: GitHub Code Scanning compatible
    - HTML: Interactive dashboards with risk scoring

    Documentation: https://github.com/beejak/mcp-sentinel
    """
    # Initialize logging before any command runs
    setup_logging(log_level=log_level, log_file=log_file)


@cli.command()
@click.argument("target", type=click.Path(exists=True), required=False)
@click.option(
    "-o",
    "--output",
    type=click.Choice(["terminal", "json", "sarif", "html"]),
    default="terminal",
    help="Output format: terminal (colored, default), json (structured), sarif (GitHub Code Scanning), html (interactive dashboard)",
)
@click.option(
    "--engines",
    type=str,
    default="static,sast",
    help="Comma-separated list of engines to use: 'static' (pattern-based), 'sast' (Semgrep/Bandit), 'semantic' (AST analysis), 'ai' (Claude 3.5), or 'all' (all 4 engines). Default: static,sast. Phase 4.3: All 4 engines available!",
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    multiple=True,
    help="Filter by severity level (can be used multiple times, e.g., --severity critical --severity high)",
)
@click.option(
    "--json-file",
    type=click.Path(),
    help="Output file path for json/sarif/html formats (e.g., report.html, results.sarif, scan.json)",
)
@click.option(
    "--no-progress",
    is_flag=True,
    help="Disable progress output",
)
def scan(
    target: Optional[str], output: str, engines: str, severity: tuple, json_file: str, no_progress: bool
):
    """
    Scan a directory or file for security vulnerabilities.

    TARGET: Path to directory or file to scan (Optional, will prompt if missing)

    Examples:

        \b
        # Quick scan with default engines (static + SAST)
        mcp-sentinel scan .

        \b
        # Full multi-engine scan with all 4 engines
        mcp-sentinel scan . --engines all

        \b
        # AI-powered deep analysis (requires ANTHROPIC_API_KEY)
        mcp-sentinel scan . --engines static,semantic,ai

        \b
        # Generate beautiful HTML report
        mcp-sentinel scan . --output html --json-file report.html

        \b
        # Generate SARIF for GitHub Code Scanning
        mcp-sentinel scan . --output sarif --json-file results.sarif

        \b
        # Filter critical and high severity only
        mcp-sentinel scan . --severity critical --severity high

        \b
        # Production scan: all engines + HTML report + critical/high only
        mcp-sentinel scan . --engines all --severity critical --severity high --output html --json-file production-scan.html

        \b
        # Fast CI scan: static + SAST only
        mcp-sentinel scan . --engines static,sast --output sarif --json-file ci-results.sarif
    """
    # Interactive prompt if target is missing
    if not target:
        target = questionary.path("Target directory to scan:").ask()
        if not target:
            console.print("[red]Operation cancelled.[/red]")
            sys.exit(0)
        
        # Check existence manually since click didn't check it (as it was optional)
        if not Path(target).exists():
            console.print(f"[red]Error: Path '{target}' does not exist.[/red]")
            sys.exit(1)

    # Parse engine selection
    enabled_engines = _parse_engines(engines)

    if not enabled_engines:
        console.print("[red]Error: At least one engine must be specified[/red]")
        raise click.Abort()

    # Show selected engines
    engine_names = [e.value for e in enabled_engines]
    console.print(
        Panel.fit(
            f"[bold cyan]MCP Sentinel v{__version__}[/bold cyan]\n"
            f"Scanning: [yellow]{target}[/yellow]\n"
            f"Engines: [green]{', '.join(engine_names)}[/green]",
            box=box.ROUNDED,
        )
    )

    # Run the scan with progress tracking
    if no_progress:
        with console.status("[bold green]Scanning for vulnerabilities..."):
            result = asyncio.run(_run_scan_multi_engine(target, enabled_engines, None))
    else:
        result = asyncio.run(_run_scan_multi_engine(target, enabled_engines, console))

    # Filter by severity if specified
    if severity:
        severity_set = set(severity)
        result.vulnerabilities = [
            v for v in result.vulnerabilities if v.severity.value in severity_set
        ]
        result.statistics.total_vulnerabilities = len(result.vulnerabilities)

    # Output results
    if output == "terminal":
        _print_terminal_results(result)
    elif output == "json":
        _print_json_results(result, json_file)
    elif output == "sarif":
        _print_sarif_results(result, json_file)
    elif output == "html":
        _print_html_results(result, json_file)

    # Exit code based on findings
    if result.has_critical_findings():
        raise click.Abort()


async def _run_scan(target: str) -> ScanResult:
    """Run the scan asynchronously (legacy - uses old Scanner)."""
    scanner = Scanner()
    return await scanner.scan_directory(target)


def _parse_engines(engines_str: str) -> Set[EngineType]:
    """
    Parse engine selection string into set of EngineType.

    Args:
        engines_str: Comma-separated engine names (e.g., "static,sast,ai" or "all")

    Returns:
        Set of EngineType enums
    """
    engines_str = engines_str.lower().strip()

    # Handle "all" shortcut
    if engines_str == "all":
        return {EngineType.STATIC, EngineType.SEMANTIC, EngineType.SAST, EngineType.AI}

    # Parse comma-separated engines
    enabled = set()
    engine_map = {
        "static": EngineType.STATIC,
        "semantic": EngineType.SEMANTIC,
        "sast": EngineType.SAST,
        "ai": EngineType.AI,
    }

    for engine_name in engines_str.split(","):
        engine_name = engine_name.strip()
        if engine_name in engine_map:
            enabled.add(engine_map[engine_name])
        elif engine_name:  # Ignore empty strings
            console.print(f"[yellow]Warning: Unknown engine '{engine_name}' - ignoring[/yellow]")

    return enabled


async def _run_scan_multi_engine(
    target: str,
    enabled_engines: Set[EngineType],
    console_for_progress: Optional[Console] = None,
) -> ScanResult:
    """
    Run the scan with multiple engines asynchronously.

    Args:
        target: Path to scan
        enabled_engines: Set of engines to enable
        console_for_progress: Console for progress output (None to disable)

    Returns:
        ScanResult with findings from all enabled engines
    """
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

    # Track progress from all engines
    engine_progress = {}

    def progress_callback(engine_name: str, progress: ScanProgress):
        """Update progress for an engine."""
        engine_progress[engine_name] = progress

    # Create scanner with enabled engines
    scanner = MultiEngineScanner(
        enabled_engines=enabled_engines,
        progress_callback=progress_callback if console_for_progress else None,
    )

    # Run scan with progress display
    if console_for_progress:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console_for_progress,
        ) as progress:
            # Create a task for the overall scan
            task_id = progress.add_task(
                f"[cyan]Scanning with {len(enabled_engines)} engine(s)...",
                total=100,
            )

            # Start scan in background
            scan_task = asyncio.create_task(scanner.scan_directory(target))

            # Update progress while scanning
            while not scan_task.done():
                # Calculate average progress across all engines
                if engine_progress:
                    avg_progress = sum(
                        p.progress_percentage for p in engine_progress.values()
                    ) / len(engine_progress)
                    progress.update(task_id, completed=avg_progress)

                await asyncio.sleep(0.1)

            # Get final result
            result = await scan_task
            progress.update(task_id, completed=100)

            return result
    else:
        # No progress display
        return await scanner.scan_directory(target)


def _print_terminal_results(result: ScanResult):
    """Print results to terminal in a nice format."""
    console.print("\n")

    # Summary statistics
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

    # Severity breakdown
    severity_table = Table(title="Vulnerabilities by Severity", box=box.ROUNDED)
    severity_table.add_column("Severity", style="bold")
    severity_table.add_column("Count", justify="right")

    severity_colors = {
        "CRITICAL": "red",
        "HIGH": "orange1",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "green",
    }

    if result.statistics.critical_count > 0:
        severity_table.add_row(
            f"[{severity_colors['CRITICAL']}]CRITICAL[/]",
            f"[{severity_colors['CRITICAL']}]{result.statistics.critical_count}[/]",
        )

    if result.statistics.high_count > 0:
        severity_table.add_row(
            f"[{severity_colors['HIGH']}]HIGH[/]",
            f"[{severity_colors['HIGH']}]{result.statistics.high_count}[/]",
        )

    if result.statistics.medium_count > 0:
        severity_table.add_row(
            f"[{severity_colors['MEDIUM']}]MEDIUM[/]",
            f"[{severity_colors['MEDIUM']}]{result.statistics.medium_count}[/]",
        )

    if result.statistics.low_count > 0:
        severity_table.add_row(
            f"[{severity_colors['LOW']}]LOW[/]",
            f"[{severity_colors['LOW']}]{result.statistics.low_count}[/]",
        )

    if result.statistics.info_count > 0:
        severity_table.add_row(
            f"[{severity_colors['INFO']}]INFO[/]",
            f"[{severity_colors['INFO']}]{result.statistics.info_count}[/]",
        )

    console.print(severity_table)
    console.print("\n")

    # Detailed findings
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
                console.print(f"   [bold green]Steps to Fix:[/bold green]")
                for step in vuln.remediation_steps:
                    console.print(f"   - {step}")

            if vuln.diff:
                console.print(f"   [bold green]Suggested Change:[/bold green]")
                syntax = Syntax(vuln.diff, "diff", theme="monokai", line_numbers=False)
                console.print(syntax)
            elif vuln.fixed_code:
                console.print(f"   [bold green]Fixed Code:[/bold green]")
                console.print(f"[green]{vuln.fixed_code}[/green]")

            console.print()

    # Risk score
    risk_score = result.risk_score()
    risk_color = "red" if risk_score >= 70 else "yellow" if risk_score >= 40 else "green"

    console.print(
        Panel.fit(
            f"[bold]Risk Score: [{risk_color}]{risk_score:.1f}/100[/][/bold]",
            box=box.ROUNDED,
        )
    )

    # Final message
    if result.statistics.total_vulnerabilities == 0:
        console.print("\n[bold green]No vulnerabilities found! [/bold green]")
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
    generator = SARIFGenerator(result)
    sarif_output = generator.generate()

    if output_file:
        try:
            with open(output_file, "w") as f:
                f.write(sarif_output)
            console.print(f"\n[bold green]SARIF report saved to {output_file}[/bold green]")
        except Exception as e:
            console.print(f"\n[bold red]Error saving SARIF report: {e}[/bold red]")
    else:
        print(sarif_output)


def _print_html_results(result: ScanResult, output_file: Optional[str] = None):
    """Print results as HTML."""
    if not output_file:
        console.print("[red]Error: --json-file argument is required for HTML output[/red]")
        return

    generator = HTMLGenerator(result)
    html_output = generator.generate()

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_output)
        console.print(f"\n[bold green]HTML report saved to {output_file}[/bold green]")
    except Exception as e:
        console.print(f"\n[bold red]Error saving HTML report: {e}[/bold red]")


if __name__ == "__main__":
    cli()
