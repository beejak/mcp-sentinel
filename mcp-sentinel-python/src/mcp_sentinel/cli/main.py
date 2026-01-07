"""
CLI entry point for MCP Sentinel.
"""

import click
import asyncio
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from mcp_sentinel import __version__
from mcp_sentinel.core.scanner import Scanner
from mcp_sentinel.core.multi_engine_scanner import MultiEngineScanner
from mcp_sentinel.engines.base import EngineType, ScanProgress
from mcp_sentinel.models.scan_result import ScanResult
from mcp_sentinel.models.vulnerability import Severity


console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="mcp-sentinel")
def cli():
    """
    MCP Sentinel - Enterprise Security Scanner for MCP Servers

    Scan your codebase for security vulnerabilities including hardcoded secrets,
    code injection, prompt injection, and more.
    """
    pass


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option(
    "-o",
    "--output",
    type=click.Choice(["terminal", "json", "sarif", "html"]),
    default="terminal",
    help="Output format",
)
@click.option(
    "--engines",
    type=str,
    default="static",
    help="Comma-separated list of engines to use (static, semantic, sast, ai, all). Default: static",
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    multiple=True,
    help="Filter by severity (can be used multiple times)",
)
@click.option(
    "--json-file",
    type=click.Path(),
    help="Output JSON results to file",
)
@click.option(
    "--no-progress",
    is_flag=True,
    help="Disable progress output",
)
def scan(target: str, output: str, engines: str, severity: tuple, json_file: str, no_progress: bool):
    """
    Scan a directory or file for security vulnerabilities.

    TARGET: Path to directory or file to scan

    Examples:

        \b
        # Scan current directory with static engine
        mcp-sentinel scan .

        \b
        # Scan with multiple engines
        mcp-sentinel scan . --engines static,sast

        \b
        # Scan with JSON output
        mcp-sentinel scan /path/to/project --output json

        \b
        # Filter critical and high severity only
        mcp-sentinel scan . --severity critical --severity high
    """
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
        console.print("[yellow]SARIF output not yet implemented[/yellow]")
    elif output == "html":
        console.print("[yellow]HTML output not yet implemented[/yellow]")

    # Exit code based on findings
    if result.has_critical_findings():
        raise click.Abort()


async def _run_scan(target: str) -> ScanResult:
    """Run the scan asynchronously (legacy - uses old Scanner)."""
    scanner = Scanner()
    return await scanner.scan_directory(target)


def _parse_engines(engines_str: str) -> set[EngineType]:
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
    enabled_engines: set[EngineType],
    console_for_progress: Console | None = None,
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
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

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
    summary_table.add_row("Files Scanned", f"{result.statistics.scanned_files}/{result.statistics.total_files}")
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


def _print_json_results(result: ScanResult, output_file: str | None = None):
    """Print results as JSON."""
    import json

    json_output = result.model_dump_json(indent=2)

    if output_file:
        with open(output_file, "w") as f:
            f.write(json_output)
        console.print(f"[green]Results saved to {output_file}[/green]")
    else:
        console.print(json_output)


@cli.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=8000, help="Port to bind to")
@click.option("--reload", is_flag=True, help="Enable auto-reload (development)")
def server(host: str, port: int, reload: bool):
    """
    Start the MCP Sentinel API server.

    This starts a FastAPI server that provides REST and GraphQL APIs
    for scanning, reporting, and integrations.

    Examples:

        \b
        # Start server on default port
        mcp-sentinel server

        \b
        # Start with auto-reload for development
        mcp-sentinel server --reload

        \b
        # Start on custom port
        mcp-sentinel server --port 9000
    """
    import uvicorn

    console.print(
        Panel.fit(
            f"[bold cyan]Starting MCP Sentinel API Server[/bold cyan]\n"
            f"Host: [yellow]{host}[/yellow]\n"
            f"Port: [yellow]{port}[/yellow]\n"
            f"Docs: [blue]http://{host if host != '0.0.0.0' else 'localhost'}:{port}/docs[/blue]",
            box=box.ROUNDED,
        )
    )

    uvicorn.run(
        "mcp_sentinel.api.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


@cli.command()
def version():
    """Show version information."""
    console.print(f"[bold cyan]MCP Sentinel[/bold cyan] version [yellow]{__version__}[/yellow]")


@cli.command()
def init():
    """
    Initialize MCP Sentinel configuration.

    Creates a .mcp-sentinel.yaml configuration file in the current directory
    with default settings.
    """
    config_content = """# MCP Sentinel Configuration

# Analysis engines to enable
engines:
  static: true
  semantic: true
  sast: true
  ai: false  # Requires API keys

# AI provider configuration (if enabled)
ai:
  provider: anthropic  # openai, anthropic, google, ollama
  model: claude-3-5-sonnet-20241022
  # api_key: ${ANTHROPIC_API_KEY}

# Reporting
reporting:
  formats: [terminal, json]
  output_dir: ./reports

# Performance
performance:
  max_workers: 4
  cache_enabled: true
  parallel_execution: true
"""

    config_path = Path(".mcp-sentinel.yaml")

    if config_path.exists():
        console.print("[yellow]Configuration file already exists![/yellow]")
        if not click.confirm("Overwrite?"):
            return

    with open(config_path, "w") as f:
        f.write(config_content)

    console.print(f"[green]Created configuration file: {config_path}[/green]")


if __name__ == "__main__":
    cli()
