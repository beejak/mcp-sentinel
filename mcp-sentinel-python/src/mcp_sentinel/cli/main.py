"""
CLI entry point for MCP Sentinel.
"""

import asyncio
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from mcp_sentinel import __version__
from mcp_sentinel.core.multi_engine_scanner import MultiEngineScanner
from mcp_sentinel.core.scanner import Scanner
from mcp_sentinel.engines.base import EngineType, ScanProgress
from mcp_sentinel.models.executive_assessment import ExecutiveAssessment
from mcp_sentinel.models.scan_result import ScanResult
from mcp_sentinel.reporting.generators import (
    HTMLGenerator,
    IncidentSummaryGenerator,
    PDFGenerator,
    SARIFGenerator,
)

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="mcp-sentinel")
def cli():
    """
    MCP Sentinel - Enterprise Security Scanner for MCP Servers.

    Comprehensive security scanning with 9 specialized detectors covering:
    secrets, code injection, prompt injection, XSS, configuration issues,
    path traversal, tool poisoning, and supply chain risks.

    Reporting: terminal, JSON, SARIF 2.1.0, HTML, and PDF summaries.

    Use ``mcp-sentinel --version`` for the build version.
    Documentation: https://github.com/beejak/mcp-sentinel
    """
    pass


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option(
    "-o",
    "--output",
    type=click.Choice(["terminal", "json", "sarif", "html", "pdf"]),
    default="terminal",
    help="Output format: terminal (default), json, sarif, html (dashboard), pdf (executive summary)",
)
@click.option(
    "--engines",
    type=str,
    default="static,sast",
    help="Comma-separated list of engines to use (static, sast, semantic, ai, all). Default: static,sast. Phase 4.1: SAST engine available (Semgrep + Bandit)",
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
    help="Output file path for json/sarif/html/pdf (e.g., report.html, results.sarif, scan.json, report.pdf)",
)
@click.option(
    "--pdf-file",
    type=click.Path(),
    default=None,
    help="Also write a PDF executive summary to this path (in addition to the primary --output).",
)
@click.option(
    "--incident-summary/--no-incident-summary",
    default=True,
    show_default=True,
    help="Write markdown incident summary for critical/RCE/exploit-likely findings.",
)
@click.option(
    "--incident-file",
    type=click.Path(),
    default=None,
    help="Output path for incident summary markdown. Defaults near --json-file if set.",
)
@click.option(
    "--no-progress",
    is_flag=True,
    help="Disable progress output",
)
@click.option(
    "--no-fail-on-critical",
    is_flag=True,
    help="Exit with code 0 even when critical findings exist (reports are still written). "
    "Default: exit 1 on critical for CI.",
)
@click.option(
    "--tool-baseline-file",
    type=click.Path(),
    help="Optional path to MCP tool-definition baseline JSON. "
    "Defaults to <target>/.mcp-sentinel-tool-baseline.json.",
)
@click.option(
    "--update-tool-baseline",
    is_flag=True,
    help="Write/update the MCP tool-definition baseline after scan completes.",
)
@click.option(
    "--executive-policy",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="YAML file for Go/No-Go policy (optional; defaults: no-go on critical).",
)
@click.option(
    "--executive-top-n",
    type=int,
    default=None,
    help="Override size of the prioritized action queue (default: 10 or from policy).",
)
@click.option(
    "--no-executive-assessment",
    is_flag=True,
    help="Skip executive decision / action queue (not added to JSON, HTML, PDF).",
)
def scan(
    target: str,
    output: str,
    engines: str,
    severity: tuple,
    json_file: str,
    pdf_file: str | None,
    incident_summary: bool,
    incident_file: str | None,
    no_progress: bool,
    no_fail_on_critical: bool,
    tool_baseline_file: str | None,
    update_tool_baseline: bool,
    executive_policy: Path | None,
    executive_top_n: int | None,
    no_executive_assessment: bool,
):
    """
    Scan a directory or file for security vulnerabilities.

    TARGET: Path to directory or file to scan

    Examples:

        \b
        # Scan current directory with terminal output (default)
        mcp-sentinel scan .

        \b
        # Generate beautiful HTML report
        mcp-sentinel scan . --output html --json-file report.html

        \b
        # Generate SARIF for GitHub Code Scanning
        mcp-sentinel scan . --output sarif --json-file results.sarif

        \b
        # Generate JSON structured output
        mcp-sentinel scan /path/to/project --output json --json-file scan.json

        \b
        # Filter critical and high severity only
        mcp-sentinel scan . --severity critical --severity high --output html --json-file critical-issues.html

        \b
        # Scan with multiple engines (Phase 4+)
        mcp-sentinel scan . --engines static,sast --output html --json-file report.html

        \b
        # Do not fail CI exit code when critical findings exist (reports still written)
        mcp-sentinel scan . --output json --json-file out.json --no-fail-on-critical

        \b
        # HTML dashboard plus PDF executive summary in one run
        mcp-sentinel scan . --engines static,sast --output html --json-file report.html --pdf-file summary.pdf

        \b
        # Write incident/exploitability summary markdown (default on)
        mcp-sentinel scan . --output json --json-file out.json --incident-file incidents.md

        \b
        # Executive Go/No-Go + action queue in reports (default on; YAML policy optional)
        mcp-sentinel scan . --output html --json-file report.html --executive-policy policy.yaml
    """
    # Parse engine selection
    enabled_engines = _parse_engines(engines)

    if not enabled_engines:
        console.print("[red]Error: At least one engine must be specified[/red]")
        raise click.Abort()

    _warn_unwired_engines(enabled_engines)

    if output in ("json", "sarif", "html", "pdf") and not json_file:
        console.print(
            f"[red]Error: --output {output} requires --json-file PATH[/red]"
        )
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
            result = asyncio.run(
                _run_scan_multi_engine(
                    target,
                    enabled_engines,
                    None,
                    tool_baseline_file=tool_baseline_file,
                    update_tool_baseline=update_tool_baseline,
                )
            )
    else:
        result = asyncio.run(
            _run_scan_multi_engine(
                target,
                enabled_engines,
                console,
                tool_baseline_file=tool_baseline_file,
                update_tool_baseline=update_tool_baseline,
            )
        )

    # Filter by severity if specified
    if severity:
        severity_set = set(severity)
        result.vulnerabilities = [
            v for v in result.vulnerabilities if v.severity.value in severity_set
        ]
        result.recalculate_statistics_from_findings()

    if not no_executive_assessment:
        from mcp_sentinel.reporting.executive_assessment import (
            build_executive_assessment,
            load_executive_policy,
        )

        pol = load_executive_policy(executive_policy)
        if executive_top_n is not None:
            pol = pol.model_copy(update={"action_queue_top_n": executive_top_n})
        result.executive_assessment = build_executive_assessment(result, pol)

    # Output results
    if output == "terminal":
        _print_terminal_results(result)
    elif output == "json":
        _print_json_results(result, json_file)
    elif output == "sarif":
        _print_sarif_results(result, json_file)
    elif output == "html":
        _print_html_results(result, json_file)
    elif output == "pdf":
        _print_pdf_results(result, json_file)

    if pdf_file:
        pdf_path = Path(pdf_file).resolve()
        primary_pdf = (
            output == "pdf"
            and json_file
            and Path(json_file).resolve() == pdf_path
        )
        if not primary_pdf:
            _print_pdf_results(result, str(pdf_file))

    if incident_summary:
        incident_path = _resolve_incident_summary_path(json_file, incident_file)
        _print_incident_summary_results(result, str(incident_path))

    # Exit code based on findings (reports already written above)
    if result.has_critical_findings():
        if no_fail_on_critical:
            console.print(
                "[yellow]Critical findings present — exiting with code 0 "
                "(--no-fail-on-critical). Reports were written above.[/yellow]"
            )
        else:
            console.print(
                "[bold red]Critical findings present — exiting with code 1 (CI fail).[/bold red]"
            )
            console.print(
                "[dim]Reports were written above. "
                "Use --no-fail-on-critical for exit 0 in local runs.[/dim]"
            )
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
    *,
    tool_baseline_file: str | None = None,
    update_tool_baseline: bool = False,
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
            scan_task = asyncio.create_task(
                scanner.scan_directory(
                    target,
                    tool_baseline_path=tool_baseline_file,
                    update_tool_baseline=update_tool_baseline,
                )
            )

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
        return await scanner.scan_directory(
            target,
            tool_baseline_path=tool_baseline_file,
            update_tool_baseline=update_tool_baseline,
        )


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

    ea = result.executive_assessment
    if isinstance(ea, ExecutiveAssessment):
        vline = "NO-GO (policy)" if ea.verdict == "no_go" else "GO (policy)"
        vcol = "red" if ea.verdict == "no_go" else "green"
        sub = (
            " · ".join(ea.verdict_reasons)
            if ea.verdict_reasons
            else "No blocking rules under current policy."
        )
        console.print(
            Panel.fit(
                f"[bold]Executive verdict:[/bold] [{vcol}]{vline}[/]\n{escape(sub)}",
                title="Decision support",
                box=box.ROUNDED,
            )
        )
        if ea.action_queue:
            t = Table(title="Prioritized action queue", box=box.ROUNDED)
            t.add_column("Triage", style="magenta")
            t.add_column("Sev", style="bold")
            t.add_column("Location", style="cyan", overflow="fold")
            t.add_column("Next step", style="white", overflow="fold")
            for a in ea.action_queue:
                t.add_row(
                    a.triage,
                    a.severity,
                    f"{a.file_path}:{a.line_number}",
                    a.suggested_next_step[:120]
                    + ("…" if len(a.suggested_next_step) > 120 else ""),
                )
            console.print(t)
        console.print(
            f"[dim]{escape(ea.disclaimer)}[/dim]\n"
        )

    # Detailed findings
    if result.vulnerabilities:
        console.print("[bold]Detailed Findings:[/bold]\n")

        for i, vuln in enumerate(result.vulnerabilities, 1):
            severity_color = severity_colors.get(vuln.severity.value.upper(), "white")

            console.print(
                f"[bold]{i}. [{severity_color}]{vuln.severity.value.upper()}[/][/bold] - "
                f"{escape(vuln.title)}"
            )
            console.print(
                f"   File: [cyan]{escape(str(vuln.file_path))}:{vuln.line_number}[/cyan]",
            )
            console.print(f"   {escape(vuln.description)}")

            if vuln.code_snippet:
                console.print(f"   Code: [dim]{escape(vuln.code_snippet)}[/dim]")

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

    json_output = result.model_dump_json(indent=2)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(json_output)
        console.print(f"[green]Results saved to {output_file}[/green]")
    else:
        console.print(json_output)


def _print_sarif_results(result: ScanResult, output_file: str | None = None):
    """Print results in SARIF format."""
    generator = SARIFGenerator()

    if output_file:
        generator.save_to_file(result, Path(output_file))
        console.print(f"[green]SARIF report saved to {output_file}[/green]")
    else:
        sarif_json = generator.generate_json(result)
        console.print(sarif_json)


def _print_html_results(result: ScanResult, output_file: str | None = None):
    """Print results in HTML format."""
    generator = HTMLGenerator()

    if output_file:
        generator.save_to_file(result, Path(output_file))
        console.print(f"[green]HTML report saved to {output_file}[/green]")
    else:
        # For terminal output, save to temp file and show path
        temp_file = Path("mcp-sentinel-report.html")
        generator.save_to_file(result, temp_file)
        console.print(f"[green]HTML report saved to {temp_file.absolute()}[/green]")


def _print_pdf_results(result: ScanResult, output_file: str | None = None):
    """Write PDF executive summary (ReportLab)."""
    if not output_file:
        return
    generator = PDFGenerator()
    generator.save_to_file(result, Path(output_file))
    console.print(f"[green]PDF report saved to {output_file}[/green]")


def _resolve_incident_summary_path(json_file: str | None, incident_file: str | None) -> Path:
    """Resolve incident markdown output path."""
    if incident_file:
        return Path(incident_file)
    if json_file:
        base = Path(json_file)
        return base.with_name(f"{base.stem}-incidents.md")
    return Path("mcp-sentinel-incidents.md")


def _print_incident_summary_results(result: ScanResult, output_file: str) -> None:
    """Write exploitability-focused incident summary markdown."""
    generator = IncidentSummaryGenerator()
    has_candidates = generator.save_to_file(result, Path(output_file))
    if has_candidates:
        console.print(f"[green]Incident summary saved to {output_file}[/green]")
    else:
        console.print(
            f"[dim]Incident summary saved to {output_file} "
            "(no critical/RCE/exploit-likely candidates).[/dim]"
        )


def _warn_unwired_engines(enabled_engines: set[EngineType]) -> None:
    """Tell the user when semantic/ai were requested but are not implemented yet."""
    not_wired = {EngineType.SEMANTIC, EngineType.AI}
    requested = enabled_engines & not_wired
    if not requested:
        return
    names = ", ".join(sorted(e.value for e in requested))
    console.print(
        f"[yellow]Warning: engine(s) [{names}] are not wired in this release — "
        "only static and SAST run.[/yellow]"
    )


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

# Analysis engines to enable (Phase 3: static only, Phase 4+: all engines)
engines:
  static: true           # ✅ Available now - Pattern-based detection
  semantic: false        # 🚧 Phase 4 - Tree-sitter AST analysis
  sast: false            # 🚧 Phase 4 - Semgrep + Bandit integration
  ai: false              # 🚧 Phase 4 - AI-powered analysis (requires API keys)

# AI provider configuration (Phase 4+)
ai:
  provider: anthropic    # Options: openai, anthropic, google, ollama
  model: claude-3-5-sonnet-20241022
  # api_key: ${ANTHROPIC_API_KEY}  # Use environment variable

# Report generation (Phase 3 ✅)
reporting:
  formats: [terminal, html, sarif]  # Available: terminal, json, sarif, html
  output_dir: ./reports

  # Terminal output settings
  terminal:
    colored: true
    show_code_snippets: true

  # HTML report settings
  html:
    include_executive_summary: true
    show_risk_score: true
    animated_charts: true

  # SARIF settings
  sarif:
    github_code_scanning: true  # GitHub-compatible SARIF 2.1.0
    include_fixes: true

# Scanning configuration
scan:
  # Severity filtering
  min_severity: low  # Options: critical, high, medium, low, info

  # File patterns
  include_patterns:
    - "**/*.py"
    - "**/*.js"
    - "**/*.ts"
    - "**/*.go"
    - "**/*.java"

  exclude_patterns:
    - "**/node_modules/**"
    - "**/.git/**"
    - "**/__pycache__/**"
    - "**/venv/**"
    - "**/dist/**"

# Performance
performance:
  max_workers: 10       # Concurrent file processing
  cache_enabled: true   # Cache scan results
  parallel_execution: true
  timeout_seconds: 300  # Max scan duration
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
