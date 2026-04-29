"""Run stdio/HTTP MCP probes and merge results into ``ScanResult``."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

from mcp_sentinel.models.scan_result import ScanResult
from mcp_sentinel.models.vulnerability import Vulnerability
from mcp_sentinel.probing.discovery import discover_probe_targets
from mcp_sentinel.probing.heuristics import analyze_live_surface, probe_failure_vulnerability
from mcp_sentinel.probing.models import ProbeRunRecord, ProbeTarget


async def run_dynamic_probes(
    root: str | Path,
    targets: list[ProbeTarget] | None = None,
    *,
    timeout_seconds: float = 90.0,
) -> tuple[list[Vulnerability], dict[str, Any]]:
    """
    Execute probes for each target (or discover targets under ``root``).

    Returns new vulnerabilities and a metadata dict for ``ScanResult.config``.
    """
    root_path = Path(root).resolve()
    if targets is None:
        targets = discover_probe_targets(root_path)

    all_vulns: list[Vulnerability] = []
    records: list[dict[str, Any]] = []

    for t in targets:
        v, rec = await _probe_single_target(root_path, t, timeout_seconds=timeout_seconds)
        all_vulns.extend(v)
        records.append(rec.model_dump())

    meta: dict[str, Any] = {
        "enabled": True,
        "target_root": str(root_path),
        "targets_attempted": len(targets),
        "runs": records,
    }
    return all_vulns, meta


async def _probe_single_target(
    root_path: Path,
    target: ProbeTarget,
    *,
    timeout_seconds: float,
) -> tuple[list[Vulnerability], ProbeRunRecord]:
    try:
        return await asyncio.wait_for(
            _probe_single_target_inner(root_path, target),
            timeout=timeout_seconds,
        )
    except TimeoutError:  # asyncio.wait_for (Py 3.11+)
        err = f"Probe timed out after {timeout_seconds}s"
        rec = ProbeRunRecord(
            server_name=target.server_name,
            transport=target.transport,
            source_file=target.source_file,
            ok=False,
            error=err,
        )
        return [probe_failure_vulnerability(target.transport, target.server_name, err)], rec


async def _probe_single_target_inner(
    root_path: Path,
    target: ProbeTarget,
) -> tuple[list[Vulnerability], ProbeRunRecord]:
    from mcp.client.stdio import StdioServerParameters, stdio_client
    from mcp.client.streamable_http import streamablehttp_client

    if target.transport == "stdio":
        if not target.command:
            err = "stdio transport missing command"
            return (
                [probe_failure_vulnerability("stdio", target.server_name, err)],
                ProbeRunRecord(
                    server_name=target.server_name,
                    transport="stdio",
                    source_file=target.source_file,
                    ok=False,
                    error=err,
                ),
            )
        params = StdioServerParameters(
            command=target.command,
            args=target.args,
            env=target.env,
            cwd=str(root_path),
        )
        # Avoid default sys.stderr (breaks in Click CliRunner / non-TTY contexts).
        err_sink = open(os.devnull, "w", encoding="utf-8")
        try:
            async with stdio_client(params, errlog=err_sink) as streams:
                read_stream, write_stream = streams
                return await _session_list_and_analyze(
                    read_stream,
                    write_stream,
                    "stdio",
                    target.server_name,
                    target.source_file,
                )
        finally:
            err_sink.close()

    if target.transport == "http":
        if not target.url:
            err = "http transport missing url"
            return (
                [probe_failure_vulnerability("http", target.server_name, err)],
                ProbeRunRecord(
                    server_name=target.server_name,
                    transport="http",
                    source_file=target.source_file,
                    ok=False,
                    error=err,
                ),
            )
        headers = target.headers if target.headers else None
        async with streamablehttp_client(target.url, headers=headers) as triple:
            read_stream, write_stream, _get_sid = triple
            return await _session_list_and_analyze(
                read_stream,
                write_stream,
                "http",
                target.server_name,
                target.source_file,
            )

    err = f"unknown transport {target.transport}"
    return (
        [probe_failure_vulnerability(target.transport, target.server_name, err)],
        ProbeRunRecord(
            server_name=target.server_name,
            transport=target.transport,
            source_file=target.source_file,
            ok=False,
            error=err,
        ),
    )


async def _session_list_and_analyze(
    read_stream: Any,
    write_stream: Any,
    transport: str,
    server_name: str,
    source_file: str,
) -> tuple[list[Vulnerability], ProbeRunRecord]:
    from mcp.client.session import ClientSession

    try:
        async with ClientSession(read_stream, write_stream) as session:
            init = await session.initialize()
            caps = getattr(init, "capabilities", None)
            server_info: dict[str, Any] = {}
            if caps is not None and hasattr(caps, "model_dump"):
                server_info["capabilities"] = caps.model_dump(exclude_none=True)
            elif caps is not None:
                server_info["capabilities"] = str(caps)

            lr = await session.list_tools()
            tools = list(lr.tools) if lr and lr.tools else []

            resources: list[Any] = []
            try:
                rr = await session.list_resources()
                if rr and rr.resources:
                    resources = list(rr.resources)
            except Exception:
                pass

            prompts: list[Any] = []
            try:
                pr = await session.list_prompts()
                if pr and pr.prompts:
                    prompts = list(pr.prompts)
            except Exception:
                pass

            findings = analyze_live_surface(
                transport=transport,
                server_name=server_name,
                tools=tools,
                resources=resources,
                prompts=prompts,
            )

            rec = ProbeRunRecord(
                server_name=server_name,
                transport=transport,
                source_file=source_file,
                ok=True,
                tools_count=len(tools),
                resources_count=len(resources),
                prompts_count=len(prompts),
                server_info=server_info,
            )
            return findings, rec
    except Exception as exc:
        err = f"{type(exc).__name__}: {exc}"
        rec = ProbeRunRecord(
            server_name=server_name,
            transport=transport,
            source_file=source_file,
            ok=False,
            error=err[:4000],
        )
        return [probe_failure_vulnerability(transport, server_name, err)], rec


def merge_probe_results(result: ScanResult, vulns: list[Vulnerability], meta: dict[str, Any]) -> None:
    """Append dynamic findings and attach probe metadata to ``result.config``."""
    for v in vulns:
        result.add_vulnerability(v)
    cfg = dict(result.config) if isinstance(result.config, dict) else {}
    cfg["dynamic_probe"] = meta
    result.config = cfg
    if meta.get("targets_attempted", 0) > 0 and "dynamic" not in result.statistics.engines_used:
        result.statistics.engines_used.append("dynamic")
