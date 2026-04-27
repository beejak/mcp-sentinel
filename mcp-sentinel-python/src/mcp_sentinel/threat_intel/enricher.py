"""Enrich scan findings with external threat intel (optional)."""

from __future__ import annotations

import asyncio
import os

from mcp_sentinel.core.config import settings
from mcp_sentinel.models.scan_result import ScanResult
from mcp_sentinel.threat_intel.vulnerable_mcp import (
    get_cached_vulnerable_mcp_entries,
    match_vulnerable_mcp_records,
)


def _threat_intel_disabled() -> bool:
    return os.environ.get("VULNERABLE_MCP_DISABLED", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )


async def enrich_scan_result_vulnerable_mcp(scan_result: ScanResult) -> None:
    """
    Attach VulnerableMCP feed matches to each finding's ``threat_intel`` field.

    Skipped when ``ENABLE_THREAT_INTEL`` is false, when ``VULNERABLE_MCP_DISABLED``
    is set, or when the feed cannot be loaded.
    """
    if not settings.engines.enable_threat_intel:
        return
    if _threat_intel_disabled():
        return
    if not scan_result.vulnerabilities:
        return

    def _load_feed() -> list:
        return get_cached_vulnerable_mcp_entries(
            url=settings.vulnerable_mcp_json_url,
            timeout_seconds=settings.vulnerable_mcp_timeout_seconds,
            cache_ttl_seconds=float(settings.cache_ttl),
        )

    entries = await asyncio.to_thread(_load_feed)
    if not entries:
        return

    for vuln in scan_result.vulnerabilities:
        matches = match_vulnerable_mcp_records(vuln, entries)
        if not matches:
            continue
        blob = vuln.threat_intel if isinstance(vuln.threat_intel, dict) else {}
        blob["vulnerable_mcp"] = {
            "feed_url": settings.vulnerable_mcp_json_url,
            "matched_records": matches,
        }
        vuln.threat_intel = blob
