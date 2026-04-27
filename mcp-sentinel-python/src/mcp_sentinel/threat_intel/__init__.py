"""Threat intelligence integrations (optional enrichment for scan findings)."""

from mcp_sentinel.threat_intel.enricher import enrich_scan_result_vulnerable_mcp

__all__ = ["enrich_scan_result_vulnerable_mcp"]
