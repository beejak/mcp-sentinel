"""Tests for VulnerableMCP threat-intel matching (no network)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from mcp_sentinel.models.vulnerability import Confidence, Severity, Vulnerability, VulnerabilityType
from mcp_sentinel.threat_intel.vulnerable_mcp import match_vulnerable_mcp_records


def _vuln(**kwargs) -> Vulnerability:
    base = {
        "type": VulnerabilityType.SUPPLY_CHAIN,
        "title": "Supply chain risk",
        "description": "desc",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "file_path": "package.json",
        "line_number": 1,
        "detector": "SupplyChainDetector",
        "engine": "static",
        "timestamp": datetime.now(UTC),
    }
    base.update(kwargs)
    return Vulnerability(**base)


def test_match_by_cve_id():
    entries = [
        {
            "id": "anthropic-git-chain",
            "title": "Anthropic Git MCP Server RCE Chain",
            "cveIds": ["CVE-2025-68145", "CVE-2025-68143"],
            "severity": "critical",
            "category": "input-validation",
            "url": "https://example.invalid/advisory",
        }
    ]
    vuln = _vuln(
        description="Known issue CVE-2025-68145 in dependency chain.",
    )
    matches = match_vulnerable_mcp_records(vuln, entries, max_matches=5)
    assert len(matches) == 1
    assert matches[0]["id"] == "anthropic-git-chain"
    assert "CVE-2025-68145" in matches[0]["cveIds"]


def test_match_by_slug_id_in_text():
    entries = [
        {
            "id": "gemini-mcp-tool-command-injection",
            "title": "Gemini MCP tool thing",
            "cveIds": [],
            "severity": "critical",
            "category": "input-validation",
            "url": "https://example.invalid/a",
        }
    ]
    vuln = _vuln(
        title="Dependency review",
        description="Package gemini-mcp-tool-command-injection referenced in audit.",
    )
    matches = match_vulnerable_mcp_records(vuln, entries, max_matches=5)
    assert len(matches) == 1
    assert matches[0]["id"] == "gemini-mcp-tool-command-injection"


def test_match_by_distinctive_title_word():
    entries = [
        {
            "id": "whatsapp-message-exfiltration",
            "title": "WhatsApp Message Exfiltration via MCP",
            "alternativeNames": [],
            "cveIds": [],
            "severity": "high",
            "category": "prompt-injection",
            "url": "https://example.invalid/w",
        }
    ]
    vuln = _vuln(
        description="Report discusses WhatsApp Message exfiltration risks in MCP tooling.",
    )
    matches = match_vulnerable_mcp_records(vuln, entries, max_matches=5)
    assert len(matches) == 1


@pytest.mark.asyncio
async def test_enricher_skips_when_disabled(monkeypatch):
    from mcp_sentinel.models.scan_result import ScanResult
    from mcp_sentinel.threat_intel.enricher import enrich_scan_result_vulnerable_mcp

    monkeypatch.setenv("VULNERABLE_MCP_DISABLED", "1")
    sr = ScanResult(target="/tmp/x", vulnerabilities=[_vuln()])
    await enrich_scan_result_vulnerable_mcp(sr)
    assert sr.vulnerabilities[0].threat_intel is None


@pytest.mark.asyncio
async def test_enricher_populates_when_feed_provided(monkeypatch):
    from unittest.mock import patch

    from mcp_sentinel.core.config import settings
    from mcp_sentinel.models.scan_result import ScanResult
    from mcp_sentinel.threat_intel.enricher import enrich_scan_result_vulnerable_mcp

    monkeypatch.delenv("VULNERABLE_MCP_DISABLED", raising=False)
    monkeypatch.setattr(settings.engines, "enable_threat_intel", True)

    feed = [
        {
            "id": "cve-test-123",
            "title": "Test CVE Record",
            "cveIds": ["CVE-2099-00001"],
            "severity": "low",
            "category": "test",
            "url": "https://example.invalid/t",
        }
    ]

    vuln = _vuln(description="See CVE-2099-00001 for background.")
    sr = ScanResult(target="/tmp/y", vulnerabilities=[vuln])

    with patch(
        "mcp_sentinel.threat_intel.enricher.get_cached_vulnerable_mcp_entries",
        return_value=feed,
    ):
        await enrich_scan_result_vulnerable_mcp(sr)

    ti = sr.vulnerabilities[0].threat_intel
    assert ti is not None
    assert "vulnerable_mcp" in ti
    assert len(ti["vulnerable_mcp"]["matched_records"]) == 1
    assert ti["vulnerable_mcp"]["matched_records"][0]["id"] == "cve-test-123"
