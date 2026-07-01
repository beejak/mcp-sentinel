"""
Detection Benchmark — MCP Sentinel against real vulnerable MCP server fixtures.

This is the project's "loss function" — a fixed eval set derived from testing
against three deliberately vulnerable MCP servers:
  - beejak/Vulnerable-MCP-Server (home target, 18 vulns)
  - MCPGoat / SabyasachiDhal (26 challenges)
  - mcpscanner/playground (8 vulnerability types)

Success criterion: ≥75% detection rate across all DETECTABLE test cases.
(Some gaps are runtime-only and cannot be caught statically — those are excluded.)

Every gap fix must add a new ASSERT here before it's considered done.
Every regression will be caught here first.

Run:
    pytest tests/integration/test_benchmark.py -v --tb=short

Score tracked in docs/DETECTION_GAPS.md.
"""

from __future__ import annotations

import pytest
from pathlib import Path
from mcp_sentinel.core.scanner import Scanner
from mcp_sentinel.models.vulnerability import VulnerabilityType, Severity

# Targets live outside tests/ so detectors don't suppress findings (base._is_test_file check)
MCPGOAT_DIR = Path(__file__).parent.parent.parent / "vulnerable_targets" / "mcpgoat"
PLAYGROUND_DIR = Path(__file__).parent.parent.parent / "vulnerable_targets" / "playground"
CHALLENGES = MCPGOAT_DIR / "challenges.ts"
DB = MCPGOAT_DIR / "db.ts"
PLAYGROUND = PLAYGROUND_DIR / "index.ts"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _types(vulns: list) -> set[str]:
    return {v.type.value if hasattr(v.type, "value") else str(v.type) for v in vulns}


def _has(vulns: list, vtype: VulnerabilityType) -> bool:
    return any(v.type == vtype for v in vulns)


def _count(vulns: list, vtype: VulnerabilityType) -> int:
    return sum(1 for v in vulns if v.type == vtype)


# ---------------------------------------------------------------------------
# MCPGoat — challenges.ts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mcpgoat_a1_tool_poisoning():
    """A1: Tool poisoning via hidden comment in description."""
    scanner = Scanner()
    result = await scanner.scan_file(CHALLENGES)
    assert _has(result, VulnerabilityType.TOOL_POISONING), (
        "A1 Tool Poisoning: hidden instruction comment in tool description not detected"
    )


@pytest.mark.asyncio
async def test_mcpgoat_b2_resource_injection():
    """B2: Resource content injection (<<SYSTEM>> in resource body)."""
    scanner = Scanner()
    result = await scanner.scan_file(CHALLENGES)
    assert _has(result, VulnerabilityType.MCP_RESOURCE_POISONING), (
        "B2 Resource Content Injection: <<SYSTEM>> in resource body not detected"
    )


@pytest.mark.asyncio
async def test_mcpgoat_b5_sampling_abuse():
    """B5: Sampling abuse — sensitive data / system prompt in createMessage."""
    scanner = Scanner()
    result = await scanner.scan_file(CHALLENGES)
    assert _has(result, VulnerabilityType.MCP_SAMPLING), (
        "B5 Sampling Abuse: sensitive data in createMessage systemPrompt not detected"
    )


@pytest.mark.asyncio
async def test_mcpgoat_c2_missing_auth():
    """C2: Admin tools without authentication guard."""
    scanner = Scanner()
    result = await scanner.scan_file(CHALLENGES)
    assert _has(result, VulnerabilityType.MISSING_AUTH), (
        "C2 Broken Auth: admin tools with no auth guard not detected"
    )


@pytest.mark.asyncio
async def test_mcpgoat_d1_command_injection():
    """D1: Command injection via execAsync with unsanitised host."""
    scanner = Scanner()
    result = await scanner.scan_file(CHALLENGES)
    assert _has(result, VulnerabilityType.CODE_INJECTION), (
        "D1 Command Injection: execAsync(`ping -c 1 ${host}`) not detected"
    )


@pytest.mark.asyncio
async def test_mcpgoat_d3_ssrf():
    """D3: SSRF via unvalidated fetch(url)."""
    scanner = Scanner()
    result = await scanner.scan_file(CHALLENGES)
    assert _has(result, VulnerabilityType.SSRF), (
        "D3 SSRF: fetch(url) with unvalidated user URL not detected"
    )


@pytest.mark.asyncio
async def test_mcpgoat_d4_sql_injection_db():
    """D4: SQL injection in db.ts via raw string interpolation."""
    scanner = Scanner()
    result = await scanner.scan_file(DB)
    vulns = result
    # Should fire as code_injection (SQL template literal) or context_flooding
    has_sqli = _has(vulns, VulnerabilityType.CODE_INJECTION) or _has(vulns, VulnerabilityType.CONTEXT_FLOODING)
    assert has_sqli, (
        f"D4 SQL Injection: `SELECT ... WHERE name LIKE '%${{term}}%'` not detected. Types found: {_types(vulns)}"
    )


@pytest.mark.asyncio
async def test_mcpgoat_d5_nosql_function_constructor():
    """D5: NoSQL injection via new Function() constructor."""
    scanner = Scanner()
    result = await scanner.scan_file(CHALLENGES)
    assert _has(result, VulnerabilityType.CODE_INJECTION), (
        "D5 NoSQL: new Function() constructor in nosqlMatch not detected"
    )


@pytest.mark.asyncio
async def test_mcpgoat_d6_ssti():
    """D6: SSTI via new Function() with user template."""
    scanner = Scanner()
    result = await scanner.scan_file(CHALLENGES)
    assert _has(result, VulnerabilityType.CODE_INJECTION), (
        "D6 SSTI: new Function('ctx', `with(ctx){ return (${expr}); }`) not detected"
    )


@pytest.mark.asyncio
async def test_mcpgoat_e1_weak_crypto():
    """H1/E1: Weak crypto (MD5, Math.random)."""
    scanner = Scanner()
    result = await scanner.scan_file(CHALLENGES)
    assert _has(result, VulnerabilityType.WEAK_CRYPTO), (
        "H1 Weak Crypto: Math.random() or md5() not detected"
    )


# ---------------------------------------------------------------------------
# MCPGoat — GAP tests (these currently FAIL; remove xfail when fixed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mcpgoat_d8_prototype_pollution():
    """D8: Prototype pollution via pollutingMerge without __proto__ guard."""
    scanner = Scanner()
    result = await scanner.scan_file(CHALLENGES)
    has_proto = (
        _has(result, VulnerabilityType.INSECURE_DESERIALIZATION)
        or any("proto" in (v.title or "").lower() or "pollution" in (v.title or "").lower()
               for v in result)
    )
    assert has_proto, "D8 Prototype Pollution: pollutingMerge without __proto__ guard not detected"


@pytest.mark.asyncio
async def test_mcpgoat_d7_xxe():
    """D7: XXE via manual entity resolver + readFile(uri)."""
    scanner = Scanner()
    result = await scanner.scan_file(CHALLENGES)
    assert any("xxe" in str(v.type).lower() or "xxe" in (v.title or "").lower()
               for v in result), (
        "D7 XXE: ENTITY SYSTEM + readFile entity resolver not detected"
    )


@pytest.mark.asyncio
async def test_mcpgoat_g4_redos():
    """G4: ReDoS via catastrophic backtracking regex /(a+)+$/."""
    scanner = Scanner()
    result = await scanner.scan_file(CHALLENGES)
    assert any("redos" in str(v.type).lower() or "backtrack" in (v.title or "").lower()
               for v in result), (
        "G4 ReDoS: /(a+)+$/ applied to user input not detected"
    )


@pytest.mark.asyncio
@pytest.mark.xfail(reason="GAP: Path traversal through sanitized var not detected")
async def test_mcpgoat_d2_path_traversal_sanitized():
    """D2: Path traversal where cleaned = rel.replace('../', '') then path.join."""
    scanner = Scanner()
    result = await scanner.scan_file(CHALLENGES)
    assert _has(result, VulnerabilityType.PATH_TRAVERSAL), (
        "D2 Path Traversal: .replace('../','') bypass + path.join not flagged as PATH_TRAVERSAL"
    )


# ---------------------------------------------------------------------------
# mcpscanner/playground — index.ts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_playground_ssrf():
    """SSRF via unvalidated fetch(url)."""
    scanner = Scanner()
    result = await scanner.scan_file(PLAYGROUND)
    assert _has(result, VulnerabilityType.SSRF), (
        "Playground SSRF: fetch(url) with raw user URL not detected"
    )


@pytest.mark.asyncio
async def test_playground_prompt_injection():
    """Prompt injection / tool poisoning in tool description."""
    scanner = Scanner()
    result = await scanner.scan_file(PLAYGROUND)
    has_pi = (
        _has(result, VulnerabilityType.PROMPT_INJECTION)
        or _has(result, VulnerabilityType.TOOL_POISONING)
    )
    assert has_pi, "Playground Prompt Injection: injection in tool description not detected"


@pytest.mark.asyncio
async def test_playground_secrets():
    """Hardcoded API keys, JWT, AWS credentials."""
    scanner = Scanner()
    result = await scanner.scan_file(PLAYGROUND)
    assert _has(result, VulnerabilityType.SECRET_EXPOSURE), (
        "Playground Secrets: hardcoded API key / AWS / JWT not detected"
    )


@pytest.mark.asyncio
async def test_playground_path_traversal():
    """Path traversal via readFileSync with raw user input."""
    scanner = Scanner()
    result = await scanner.scan_file(PLAYGROUND)
    assert _has(result, VulnerabilityType.PATH_TRAVERSAL), (
        "Playground Path Traversal: readFileSync(filePath) with user input not detected as PATH_TRAVERSAL"
    )


@pytest.mark.asyncio
async def test_playground_command_injection_alias():
    """Command injection via execAsync = promisify(exec); execAsync(command)."""
    scanner = Scanner()
    result = await scanner.scan_file(PLAYGROUND)
    # Look specifically for the line with execAsync(command) — not the exec() import
    hits = [v for v in result
            if v.type == VulnerabilityType.CODE_INJECTION and v.line_number >= 35]
    assert hits, (
        "Playground Command Injection: execAsync(command) via promisify alias not detected at callsite"
    )


@pytest.mark.asyncio
async def test_playground_prototype_pollution():
    """Prototype pollution via merge() in load_state tool."""
    scanner = Scanner()
    result = await scanner.scan_file(PLAYGROUND)
    has_proto = (
        _has(result, VulnerabilityType.INSECURE_DESERIALIZATION)
        or any("proto" in (v.title or "").lower() or "pollution" in (v.title or "").lower()
               for v in result)
    )
    assert has_proto, "Playground Prototype Pollution: merge() without __proto__ guard not detected"


# ---------------------------------------------------------------------------
# Benchmark score reporter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_benchmark_score_mcpgoat():
    """
    Aggregate detection rate against MCPGoat fixture.
    Fails if detection rate drops below 40% (current baseline).
    Raise the threshold as gaps are fixed.
    """
    scanner = Scanner()
    result_c = await scanner.scan_file(CHALLENGES)
    result_d = await scanner.scan_file(DB)
    all_vulns = result_c + result_d

    # Definitive true-positive test cases (statically detectable from fixture)
    DETECTABLE = [
        (VulnerabilityType.TOOL_POISONING, "A1 tool poisoning"),
        (VulnerabilityType.MCP_RESOURCE_POISONING, "B2 resource injection"),
        (VulnerabilityType.MCP_SAMPLING, "B5 sampling abuse"),
        (VulnerabilityType.MISSING_AUTH, "C2 broken auth"),
        (VulnerabilityType.CODE_INJECTION, "D1/D5/D6 code injection"),
        (VulnerabilityType.SSRF, "D3 ssrf"),
        (VulnerabilityType.WEAK_CRYPTO, "H1 weak crypto"),
    ]
    detected = sum(1 for vtype, _ in DETECTABLE if _has(all_vulns, vtype))
    rate = detected / len(DETECTABLE)

    print(f"\n  MCPGoat benchmark: {detected}/{len(DETECTABLE)} = {rate:.0%}")
    for vtype, label in DETECTABLE:
        status = "✅" if _has(all_vulns, vtype) else "❌"
        print(f"    {status} {label}")

    assert rate >= 0.40, f"MCPGoat detection rate {rate:.0%} dropped below 40% baseline"


@pytest.mark.asyncio
async def test_benchmark_score_playground():
    """
    Aggregate detection rate against mcpscanner/playground fixture.
    Fails if detection rate drops below 35% (current baseline).
    """
    scanner = Scanner()
    result = await scanner.scan_file(PLAYGROUND)
    vulns = result

    DETECTABLE = [
        (VulnerabilityType.SSRF, "ssrf"),
        (VulnerabilityType.PROMPT_INJECTION, "prompt injection"),
        (VulnerabilityType.SECRET_EXPOSURE, "secrets"),
    ]
    detected = sum(1 for vtype, _ in DETECTABLE
                   if _has(vulns, vtype) or (vtype == VulnerabilityType.PROMPT_INJECTION
                                              and _has(vulns, VulnerabilityType.TOOL_POISONING)))
    rate = detected / len(DETECTABLE)

    print(f"\n  Playground benchmark: {detected}/{len(DETECTABLE)} = {rate:.0%}")
    assert rate >= 0.35, f"Playground detection rate {rate:.0%} dropped below 35% baseline"
