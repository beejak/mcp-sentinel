"""
Integration tests: default Scanner + static detectors (secrets, PP, prompt injection, etc.).

Roadmap: SECURITY_ANALYSIS_AND_ROADMAP.md — additional integration coverage for shipped detectors.
"""

import pytest

from mcp_sentinel.core.scanner import Scanner
from mcp_sentinel.models.vulnerability import VulnerabilityType


@pytest.mark.asyncio
async def test_integration_scanner_has_nine_default_detectors():
    scanner = Scanner()
    assert len(scanner.detectors) == 9
    names = {d.name for d in scanner.detectors}
    assert "PrototypePollutionDetector" in names


@pytest.mark.asyncio
async def test_integration_proto_pollution_literal_in_js_directory(temp_dir):
    (temp_dir / "pollute.js").write_text('const x = { "__proto__": { hacked: true } };')
    result = await Scanner().scan_directory(temp_dir)
    pp = [v for v in result.vulnerabilities if v.type == VulnerabilityType.PROTOTYPE_POLLUTION]
    assert len(pp) >= 1
    assert any("proto" in v.title.lower() for v in pp)


@pytest.mark.asyncio
async def test_integration_deep_merge_multiline_merge_body(temp_dir):
    (temp_dir / "routes.ts").write_text(
        """_.merge(
  defaults,
  req.body
);
"""
    )
    result = await Scanner().scan_directory(temp_dir)
    pp = [v for v in result.vulnerabilities if v.type == VulnerabilityType.PROTOTYPE_POLLUTION]
    assert any("deep merge" in v.title.lower() for v in pp)


@pytest.mark.asyncio
async def test_integration_set_prototype_of_is_reported(temp_dir):
    (temp_dir / "hack.js").write_text("Object.setPrototypeOf(o, EvilProto);")
    result = await Scanner().scan_directory(temp_dir)
    pp = [v for v in result.vulnerabilities if v.type == VulnerabilityType.PROTOTYPE_POLLUTION]
    assert len(pp) >= 1


@pytest.mark.asyncio
async def test_integration_chat_json_user_role_not_role_assignment_spam(temp_dir):
    (temp_dir / "msg.json").write_text('{"role": "user", "content": "hello"}')
    result = await Scanner().scan_directory(temp_dir)
    role_assign = [v for v in result.vulnerabilities if "Role Assignment" in v.title]
    assert len(role_assign) == 0


@pytest.mark.asyncio
async def test_integration_chat_json_system_role_still_flagged(temp_dir):
    (temp_dir / "sys.json").write_text('{"role": "system", "content": "You are helpful"}')
    result = await Scanner().scan_directory(temp_dir)
    role_assign = [v for v in result.vulnerabilities if "Role Assignment" in v.title]
    assert len(role_assign) >= 1


@pytest.mark.asyncio
async def test_integration_mixed_python_and_js_secrets_and_proto(temp_dir, sample_python_file):
    (temp_dir / "bad.js").write_text('const x = {"__proto__": {}};')
    result = await Scanner().scan_directory(temp_dir)
    pp = [v for v in result.vulnerabilities if v.type == VulnerabilityType.PROTOTYPE_POLLUTION]
    secrets = [v for v in result.vulnerabilities if v.type == VulnerabilityType.SECRET_EXPOSURE]
    assert len(pp) >= 1
    assert len(secrets) >= 1


@pytest.mark.asyncio
async def test_integration_clean_js_has_no_prototype_pollution(temp_dir):
    (temp_dir / "clean.js").write_text("export const VERSION = '1.0.0';\n")
    result = await Scanner().scan_directory(temp_dir)
    pp = [v for v in result.vulnerabilities if v.type == VulnerabilityType.PROTOTYPE_POLLUTION]
    assert len(pp) == 0


@pytest.mark.asyncio
async def test_integration_scan_file_single_js_proto_pollution(temp_dir):
    p = temp_dir / "one.js"
    p.write_text('obj.__proto__ = evil;')
    vulns = await Scanner().scan_file(p)
    pp = [v for v in vulns if v.type == VulnerabilityType.PROTOTYPE_POLLUTION]
    assert len(pp) >= 1


@pytest.mark.asyncio
async def test_integration_scan_directory_counts_scanned_files(temp_dir):
    (temp_dir / "a.js").write_text("// ok\n")
    (temp_dir / "b.ts").write_text("// ok\n")
    result = await Scanner().scan_directory(temp_dir)
    assert result.statistics.scanned_files >= 2
    assert result.status == "completed"
