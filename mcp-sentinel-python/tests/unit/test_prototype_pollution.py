"""Unit tests for PrototypePollutionDetector (CWE-1321)."""

from pathlib import Path

import pytest

from mcp_sentinel.detectors.prototype_pollution import PrototypePollutionDetector
from mcp_sentinel.models.vulnerability import Confidence, Severity, VulnerabilityType


@pytest.fixture
def detector():
    return PrototypePollutionDetector()


@pytest.mark.asyncio
async def test_proto_key_literal_double_quotes(detector):
    content = 'const x = { "__proto__": { "polluted": true } };'
    vulns = await detector.detect(Path("evil.js"), content)

    assert len(vulns) == 1
    assert vulns[0].type == VulnerabilityType.PROTOTYPE_POLLUTION
    assert vulns[0].cwe_id == "CWE-1321"
    assert vulns[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_proto_key_literal_single_quotes(detector):
    content = "merge({ '__proto__': payload });"
    vulns = await detector.detect(Path("merge.js"), content)

    assert len(vulns) == 1
    assert "Prototype Pollution" in vulns[0].title


@pytest.mark.asyncio
async def test_proto_direct_assignment(detector):
    content = "obj.__proto__ = polluted;"
    vulns = await detector.detect(Path("bad.js"), content)

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_object_set_prototype_of(detector):
    content = "Object.setPrototypeOf(o, Evil);"
    vulns = await detector.detect(Path("hack.ts"), content)

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.MEDIUM
    assert vulns[0].confidence == Confidence.MEDIUM


@pytest.mark.asyncio
async def test_reflect_set_prototype_of(detector):
    content = "Reflect.setPrototypeOf(obj, proto);"
    vulns = await detector.detect(Path("hack.mjs"), content)

    assert len(vulns) == 1


@pytest.mark.asyncio
async def test_clean_code_no_findings(detector):
    content = """
const cfg = { role: "server", tools: ["a", "b"] };
export default cfg;
"""
    vulns = await detector.detect(Path("clean.ts"), content)

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_json_proto_key(detector):
    content = '{"__proto__": {"admin": true}}'
    vulns = await detector.detect(Path("evil.json"), content)

    assert len(vulns) == 1


@pytest.mark.asyncio
async def test_skip_js_line_comment(detector):
    content = '// "__proto__": harmless\nconst safe = 1;\n'
    vulns = await detector.detect(Path("fine.js"), content)

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_skip_proto_inside_block_comment_on_line(detector):
    content = 'const x = { /* "__proto__": true */ ok: 1 };'
    vulns = await detector.detect(Path("fine.js"), content)

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_deep_merge_with_req_body(detector):
    content = "_.defaultsDeep(cfg, req.body);"
    vulns = await detector.detect(Path("srv.ts"), content)

    assert len(vulns) == 1
    assert "deep merge" in vulns[0].title.lower()
    assert vulns[0].type == VulnerabilityType.PROTOTYPE_POLLUTION


@pytest.mark.asyncio
async def test_deep_merge_clean_two_locals_no_finding(detector):
    content = "_.merge(defaults, localOpts);"
    vulns = await detector.detect(Path("safe.js"), content)

    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_deep_merge_json_parse_hint(detector):
    content = 'lodash.merge(dst, JSON.parse(raw));'
    vulns = await detector.detect(Path("api.js"), content)

    assert len(vulns) == 1


@pytest.mark.asyncio
async def test_deep_merge_multiline_req_body(detector):
    content = """_.merge(
  defaults,
  req.body
);
"""
    vulns = await detector.detect(Path("routes.ts"), content)

    assert len(vulns) == 1
    assert vulns[0].line_number == 1
    assert "deep merge" in vulns[0].title.lower()
