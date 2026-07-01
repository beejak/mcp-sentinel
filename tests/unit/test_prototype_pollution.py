"""Tests for PrototypePollutionDetector."""

from pathlib import Path

import pytest

from mcp_sentinel.detectors.prototype_pollution import PrototypePollutionDetector


@pytest.fixture
def detector():
    return PrototypePollutionDetector()


def test_object_assign_json_parse_fires(detector):
    code = "Object.assign(globalObj, JSON.parse(userInput));"
    results = detector.detect_sync(Path("test.js"), code)
    assert len(results) >= 1


def test_proto_key_direct_fires(detector):
    code = 'target["__proto__"] = { isAdmin: true };'
    results = detector.detect_sync(Path("test.js"), code)
    assert len(results) >= 1


def test_merge_without_guard_fires(detector):
    code = """
function merge(target, source) {
  for (const key of Object.keys(source)) {
    target[key] = source[key];
  }
}
"""
    results = detector.detect_sync(Path("test.ts"), code)
    assert len(results) >= 1


def test_with_proto_guard_clean(detector):
    code = """
function merge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__') continue;
    target[key] = source[key];
  }
}
"""
    results = detector.detect_sync(Path("test.ts"), code)
    # With guard, should not fire on target[key] =
    proto_findings = [
        r for r in results
        if "prototype" in r.description.lower() or "merge" in r.title.lower()
    ]
    assert len(proto_findings) == 0


def test_safe_object_assign_literal_clean(detector):
    code = "Object.assign({}, { a: 1 });"
    results = detector.detect_sync(Path("test.js"), code)
    assert len(results) == 0


def test_non_js_file_ignored(detector):
    code = "Object.assign(t, JSON.parse(x));"
    results = detector.detect_sync(Path("test.py"), code)
    assert len(results) == 0
