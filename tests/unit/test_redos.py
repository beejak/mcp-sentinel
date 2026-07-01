"""Tests for ReDoSDetector."""

from pathlib import Path

import pytest

from mcp_sentinel.detectors.redos import ReDoSDetector


@pytest.fixture
def detector():
    return ReDoSDetector()


def test_js_nested_quantifier_fires(detector):
    code = "const re = /(a+)+$/;"
    results = detector.detect_sync(Path("test.js"), code)
    assert len(results) >= 1


def test_js_word_nested_fires(detector):
    code = r"const re = /^(\w+)*!/;"
    results = detector.detect_sync(Path("test.js"), code)
    assert len(results) >= 1


def test_py_nested_quantifier_fires(detector):
    code = 're.compile(r"^(a+)+$")'
    results = detector.detect_sync(Path("test.py"), code)
    assert len(results) >= 1


def test_js_safe_bounded_clean(detector):
    code = "const re = /^[a-z0-9]{1,64}$/;"
    results = detector.detect_sync(Path("test.js"), code)
    assert len(results) == 0


def test_js_simple_quantifier_clean(detector):
    code = r"const re = /^\d+$/;"
    results = detector.detect_sync(Path("test.js"), code)
    assert len(results) == 0


def test_py_digit_nested_fires(detector):
    code = 're.compile(r"^(\\d+)*#$")'
    results = detector.detect_sync(Path("test.py"), code)
    assert len(results) >= 1
