"""Tests for scan config fingerprint metadata."""

from mcp_sentinel.core.config import build_scan_config_metadata


def test_config_fingerprint_is_stable_for_equivalent_inputs():
    a = build_scan_config_metadata(
        scanner_kind="single-engine",
        target_path="repo",
        file_patterns=["**/*.py", "**/*.js"],
        detector_names=["SecretsDetector", "CodeInjectionDetector"],
        engine_names=["static"],
    )
    b = build_scan_config_metadata(
        scanner_kind="single-engine",
        target_path="repo",
        file_patterns=["**/*.js", "**/*.py"],
        detector_names=["CodeInjectionDetector", "SecretsDetector"],
        engine_names=["static"],
    )
    assert a["config_fingerprint"] == b["config_fingerprint"]


def test_config_fingerprint_changes_when_scan_inputs_change():
    base = build_scan_config_metadata(
        scanner_kind="single-engine",
        target_path="repo",
        file_patterns=["**/*.py"],
        detector_names=["SecretsDetector"],
        engine_names=["static"],
    )
    changed = build_scan_config_metadata(
        scanner_kind="single-engine",
        target_path="repo",
        file_patterns=["**/*.py", "**/*.json"],
        detector_names=["SecretsDetector"],
        engine_names=["static"],
    )
    assert base["config_fingerprint"] != changed["config_fingerprint"]
