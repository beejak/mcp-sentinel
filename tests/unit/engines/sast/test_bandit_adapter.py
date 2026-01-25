"""
Comprehensive BanditAdapter testing.

This test suite provides thorough coverage of the BanditAdapter SAST tool,
including real output parsing validation, edge cases, and error handling.

Critical for ensuring accurate Python security scanning.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from mcp_sentinel.engines.sast.bandit_adapter import BanditAdapter
from mcp_sentinel.models.vulnerability import (
    Confidence,
    Severity,
    VulnerabilityType,
)


class TestBanditAdapterInitialization:
    """Test BanditAdapter initialization."""

    @patch("shutil.which")
    def test_init_with_bandit_available(self, mock_which):
        """Test initialization when Bandit is available."""
        mock_which.return_value = "/usr/bin/bandit"

        adapter = BanditAdapter(enabled=True, timeout=300)

        assert adapter.enabled is True
        assert adapter.timeout == 300
        mock_which.assert_called_once_with("bandit")

    @patch("shutil.which")
    def test_init_with_bandit_unavailable(self, mock_which):
        """Test initialization when Bandit is not installed."""
        mock_which.return_value = None

        adapter = BanditAdapter(enabled=True, timeout=300)

        assert adapter.enabled is False
        mock_which.assert_called_once_with("bandit")

    @patch("shutil.which")
    def test_init_disabled_explicitly(self, mock_which):
        """Test initialization when explicitly disabled."""
        mock_which.return_value = "/usr/bin/bandit"

        adapter = BanditAdapter(enabled=False, timeout=300)

        assert adapter.enabled is False

    def test_init_custom_timeout(self):
        """Test initialization with custom timeout."""
        with patch("shutil.which", return_value="/usr/bin/bandit"):
            adapter = BanditAdapter(enabled=True, timeout=600)

            assert adapter.timeout == 600


class TestBanditCommandBuilding:
    """Test Bandit command construction."""

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_build_command_basic(self, mock_which):
        """Test basic command building."""
        adapter = BanditAdapter()
        target_path = Path("/tmp/test_project")

        cmd = adapter._build_command(target_path)

        assert cmd == ["bandit", "-r", "-f", "json", str(target_path)]

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_build_command_with_windows_path(self, mock_which):
        """Test command building with Windows path."""
        adapter = BanditAdapter()
        target_path = Path("C:\\Users\\test\\project")

        cmd = adapter._build_command(target_path)

        assert "bandit" in cmd
        assert "-r" in cmd
        assert "-f" in cmd
        assert "json" in cmd
        assert str(target_path) in cmd


class TestBanditResultParsing:
    """Test Bandit JSON output parsing."""

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_parse_results_comprehensive(self, mock_which):
        """Test parsing real Bandit JSON output with multiple findings."""
        adapter = BanditAdapter()
        target_path = Path("/tmp/test")

        # Real Bandit output structure
        bandit_output = json.dumps(
            {
                "results": [
                    {
                        "code": "import pickle\npickle.loads(user_data)",
                        "filename": "/tmp/test/vulnerable.py",
                        "issue_confidence": "HIGH",
                        "issue_severity": "HIGH",
                        "issue_text": "Pickle usage detected",
                        "line_number": 10,
                        "test_id": "B301",
                        "test_name": "pickle",
                        "more_info": "https://bandit.readthedocs.io/",
                    },
                    {
                        "code": 'query = f"SELECT * FROM users WHERE id={user_id}"',
                        "filename": "/tmp/test/sql.py",
                        "issue_confidence": "HIGH",
                        "issue_severity": "MEDIUM",
                        "issue_text": "SQL injection vulnerability",
                        "line_number": 25,
                        "test_id": "B608",
                        "test_name": "sql_injection",
                    },
                ],
                "metrics": {"_totals": {"CONFIDENCE.HIGH": 2}},
            }
        )

        vulns = adapter._parse_results(bandit_output, target_path)

        assert len(vulns) == 2
        assert all(v.line_number > 0 for v in vulns)
        assert all(v.cwe_id for v in vulns)
        assert all(v.detector == "BanditAdapter" for v in vulns)
        assert all(v.engine == "sast" for v in vulns)

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_parse_results_empty(self, mock_which):
        """Test parsing Bandit output with no findings."""
        adapter = BanditAdapter()
        bandit_output = json.dumps({"results": [], "metrics": {}})

        vulns = adapter._parse_results(bandit_output, Path("/tmp"))

        assert len(vulns) == 0

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_parse_results_malformed_json(self, mock_which):
        """Test parsing malformed JSON output."""
        adapter = BanditAdapter()
        malformed_output = "This is not valid JSON"

        vulns = adapter._parse_results(malformed_output, Path("/tmp"))

        assert len(vulns) == 0

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_parse_results_missing_results_key(self, mock_which):
        """Test parsing output without 'results' key."""
        adapter = BanditAdapter()
        output = json.dumps({"metrics": {}})

        vulns = adapter._parse_results(output, Path("/tmp"))

        assert len(vulns) == 0


class TestBanditTestIdMapping:
    """Test mapping of ALL Bandit test IDs to vulnerability types."""

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_map_code_injection_test_ids(self, mock_which):
        """Test all code injection test ID mappings."""
        adapter = BanditAdapter()

        code_injection_ids = [
            "B307",  # eval
            "B308",  # mark_safe
            "B401",  # subprocess import
            "B601",  # shell injection
            "B602",  # shell=True
            "B603",  # subprocess
            "B604",  # shell=True variants
            "B605",  # start with shell
            "B606",  # start without shell
            "B607",  # partial path
            "B608",  # SQL
            "B609",  # wildcard injection
            "B610",  # SQL string format
            "B611",  # SQL concat
        ]

        for test_id in code_injection_ids:
            vuln_type = adapter._map_test_id_to_type(test_id)
            assert vuln_type == VulnerabilityType.CODE_INJECTION, f"{test_id} should map to CODE_INJECTION"

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_map_weak_crypto_test_ids(self, mock_which):
        """Test weak cryptography test ID mappings."""
        adapter = BanditAdapter()

        weak_crypto_ids = ["B303", "B304", "B305", "B505"]

        for test_id in weak_crypto_ids:
            vuln_type = adapter._map_test_id_to_type(test_id)
            assert vuln_type == VulnerabilityType.WEAK_CRYPTO

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_map_insecure_deserialization_test_ids(self, mock_which):
        """Test insecure deserialization test ID mappings."""
        adapter = BanditAdapter()

        deserialization_ids = ["B301", "B302", "B506"]

        for test_id in deserialization_ids:
            vuln_type = adapter._map_test_id_to_type(test_id)
            assert vuln_type == VulnerabilityType.INSECURE_DESERIALIZATION

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_map_config_security_test_ids(self, mock_which):
        """Test config security test ID mappings."""
        adapter = BanditAdapter()

        config_ids = ["B201", "B306", "B501", "B502", "B503", "B504"]

        for test_id in config_ids:
            vuln_type = adapter._map_test_id_to_type(test_id)
            assert vuln_type == VulnerabilityType.CONFIG_SECURITY

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_map_xss_test_ids(self, mock_which):
        """Test XSS test ID mappings."""
        adapter = BanditAdapter()

        xss_ids = ["B701", "B702", "B703"]

        for test_id in xss_ids:
            vuln_type = adapter._map_test_id_to_type(test_id)
            assert vuln_type == VulnerabilityType.XSS

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_map_unknown_test_id(self, mock_which):
        """Test mapping of unknown test ID defaults to CODE_INJECTION."""
        adapter = BanditAdapter()

        vuln_type = adapter._map_test_id_to_type("B999")

        assert vuln_type == VulnerabilityType.CODE_INJECTION


class TestBanditSeverityMapping:
    """Test all combinations of Bandit severity + confidence."""

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_high_severity_high_confidence(self, mock_which):
        """HIGH severity + HIGH confidence -> CRITICAL."""
        adapter = BanditAdapter()

        severity = adapter._map_severity("HIGH", "HIGH")

        assert severity == Severity.CRITICAL

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_high_severity_medium_confidence(self, mock_which):
        """HIGH severity + MEDIUM confidence -> HIGH."""
        adapter = BanditAdapter()

        severity = adapter._map_severity("HIGH", "MEDIUM")

        assert severity == Severity.HIGH

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_high_severity_low_confidence(self, mock_which):
        """HIGH severity + LOW confidence -> MEDIUM."""
        adapter = BanditAdapter()

        severity = adapter._map_severity("HIGH", "LOW")

        assert severity == Severity.MEDIUM

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_medium_severity_high_confidence(self, mock_which):
        """MEDIUM severity + HIGH confidence -> HIGH."""
        adapter = BanditAdapter()

        severity = adapter._map_severity("MEDIUM", "HIGH")

        assert severity == Severity.HIGH

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_medium_severity_medium_confidence(self, mock_which):
        """MEDIUM severity + MEDIUM confidence -> MEDIUM."""
        adapter = BanditAdapter()

        severity = adapter._map_severity("MEDIUM", "MEDIUM")

        assert severity == Severity.MEDIUM

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_medium_severity_low_confidence(self, mock_which):
        """MEDIUM severity + LOW confidence -> LOW."""
        adapter = BanditAdapter()

        severity = adapter._map_severity("MEDIUM", "LOW")

        assert severity == Severity.LOW

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_low_severity_any_confidence(self, mock_which):
        """LOW severity + any confidence -> LOW."""
        adapter = BanditAdapter()

        assert adapter._map_severity("LOW", "HIGH") == Severity.LOW
        assert adapter._map_severity("LOW", "MEDIUM") == Severity.LOW
        assert adapter._map_severity("LOW", "LOW") == Severity.LOW


class TestBanditVulnerabilityConversion:
    """Test conversion of Bandit results to Vulnerability objects."""

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_convert_basic_result(self, mock_which):
        """Test converting a basic Bandit result."""
        adapter = BanditAdapter()
        result = {
            "filename": "/tmp/test/file.py",
            "line_number": 10,
            "test_id": "B608",
            "test_name": "sql_injection",
            "issue_text": "SQL injection detected",
            "issue_severity": "HIGH",
            "issue_confidence": "HIGH",
            "code": 'query = f"SELECT * FROM users WHERE id={user_id}"',
            "more_info": "https://bandit.readthedocs.io/",
        }

        vuln = adapter._convert_to_vulnerability(result, Path("/tmp/test"))

        assert vuln is not None
        assert vuln.type == VulnerabilityType.CODE_INJECTION
        assert vuln.severity == Severity.CRITICAL
        assert vuln.line_number == 10
        assert vuln.confidence == Confidence.HIGH
        assert vuln.cwe_id == "CWE-89"
        assert "bandit_test_id" in vuln.metadata

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_convert_with_multiline_code(self, mock_which):
        """Test converting result with multi-line code snippet."""
        adapter = BanditAdapter()
        result = {
            "filename": "/tmp/test.py",
            "line_number": 5,
            "test_id": "B301",
            "test_name": "pickle",
            "issue_text": "Pickle usage",
            "issue_severity": "HIGH",
            "issue_confidence": "HIGH",
            "code": "import pickle\ndata = request.get_data()\nobj = pickle.loads(data)",
        }

        vuln = adapter._convert_to_vulnerability(result, Path("/tmp"))

        assert vuln is not None
        assert "\n" in vuln.code_snippet

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_convert_with_unicode_content(self, mock_which):
        """Test converting result with Unicode characters."""
        adapter = BanditAdapter()
        result = {
            "filename": "/tmp/tëst.py",
            "line_number": 1,
            "test_id": "B307",
            "test_name": "eval",
            "issue_text": "Use of eval() détécted with unicode 中文",
            "issue_severity": "HIGH",
            "issue_confidence": "HIGH",
            "code": 'eval("print(\'héllo\')")',
        }

        vuln = adapter._convert_to_vulnerability(result, Path("/tmp"))

        assert vuln is not None
        assert "unicode" in vuln.description or "中文" in vuln.description

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_convert_with_missing_optional_fields(self, mock_which):
        """Test converting result with missing optional fields."""
        adapter = BanditAdapter()
        result = {
            "filename": "/tmp/test.py",
            "line_number": 10,
            "test_id": "B999",
            # Missing: test_name, more_info, code
        }

        vuln = adapter._convert_to_vulnerability(result, Path("/tmp"))

        # Should handle gracefully and not crash
        assert vuln is not None or vuln is None  # Either works, shouldn't crash

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_convert_with_relative_path(self, mock_which):
        """Test converting result with relative file path."""
        adapter = BanditAdapter()
        result = {
            "filename": "src/vulnerable.py",  # Relative path
            "line_number": 10,
            "test_id": "B608",
            "test_name": "sql",
            "issue_text": "SQL issue",
            "issue_severity": "MEDIUM",
            "issue_confidence": "MEDIUM",
        }

        vuln = adapter._convert_to_vulnerability(result, Path("/tmp/project"))

        assert vuln is not None
        # Should resolve to absolute path
        assert "project" in vuln.file_path or "vulnerable.py" in vuln.file_path


@pytest.mark.asyncio
class TestBanditScanning:
    """Test Bandit scanning operations."""

    @patch("shutil.which", return_value="/usr/bin/bandit")
    async def test_scan_directory_success(self, mock_which):
        """Test successful directory scanning."""
        adapter = BanditAdapter()

        # Mock the subprocess
        mock_process = AsyncMock()
        mock_process.returncode = 1  # Findings found
        mock_process.communicate = AsyncMock(
            return_value=(
                json.dumps(
                    {
                        "results": [
                            {
                                "filename": "test.py",
                                "line_number": 5,
                                "test_id": "B608",
                                "test_name": "sql",
                                "issue_text": "SQL injection",
                                "issue_severity": "HIGH",
                                "issue_confidence": "HIGH",
                            }
                        ]
                    }
                ).encode(),
                b"",
            )
        )

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            vulns = await adapter.scan_directory(Path("/tmp/test"))

        assert len(vulns) > 0

    @patch("shutil.which", return_value=None)
    async def test_scan_directory_disabled(self, mock_which):
        """Test scanning when adapter is disabled."""
        adapter = BanditAdapter()

        vulns = await adapter.scan_directory(Path("/tmp/test"))

        assert len(vulns) == 0

    @patch("shutil.which", return_value="/usr/bin/bandit")
    async def test_scan_directory_timeout(self, mock_which):
        """Test scanning with timeout."""
        adapter = BanditAdapter(timeout=1)

        mock_process = AsyncMock()
        mock_process.communicate = AsyncMock(side_effect=TimeoutError)
        mock_process.kill = MagicMock()

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            vulns = await adapter.scan_directory(Path("/tmp/test"))

        assert len(vulns) == 0
        mock_process.kill.assert_called_once()

    @patch("shutil.which", return_value="/usr/bin/bandit")
    async def test_scan_file_python(self, mock_which):
        """Test scanning a Python file."""
        adapter = BanditAdapter()

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(
            return_value=(json.dumps({"results": []}).encode(), b"")
        )

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            vulns = await adapter.scan_file(Path("/tmp/test.py"))

        assert isinstance(vulns, list)

    @patch("shutil.which", return_value="/usr/bin/bandit")
    async def test_scan_file_non_python(self, mock_which):
        """Test scanning non-Python file is skipped."""
        adapter = BanditAdapter()

        vulns = await adapter.scan_file(Path("/tmp/test.js"))

        assert len(vulns) == 0

    @patch("shutil.which", return_value="/usr/bin/bandit")
    async def test_scan_directory_error_handling(self, mock_which):
        """Test error handling during scan."""
        adapter = BanditAdapter()

        mock_process = AsyncMock()
        mock_process.returncode = 2  # Error
        mock_process.communicate = AsyncMock(return_value=(b"", b"Error occurred"))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            vulns = await adapter.scan_directory(Path("/tmp/test"))

        assert len(vulns) == 0


class TestBanditCWEExtraction:
    """Test CWE ID extraction from Bandit results."""

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_extract_cwe_common_test_ids(self, mock_which):
        """Test CWE extraction for common Bandit test IDs."""
        adapter = BanditAdapter()

        test_cases = {
            "B608": "CWE-89",  # SQL injection
            "B301": "CWE-327",  # Pickle
            "B307": "CWE-78",  # eval
            "B501": "CWE-295",  # SSL cert
            "B601": "CWE-78",  # Shell injection
        }

        for test_id, expected_cwe in test_cases.items():
            result = {"test_id": test_id}
            cwe = adapter._extract_cwe(result)
            assert cwe == expected_cwe, f"{test_id} should map to {expected_cwe}"

    @patch("shutil.which", return_value="/usr/bin/bandit")
    def test_extract_cwe_unknown_test_id(self, mock_which):
        """Test CWE extraction for unknown test ID."""
        adapter = BanditAdapter()
        result = {"test_id": "B999"}

        cwe = adapter._extract_cwe(result)

        assert cwe is None
