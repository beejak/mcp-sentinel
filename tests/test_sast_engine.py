"""
Unit tests for SAST Engine and adapters.
"""

import pytest
import asyncio
import json
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock, MagicMock
import sys

from mcp_sentinel.engines.sast.sast_engine import SASTEngine
from mcp_sentinel.engines.sast.semgrep_adapter import SemgrepAdapter
from mcp_sentinel.engines.sast.bandit_adapter import BanditAdapter
from mcp_sentinel.models.vulnerability import Vulnerability, Severity, VulnerabilityType, Confidence
from mcp_sentinel.engines.base import EngineType, EngineStatus


class TestSemgrepAdapter:
    """Tests for Semgrep adapter."""

    def test_initialization_when_semgrep_available(self):
        """Test adapter initializes when Semgrep is available."""
        with patch("shutil.which", return_value="/usr/bin/semgrep"):
            adapter = SemgrepAdapter(enabled=True)
            assert adapter.enabled is True
            assert adapter.rulesets == [
                "p/security-audit",
                "p/owasp-top-10",
                "p/command-injection",
            ]

    def test_initialization_when_semgrep_not_available(self):
        """Test adapter disables when Semgrep not available."""
        with patch("shutil.which", return_value=None):
            adapter = SemgrepAdapter(enabled=True)
            assert adapter.enabled is False

    def test_custom_rulesets(self):
        """Test custom rulesets configuration."""
        with patch("shutil.which", return_value="/usr/bin/semgrep"):
            custom_rules = ["p/security-audit", "p/python"]
            adapter = SemgrepAdapter(enabled=True, rulesets=custom_rules)
            assert adapter.rulesets == custom_rules

    def test_build_command(self):
        """Test Semgrep command building."""
        with patch("shutil.which", return_value="/usr/bin/semgrep"):
            adapter = SemgrepAdapter(enabled=True)
            target = Path("/test/path")
            cmd = adapter._build_command(target)

            assert cmd[0] == "semgrep"
            assert "scan" in cmd
            assert "--json" in cmd
            assert "--config" in cmd
            assert str(target) in cmd

    def test_severity_mapping(self):
        """Test Semgrep severity to MCP Sentinel severity mapping."""
        with patch("shutil.which", return_value="/usr/bin/semgrep"):
            adapter = SemgrepAdapter(enabled=True)

            assert adapter._map_severity("ERROR") == Severity.HIGH
            assert adapter._map_severity("WARNING") == Severity.MEDIUM
            assert adapter._map_severity("INFO") == Severity.LOW
            assert adapter._map_severity("UNKNOWN") == Severity.MEDIUM

    def test_cwe_extraction(self):
        """Test CWE extraction from metadata."""
        with patch("shutil.which", return_value="/usr/bin/semgrep"):
            adapter = SemgrepAdapter(enabled=True)

            # Test list format
            metadata1 = {"cwe": [89]}
            assert adapter._extract_cwe(metadata1) == "CWE-89"

            # Test string format
            metadata2 = {"cwe-id": "CWE-79"}
            assert adapter._extract_cwe(metadata2) == "CWE-79"

            # Test OWASP format
            metadata3 = {"owasp": {"cwe": "CWE-22"}}
            assert adapter._extract_cwe(metadata3) == "CWE-22"

            # Test no CWE
            metadata4 = {}
            assert adapter._extract_cwe(metadata4) is None

    @pytest.mark.asyncio
    async def test_scan_directory_when_disabled(self):
        """Test scan returns empty list when disabled."""
        with patch("shutil.which", return_value=None):
            adapter = SemgrepAdapter(enabled=True)
            result = await adapter.scan_directory(Path("/test"))
            assert result == []

    @pytest.mark.asyncio
    async def test_scan_directory_timeout(self):
        """Test scan handles timeout gracefully."""
        with patch("shutil.which", return_value="/usr/bin/semgrep"):
            adapter = SemgrepAdapter(enabled=True, timeout=1)

            # Mock asyncio.create_subprocess_exec to timeout
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
            mock_process.kill = Mock()

            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                result = await adapter.scan_directory(Path("/test"))
                assert result == []
                mock_process.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_directory_success(self, temp_dir):
        """Test successful scan with mock Semgrep output."""
        with patch("shutil.which", return_value="/usr/bin/semgrep"):
            adapter = SemgrepAdapter(enabled=True)

            # Mock Semgrep JSON output
            semgrep_output = {
                "results": [
                    {
                        "path": "test.py",
                        "start": {"line": 10},
                        "check_id": "python.lang.security.sql-injection",
                        "extra": {
                            "message": "SQL injection detected",
                            "severity": "ERROR",
                            "metadata": {"cwe": [89]},
                            "lines": "cursor.execute(query)",
                        }
                    }
                ]
            }

            # Mock subprocess
            mock_process = AsyncMock()
            mock_process.returncode = 1  # Findings found
            mock_process.communicate = AsyncMock(
                return_value=(json.dumps(semgrep_output).encode(), b"")
            )

            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                result = await adapter.scan_directory(temp_dir)

                assert len(result) == 1
                vuln = result[0]
                assert vuln.type == VulnerabilityType.CODE_INJECTION  # SQL injection maps to CODE_INJECTION
                assert vuln.severity == Severity.HIGH
                assert vuln.line_number == 10
                assert vuln.cwe_id == "CWE-89"
                assert vuln.engine == "sast"
                assert vuln.detector == "SemgrepAdapter"
                assert vuln.confidence == Confidence.HIGH


class TestBanditAdapter:
    """Tests for Bandit adapter."""

    def test_initialization_when_bandit_available(self):
        """Test adapter initializes when Bandit is available."""
        with patch("shutil.which", return_value="/usr/bin/bandit"):
            adapter = BanditAdapter(enabled=True)
            assert adapter.enabled is True

    def test_initialization_when_bandit_not_available(self):
        """Test adapter disables when Bandit not available."""
        with patch("shutil.which", return_value=None):
            adapter = BanditAdapter(enabled=True)
            assert adapter.enabled is False

    def test_build_command(self):
        """Test Bandit command building."""
        with patch("shutil.which", return_value="/usr/bin/bandit"):
            adapter = BanditAdapter(enabled=True)
            target = Path("/test/path")
            cmd = adapter._build_command(target)

            assert cmd[0] == "bandit"
            assert "-r" in cmd
            assert "-f" in cmd
            assert "json" in cmd
            assert str(target) in cmd

    def test_severity_mapping(self):
        """Test Bandit severity+confidence to MCP Sentinel severity mapping."""
        with patch("shutil.which", return_value="/usr/bin/bandit"):
            adapter = BanditAdapter(enabled=True)

            # HIGH + HIGH -> CRITICAL
            assert adapter._map_severity("HIGH", "HIGH") == Severity.CRITICAL

            # HIGH + MEDIUM -> HIGH
            assert adapter._map_severity("HIGH", "MEDIUM") == Severity.HIGH

            # HIGH + LOW -> MEDIUM
            assert adapter._map_severity("HIGH", "LOW") == Severity.MEDIUM

            # MEDIUM + HIGH -> HIGH
            assert adapter._map_severity("MEDIUM", "HIGH") == Severity.HIGH

            # MEDIUM + MEDIUM -> MEDIUM
            assert adapter._map_severity("MEDIUM", "MEDIUM") == Severity.MEDIUM

            # MEDIUM + LOW -> LOW
            assert adapter._map_severity("MEDIUM", "LOW") == Severity.LOW

            # LOW -> LOW
            assert adapter._map_severity("LOW", "HIGH") == Severity.LOW

    def test_cwe_extraction(self):
        """Test CWE extraction from Bandit test IDs."""
        with patch("shutil.which", return_value="/usr/bin/bandit"):
            adapter = BanditAdapter(enabled=True)

            # Known test IDs
            assert adapter._extract_cwe({"test_id": "B608"}) == "CWE-89"  # SQL injection
            assert adapter._extract_cwe({"test_id": "B601"}) == "CWE-78"  # Shell injection
            assert adapter._extract_cwe({"test_id": "B501"}) == "CWE-295"  # SSL cert
            assert adapter._extract_cwe({"test_id": "B311"}) == "CWE-330"  # Random

            # Unknown test ID
            assert adapter._extract_cwe({"test_id": "B999"}) is None

    @pytest.mark.asyncio
    async def test_scan_file_non_python(self):
        """Test scan skips non-Python files."""
        with patch("shutil.which", return_value="/usr/bin/bandit"):
            adapter = BanditAdapter(enabled=True)
            result = await adapter.scan_file(Path("/test/file.js"))
            assert result == []

    @pytest.mark.asyncio
    async def test_scan_directory_when_disabled(self):
        """Test scan returns empty list when disabled."""
        with patch("shutil.which", return_value=None):
            adapter = BanditAdapter(enabled=True)
            result = await adapter.scan_directory(Path("/test"))
            assert result == []

    @pytest.mark.asyncio
    async def test_scan_directory_success(self, temp_dir):
        """Test successful scan with mock Bandit output."""
        with patch("shutil.which", return_value="/usr/bin/bandit"):
            adapter = BanditAdapter(enabled=True)

            # Mock Bandit JSON output
            bandit_output = {
                "results": [
                    {
                        "filename": "test.py",
                        "line_number": 15,
                        "test_id": "B608",
                        "test_name": "hardcoded_sql_expressions",
                        "issue_text": "Possible SQL injection vector",
                        "issue_severity": "HIGH",
                        "issue_confidence": "HIGH",
                        "code": "cursor.execute(query)",
                        "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b608.html"
                    }
                ]
            }

            # Mock subprocess
            mock_process = AsyncMock()
            mock_process.returncode = 1  # Issues found
            mock_process.communicate = AsyncMock(
                return_value=(json.dumps(bandit_output).encode(), b"")
            )

            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                result = await adapter.scan_directory(temp_dir)

                assert len(result) == 1
                vuln = result[0]
                assert vuln.type == VulnerabilityType.CODE_INJECTION  # B608 maps to CODE_INJECTION
                assert vuln.severity == Severity.CRITICAL
                assert vuln.line_number == 15
                assert vuln.cwe_id == "CWE-89"
                assert vuln.engine == "sast"
                assert vuln.detector == "BanditAdapter"
                assert vuln.confidence == Confidence.HIGH


class TestSASTEngine:
    """Tests for SAST Engine."""

    def test_initialization_with_both_tools(self):
        """Test engine initializes with both tools available."""
        with patch("shutil.which") as mock_which:
            mock_which.side_effect = lambda x: f"/usr/bin/{x}"

            engine = SASTEngine(enabled=True)

            assert engine.enabled is True
            assert engine.semgrep_available is True
            assert engine.bandit_available is True
            assert engine.semgrep is not None
            assert engine.bandit is not None

    def test_initialization_with_no_tools(self):
        """Test engine disables when no tools available."""
        with patch("shutil.which", return_value=None):
            engine = SASTEngine(enabled=True)

            assert engine.enabled is False
            assert engine.semgrep_available is False
            assert engine.bandit_available is False

    def test_initialization_with_only_semgrep(self):
        """Test engine works with only Semgrep."""
        with patch("shutil.which") as mock_which:
            mock_which.side_effect = lambda x: "/usr/bin/semgrep" if x == "semgrep" else None

            engine = SASTEngine(enabled=True)

            assert engine.enabled is True
            assert engine.semgrep_available is True
            assert engine.bandit_available is False

    def test_engine_type(self):
        """Test engine has correct type."""
        with patch("shutil.which", return_value="/usr/bin/semgrep"):
            engine = SASTEngine(enabled=True)
            assert engine.engine_type == EngineType.SAST

    def test_supported_languages(self):
        """Test supported languages list."""
        with patch("shutil.which") as mock_which:
            mock_which.side_effect = lambda x: f"/usr/bin/{x}"

            engine = SASTEngine(enabled=True)
            languages = engine.get_supported_languages()

            assert "python" in languages
            assert "javascript" in languages
            assert "go" in languages

    def test_is_applicable(self):
        """Test is_applicable check."""
        with patch("shutil.which") as mock_which:
            mock_which.side_effect = lambda x: f"/usr/bin/{x}"

            engine = SASTEngine(enabled=True)

            # With Semgrep available, all files applicable
            assert engine.is_applicable(Path("test.py"), "python") is True
            assert engine.is_applicable(Path("test.js"), "javascript") is True

    @pytest.mark.asyncio
    async def test_scan_directory_delegates_to_adapters(self, temp_dir):
        """Test scan_directory delegates to both adapters."""
        with patch("shutil.which") as mock_which:
            mock_which.side_effect = lambda x: f"/usr/bin/{x}"

            engine = SASTEngine(enabled=True)

            # Mock adapters
            engine.semgrep.scan_directory = AsyncMock(return_value=[
                Vulnerability(
                    type=VulnerabilityType.CODE_INJECTION,
                    severity=Severity.HIGH,
                    title="Semgrep Test",
                    description="Test vuln",
                    file_path=str(temp_dir / "test.py"),
                    line_number=10,
                    detector="SemgrepAdapter",
                    engine="sast"
                )
            ])

            engine.bandit.scan_directory = AsyncMock(return_value=[
                Vulnerability(
                    type=VulnerabilityType.WEAK_CRYPTO,
                    severity=Severity.MEDIUM,
                    title="Bandit Test",
                    description="Test vuln",
                    file_path=str(temp_dir / "test.py"),
                    line_number=20,
                    detector="BanditAdapter",
                    engine="sast"
                )
            ])

            result = await engine.scan_directory(temp_dir)

            assert len(result) == 2
            assert engine.semgrep.scan_directory.called
            assert engine.bandit.scan_directory.called
            assert engine.status == EngineStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_scan_directory_handles_adapter_failure(self, temp_dir):
        """Test scan continues when one adapter fails."""
        with patch("shutil.which") as mock_which:
            mock_which.side_effect = lambda x: f"/usr/bin/{x}"

            engine = SASTEngine(enabled=True)

            # Semgrep succeeds
            engine.semgrep.scan_directory = AsyncMock(return_value=[
                Vulnerability(
                    type=VulnerabilityType.CODE_INJECTION,
                    severity=Severity.HIGH,
                    title="Test",
                    description="Test",
                    file_path=str(temp_dir / "test.py"),
                    line_number=10,
                    detector="SemgrepAdapter",
                    engine="sast"
                )
            ])

            # Bandit fails
            engine.bandit.scan_directory = AsyncMock(side_effect=Exception("Bandit error"))

            result = await engine.scan_directory(temp_dir)

            # Should still get Semgrep results
            assert len(result) == 1
            assert result[0].type == VulnerabilityType.CODE_INJECTION

    def test_string_representation(self):
        """Test __str__ method."""
        with patch("shutil.which") as mock_which:
            mock_which.side_effect = lambda x: f"/usr/bin/{x}"

            engine = SASTEngine(enabled=True)
            str_repr = str(engine)

            assert "SAST Engine" in str_repr
            assert "Semgrep" in str_repr
            assert "Bandit" in str_repr
