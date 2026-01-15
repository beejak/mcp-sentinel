"""
Unit tests for SupplyChainDetector.

Tests all 11 patterns for supply chain security detection.
"""

import pytest
import json
from pathlib import Path
from typing import List

from mcp_sentinel.detectors.supply_chain import SupplyChainDetector
from mcp_sentinel.models.vulnerability import (
    Vulnerability,
    VulnerabilityType,
    Severity,
    Confidence,
)


@pytest.fixture
def detector():
    """Create a SupplyChainDetector instance for testing."""
    return SupplyChainDetector()


@pytest.fixture
def malicious_package_json_path():
    """Path to malicious package.json fixture."""
    return Path(__file__).parent.parent / "fixtures" / "malicious_package.json"


@pytest.fixture
def malicious_requirements_path():
    """Path to malicious requirements.txt fixture."""
    return Path(__file__).parent.parent / "fixtures" / "malicious_requirements.txt"


# ============================================================================
# Known Malicious Packages Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_known_malicious_npm_package(detector):
    """Test detection of known malicious npm package."""
    content = """
    {
      "dependencies": {
        "bitcoin-miner": "1.0.0"
      }
    }
    """
    vulns = await detector.detect(Path("package.json"), content)

    malicious = [v for v in vulns if "Known Malicious Package" in v.title]
    assert len(malicious) >= 1
    assert malicious[0].severity == Severity.CRITICAL
    assert malicious[0].cvss_score == 10.0
    assert malicious[0].cwe_id == "CWE-506"


@pytest.mark.asyncio
async def test_detect_known_malicious_python_package(detector):
    """Test detection of known malicious Python package."""
    content = "bitcoin-miner==1.0.0\nrequests==2.28.0"
    vulns = await detector.detect(Path("requirements.txt"), content)

    malicious = [v for v in vulns if "Known Malicious Package" in v.title]
    assert len(malicious) >= 1


# ============================================================================
# Typosquatting Detection Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_requests_typosquatting(detector):
    """Test detection of 'requestes' typosquatting 'requests'."""
    content = """
    {
      "dependencies": {
        "requestes": "2.28.0"
      }
    }
    """
    vulns = await detector.detect(Path("package.json"), content)

    typo = [v for v in vulns if "Typosquatting" in v.title]
    assert len(typo) >= 1
    assert typo[0].severity == Severity.CRITICAL
    assert "requests" in typo[0].description
    assert typo[0].cvss_score >= 9.0


@pytest.mark.asyncio
async def test_detect_urllib3_typosquatting(detector):
    """Test detection of 'urlib3' typosquatting 'urllib3'."""
    content = "urlib3==1.26.0\n"
    vulns = await detector.detect(Path("requirements.txt"), content)

    typo = [v for v in vulns if "Typosquatting" in v.title]
    assert len(typo) >= 1
    assert "urllib3" in typo[0].description


@pytest.mark.asyncio
async def test_detect_express_typosquatting(detector):
    """Test detection of 'expres' typosquatting 'express'."""
    content = """
    {
      "dependencies": {
        "expres": "4.18.0"
      }
    }
    """
    vulns = await detector.detect(Path("package.json"), content)

    typo = [v for v in vulns if "Typosquatting" in v.title]
    assert len(typo) >= 1


@pytest.mark.asyncio
async def test_detect_lodash_typosquatting(detector):
    """Test detection of 'loadsh' typosquatting 'lodash'."""
    content = """
    {
      "dependencies": {
        "loadsh": "4.17.21"
      }
    }
    """
    vulns = await detector.detect(Path("package.json"), content)

    typo = [v for v in vulns if "Typosquatting" in v.title]
    assert len(typo) >= 1
    assert "lodash" in typo[0].description


# ============================================================================
# Suspicious Package Names Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_suspicious_miner_package(detector):
    """Test detection of suspicious 'miner' keyword."""
    content = "crypto-miner==0.1.0\n"
    vulns = await detector.detect(Path("requirements.txt"), content)

    suspicious = [v for v in vulns if "Suspicious Package Name" in v.title]
    assert len(suspicious) >= 1
    assert suspicious[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_detect_suspicious_backdoor_package(detector):
    """Test detection of suspicious 'backdoor' keyword."""
    content = """
    {
      "dependencies": {
        "express-backdoor": "1.0.0"
      }
    }
    """
    vulns = await detector.detect(Path("package.json"), content)

    suspicious = [v for v in vulns if "Suspicious Package Name" in v.title]
    assert len(suspicious) >= 1


@pytest.mark.asyncio
async def test_detect_suspicious_keylogger_package(detector):
    """Test detection of suspicious 'keylogger' keyword."""
    content = "keylogger-test==1.0.0\n"
    vulns = await detector.detect(Path("requirements.txt"), content)

    suspicious = [v for v in vulns if "Suspicious Package Name" in v.title]
    assert len(suspicious) >= 1


# ============================================================================
# Wildcard Version Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_wildcard_asterisk(detector):
    """Test detection of asterisk wildcard version."""
    content = """
    {
      "dependencies": {
        "express": "*"
      }
    }
    """
    vulns = await detector.detect(Path("package.json"), content)

    wildcard = [v for v in vulns if "Wildcard Version" in v.title]
    assert len(wildcard) >= 1
    assert wildcard[0].severity == Severity.LOW


@pytest.mark.asyncio
async def test_detect_wildcard_latest(detector):
    """Test detection of 'latest' version."""
    content = """
    {
      "dependencies": {
        "react": "latest"
      }
    }
    """
    vulns = await detector.detect(Path("package.json"), content)

    wildcard = [v for v in vulns if "Wildcard Version" in v.title]
    assert len(wildcard) >= 1


@pytest.mark.asyncio
async def test_detect_wildcard_caret(detector):
    """Test detection of caret (^) version."""
    content = """
    {
      "dependencies": {
        "vue": "^3.2.0"
      }
    }
    """
    vulns = await detector.detect(Path("package.json"), content)

    wildcard = [v for v in vulns if "Wildcard Version" in v.title]
    assert len(wildcard) >= 1


@pytest.mark.asyncio
async def test_detect_wildcard_tilde(detector):
    """Test detection of tilde (~) version."""
    content = """
    {
      "dependencies": {
        "axios": "~1.3.0"
      }
    }
    """
    vulns = await detector.detect(Path("package.json"), content)

    wildcard = [v for v in vulns if "Wildcard Version" in v.title]
    assert len(wildcard) >= 1


# ============================================================================
# Pre-release Version Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_alpha_version(detector):
    """Test detection of alpha version."""
    content = """
    {
      "dependencies": {
        "next": "13.0.0-alpha.1"
      }
    }
    """
    vulns = await detector.detect(Path("package.json"), content)

    prerelease = [v for v in vulns if "Pre-release Version" in v.title]
    assert len(prerelease) >= 1
    assert prerelease[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_detect_beta_version(detector):
    """Test detection of beta version."""
    content = """
    {
      "dependencies": {
        "typescript": "5.0.0-beta"
      }
    }
    """
    vulns = await detector.detect(Path("package.json"), content)

    prerelease = [v for v in vulns if "Pre-release Version" in v.title]
    assert len(prerelease) >= 1


@pytest.mark.asyncio
async def test_detect_rc_version(detector):
    """Test detection of release candidate version."""
    content = """
    {
      "dependencies": {
        "webpack": "5.75.0-rc.1"
      }
    }
    """
    vulns = await detector.detect(Path("package.json"), content)

    prerelease = [v for v in vulns if "Pre-release Version" in v.title]
    assert len(prerelease) >= 1


# ============================================================================
# HTTP Source Detection Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_http_package_source(detector):
    """Test detection of HTTP (non-HTTPS) package source."""
    content = """
    {
      "dependencies": {
        "custom-package": "http://example.com/package.tar.gz"
      }
    }
    """
    vulns = await detector.detect(Path("package.json"), content)

    http = [v for v in vulns if "HTTP Package Source" in v.title or "Insecure HTTP" in v.title]
    assert len(http) >= 1
    assert http[0].severity == Severity.HIGH


# ============================================================================
# Git Source Detection Tests
# ============================================================================


@pytest.mark.asyncio
async def test_detect_untrusted_git_source(detector):
    """Test detection of Git dependency from untrusted source."""
    content = """
    {
      "dependencies": {
        "suspicious-package": "git://unknown-server.com/package.git"
      }
    }
    """
    vulns = await detector.detect(Path("package.json"), content)

    git = [v for v in vulns if "Untrusted Git" in v.title or "Git Dependency Source" in v.title]
    assert len(git) >= 1
    assert git[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_allow_github_git_source(detector):
    """Test that GitHub sources are not flagged."""
    content = """
    {
      "dependencies": {
        "package": "git+https://github.com/user/repo.git"
      }
    }
    """
    vulns = await detector.detect(Path("package.json"), content)

    # Should NOT flag GitHub
    git = [v for v in vulns if "Untrusted Git" in v.title]
    assert len(git) == 0


# ============================================================================
# File Type Detection Tests
# ============================================================================


def test_is_applicable_package_json(detector):
    """Test that detector applies to package.json."""
    assert detector.is_applicable(Path("package.json")) is True
    assert detector.is_applicable(Path("package-lock.json")) is True


def test_is_applicable_python_files(detector):
    """Test that detector applies to Python dependency files."""
    assert detector.is_applicable(Path("requirements.txt")) is True
    assert detector.is_applicable(Path("Pipfile")) is True
    assert detector.is_applicable(Path("pyproject.toml")) is True


def test_is_applicable_other_package_managers(detector):
    """Test that detector applies to other package managers."""
    assert detector.is_applicable(Path("yarn.lock")) is True
    assert detector.is_applicable(Path("Gemfile")) is True
    assert detector.is_applicable(Path("Cargo.toml")) is True


def test_not_applicable_code_files(detector):
    """Test that detector does not apply to code files."""
    assert detector.is_applicable(Path("app.py")) is False
    assert detector.is_applicable(Path("index.js")) is False
    assert detector.is_applicable(Path("README.md")) is False


# ============================================================================
# Integration Tests
# ============================================================================


@pytest.mark.asyncio
async def test_malicious_package_json_fixture(detector, malicious_package_json_path):
    """Test detection against malicious package.json fixture."""
    content = malicious_package_json_path.read_text()
    vulns = await detector.detect(malicious_package_json_path, content)

    # Should detect multiple issues
    assert len(vulns) >= 5

    # Check for different vulnerability types
    titles = {v.title for v in vulns}
    assert any("Typosquatting" in t or "Malicious" in t or "Suspicious" in t for t in titles)


@pytest.mark.asyncio
async def test_malicious_requirements_fixture(detector, malicious_requirements_path):
    """Test detection against malicious requirements.txt fixture."""
    content = malicious_requirements_path.read_text()
    vulns = await detector.detect(malicious_requirements_path, content)

    # Should detect multiple issues
    assert len(vulns) >= 4

    # Should find typosquatting and malicious packages
    assert any("Typosquatting" in v.title for v in vulns)
    assert any("Malicious" in v.title or "Suspicious" in v.title for v in vulns)


@pytest.mark.asyncio
async def test_clean_package_json(detector):
    """Test that clean package.json has no issues."""
    content = """
    {
      "dependencies": {
        "express": "4.18.2",
        "axios": "1.3.4"
      }
    }
    """
    vulns = await detector.detect(Path("package.json"), content)

    # Clean packages should have no vulnerabilities
    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_clean_requirements_txt(detector):
    """Test that clean requirements.txt has no issues."""
    content = """requests==2.28.2
flask==2.2.3
numpy==1.24.0
"""
    vulns = await detector.detect(Path("requirements.txt"), content)

    assert len(vulns) == 0


# ============================================================================
# Edge Case Tests
# ============================================================================


@pytest.mark.asyncio
async def test_comments_in_requirements(detector):
    """Test that comments in requirements.txt are ignored."""
    content = """# This is a comment
requests==2.28.0
# Another comment
flask>=2.0.0
"""
    vulns = await detector.detect(Path("requirements.txt"), content)

    # Should only check actual packages, not comments
    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_invalid_json(detector):
    """Test that invalid JSON doesn't crash the detector."""
    content = "{ invalid json"
    vulns = await detector.detect(Path("package.json"), content)

    # Should handle gracefully
    assert isinstance(vulns, list)


@pytest.mark.asyncio
async def test_empty_package_json(detector):
    """Test that empty package.json is handled."""
    content = "{}"
    vulns = await detector.detect(Path("package.json"), content)

    assert len(vulns) == 0


# ============================================================================
# Metadata Tests
# ============================================================================


def test_detector_name(detector):
    """Test that detector has correct name."""
    assert detector.name == "SupplyChainDetector"


def test_detector_enabled_by_default(detector):
    """Test that detector is enabled by default."""
    assert detector.enabled is True


@pytest.mark.asyncio
async def test_vulnerability_metadata_complete(detector):
    """Test that vulnerabilities have complete metadata."""
    content = """
    {
      "dependencies": {
        "bitcoin-miner": "1.0.0"
      }
    }
    """
    vulns = await detector.detect(Path("package.json"), content)

    assert len(vulns) >= 1
    vuln = vulns[0]

    # Check all required fields
    assert vuln.type == VulnerabilityType.SUPPLY_CHAIN
    assert vuln.title is not None
    assert len(vuln.title) > 0
    assert vuln.description is not None
    assert len(vuln.description) > 50
    assert vuln.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    assert vuln.confidence in [Confidence.HIGH, Confidence.MEDIUM]
    assert vuln.cwe_id is not None
    assert vuln.cwe_id.startswith("CWE-")
    assert vuln.cvss_score > 0
    assert vuln.remediation is not None
    assert len(vuln.remediation) > 30
    assert len(vuln.references) >= 2
    assert vuln.detector == "SupplyChainDetector"
    assert vuln.engine == "static"
    assert len(vuln.mitre_attack_ids) > 0
    assert "T1195" in vuln.mitre_attack_ids[0]


@pytest.mark.asyncio
async def test_remediation_guidance(detector):
    """Test that remediation guidance is provided."""
    content = "requestes==2.28.0"
    vulns = await detector.detect(Path("requirements.txt"), content)

    assert len(vulns) >= 1
    assert "1." in vulns[0].remediation
    assert len(vulns[0].remediation.split("\n")) >= 3


@pytest.mark.asyncio
async def test_references_included(detector):
    """Test that references are included."""
    content = "bitcoin-miner==1.0.0"
    vulns = await detector.detect(Path("requirements.txt"), content)

    assert len(vulns) >= 1
    assert len(vulns[0].references) >= 2
