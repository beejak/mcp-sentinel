"""
Secrets detector for finding hardcoded credentials and API keys.
"""

import re
from typing import List, Dict, Pattern
from pathlib import Path

from mcp_sentinel.detectors.base import BaseDetector
from mcp_sentinel.models.vulnerability import (
    Vulnerability,
    VulnerabilityType,
    Severity,
    Confidence,
)


class SecretsDetector(BaseDetector):
    """
    Detector for hardcoded secrets, API keys, and credentials.

    Detects 15+ types of secrets:
    - AWS keys
    - OpenAI/Anthropic API keys
    - Private keys (RSA, EC, SSH)
    - JWT tokens
    - Database credentials
    - GitHub tokens
    - And more...
    """

    def __init__(self):
        """Initialize the secrets detector."""
        super().__init__(name="SecretsDetector", enabled=True)
        self.patterns: Dict[str, Pattern] = self._compile_patterns()

    def _compile_patterns(self) -> Dict[str, Pattern]:
        """Compile regex patterns for secret detection."""
        return {
            # AWS Access Keys
            "aws_access_key": re.compile(r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),

            # AWS Secret Keys
            "aws_secret_key": re.compile(r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"),

            # OpenAI API Keys
            "openai_api_key": re.compile(r"sk-[a-zA-Z0-9]{48}"),
            "openai_legacy_key": re.compile(r"sk-[a-zA-Z0-9]{32}"),

            # Anthropic Claude API Keys
            "anthropic_api_key": re.compile(r"sk-ant-api03-[a-zA-Z0-9\-_]{95,}"),

            # Google API Keys
            "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),

            # GitHub Personal Access Tokens
            "github_token": re.compile(r"ghp_[0-9a-zA-Z]{36}"),
            "github_oauth": re.compile(r"gho_[0-9a-zA-Z]{36}"),

            # Slack Tokens
            "slack_token": re.compile(r"xox[baprs]-([0-9a-zA-Z]{10,48})"),

            # JWT Tokens
            "jwt_token": re.compile(r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"),

            # RSA Private Keys
            "rsa_private_key": re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),

            # EC Private Keys
            "ec_private_key": re.compile(r"-----BEGIN EC PRIVATE KEY-----"),

            # OpenSSH Private Keys
            "openssh_private_key": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),

            # Generic Private Keys
            "generic_private_key": re.compile(r"-----BEGIN PRIVATE KEY-----"),

            # PostgreSQL Connection Strings
            "postgres_url": re.compile(
                r"postgres(?:ql)?://[a-zA-Z0-9_-]+:[a-zA-Z0-9_!@#$%^&*()+-]+@[a-zA-Z0-9.-]+:\d+/[a-zA-Z0-9_-]+"
            ),

            # MySQL Connection Strings
            "mysql_url": re.compile(
                r"mysql://[a-zA-Z0-9_-]+:[a-zA-Z0-9_!@#$%^&*()+-]+@[a-zA-Z0-9.-]+:\d+/[a-zA-Z0-9_-]+"
            ),

            # Generic API Keys
            "generic_api_key": re.compile(
                r"(?i)(api[_-]?key|apikey|secret[_-]?key)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{32,})['\"]"
            ),
        }

    async def detect(
        self, file_path: Path, content: str, file_type: str | None = None
    ) -> List[Vulnerability]:
        """
        Detect hardcoded secrets in file content.

        Args:
            file_path: Path to the file
            content: File content
            file_type: File type (optional)

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []

        # Split content into lines for line number tracking
        lines = content.split("\n")

        for secret_type, pattern in self.patterns.items():
            for line_num, line in enumerate(lines, start=1):
                matches = pattern.finditer(line)

                for match in matches:
                    # Extract the matched secret
                    secret_value = match.group(0)

                    # Skip if it looks like a placeholder
                    if self._is_placeholder(secret_value):
                        continue

                    # Create vulnerability
                    vuln = Vulnerability(
                        type=VulnerabilityType.SECRET_EXPOSURE,
                        title=f"Hardcoded {self._format_secret_type(secret_type)}",
                        description=self._generate_description(secret_type, secret_value),
                        severity=self._determine_severity(secret_type),
                        confidence=self._determine_confidence(secret_type, secret_value),
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=line.strip(),
                        cwe_id="CWE-798",  # Use of Hard-coded Credentials
                        cvss_score=9.1,
                        remediation=self._generate_remediation(secret_type),
                        references=[
                            "https://cwe.mitre.org/data/definitions/798.html",
                            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                        ],
                        detector=self.name,
                        engine="static",
                        mitre_attack_ids=["T1552.001"],  # Unsecured Credentials: Credentials In Files
                    )

                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _is_placeholder(self, secret: str) -> bool:
        """Check if the secret is likely a placeholder."""
        placeholders = [
            "your_api_key",
            "your_secret",
            "placeholder",
            "example",
            "fake",
            "test",
            "dummy",
            "xxx",
            "yyy",
            "zzz",
            "000",
            "111",
        ]
        secret_lower = secret.lower()
        return any(placeholder in secret_lower for placeholder in placeholders)

    def _format_secret_type(self, secret_type: str) -> str:
        """Format secret type for display."""
        return secret_type.replace("_", " ").title()

    def _generate_description(self, secret_type: str, secret_value: str) -> str:
        """Generate vulnerability description."""
        # Redact most of the secret for security
        redacted = secret_value[:8] + "..." + ("*" * 8)

        descriptions = {
            "aws_access_key": f"AWS Access Key found: {redacted}. This grants programmatic access to AWS resources.",
            "aws_secret_key": f"AWS Secret Key found: {redacted}. This can be used to authenticate AWS API requests.",
            "openai_api_key": f"OpenAI API Key found: {redacted}. This provides access to OpenAI's API services.",
            "anthropic_api_key": f"Anthropic Claude API Key found: {redacted}. This grants access to Claude AI models.",
            "github_token": f"GitHub Personal Access Token found: {redacted}. This can access GitHub repositories and data.",
            "slack_token": f"Slack API Token found: {redacted}. This provides access to Slack workspace data.",
            "jwt_token": f"JWT Token found: {redacted}. This may contain sensitive authentication information.",
            "rsa_private_key": "RSA Private Key found. This can be used to decrypt data or impersonate the key owner.",
            "postgres_url": "PostgreSQL connection string with embedded credentials found.",
            "mysql_url": "MySQL connection string with embedded credentials found.",
        }

        return descriptions.get(
            secret_type,
            f"{self._format_secret_type(secret_type)} found: {redacted}. Hardcoded secrets pose a security risk.",
        )

    def _determine_severity(self, secret_type: str) -> Severity:
        """Determine severity based on secret type."""
        critical_types = [
            "aws_access_key",
            "aws_secret_key",
            "rsa_private_key",
            "ec_private_key",
            "openssh_private_key",
            "generic_private_key",
        ]

        high_types = [
            "openai_api_key",
            "anthropic_api_key",
            "github_token",
            "postgres_url",
            "mysql_url",
        ]

        if secret_type in critical_types:
            return Severity.CRITICAL
        elif secret_type in high_types:
            return Severity.HIGH
        else:
            return Severity.MEDIUM

    def _determine_confidence(self, secret_type: str, secret_value: str) -> Confidence:
        """Determine confidence level."""
        # Private keys have very specific formats - high confidence
        if "private_key" in secret_type:
            return Confidence.HIGH

        # Well-known API key formats - high confidence
        high_confidence_types = [
            "aws_access_key",
            "openai_api_key",
            "anthropic_api_key",
            "github_token",
        ]

        if secret_type in high_confidence_types:
            return Confidence.HIGH

        # Generic patterns - medium confidence
        return Confidence.MEDIUM

    def _generate_remediation(self, secret_type: str) -> str:
        """Generate remediation advice."""
        if "api_key" in secret_type or "token" in secret_type:
            return (
                "1. Immediately revoke this API key/token\n"
                "2. Remove the hardcoded credential from the source code\n"
                "3. Use environment variables or a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager)\n"
                "4. Rotate all credentials that may have been exposed\n"
                "5. Review access logs for unauthorized usage"
            )

        elif "private_key" in secret_type:
            return (
                "1. Revoke and regenerate this private key immediately\n"
                "2. Remove the private key from source control\n"
                "3. Store private keys in a secure location with restricted access\n"
                "4. Use a secrets manager or encrypted storage\n"
                "5. Review git history and remove key from all commits"
            )

        elif "url" in secret_type:
            return (
                "1. Change the database password immediately\n"
                "2. Remove the connection string from source code\n"
                "3. Use environment variables for database credentials\n"
                "4. Review database access logs for unauthorized connections\n"
                "5. Consider using IAM authentication for cloud databases"
            )

        else:
            return (
                "1. Remove the hardcoded secret from source code\n"
                "2. Use environment variables or a secrets manager\n"
                "3. Rotate the exposed credential\n"
                "4. Implement secret scanning in CI/CD pipeline"
            )
