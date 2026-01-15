"""
Configuration Security vulnerability detector for MCP security.

Detects insecure configuration patterns that can lead to security vulnerabilities
in MCP servers and related applications.

Critical for ensuring MCP servers follow security best practices in deployment.
"""

import re
from pathlib import Path
from re import Pattern

from mcp_sentinel.detectors.base import BaseDetector
from mcp_sentinel.models.vulnerability import (
    Confidence,
    Severity,
    Vulnerability,
    VulnerabilityType,
)


class ConfigSecurityDetector(BaseDetector):
    """
    Detector for configuration security vulnerabilities.

    Detects 8 critical configuration security issues:
    1. Debug mode enabled in production
    2. Weak or missing authentication
    3. Insecure CORS configurations
    4. Missing security headers
    5. Weak session/secret configurations
    6. Missing rate limiting
    7. Insecure SSL/TLS settings
    8. Exposed debug/admin endpoints
    """

    def __init__(self):
        """Initialize the Config Security detector."""
        super().__init__(name="ConfigSecurityDetector", enabled=True)
        self.patterns: dict[str, list[Pattern]] = self._compile_patterns()

    def _compile_patterns(self) -> dict[str, list[Pattern]]:
        """Compile regex patterns for configuration security detection."""
        return {
            # Pattern 1: Debug mode enabled
            "debug_mode": [
                re.compile(r"DEBUG\s*=\s*True", re.IGNORECASE),
                re.compile(r"debug\s*:\s*true", re.IGNORECASE),
                re.compile(r"app\.debug\s*=\s*True", re.IGNORECASE),
                re.compile(r"environment\s*:\s*['\"]development['\"]", re.IGNORECASE),
                re.compile(r"NODE_ENV\s*=\s*['\"]development['\"]", re.IGNORECASE),
            ],
            # Pattern 2: Weak authentication
            "weak_auth": [
                re.compile(r"['\"]?auth['\"]?\s*[:=]\s*False", re.IGNORECASE),
                re.compile(r"['\"]?authentication['\"]?\s*[:=]\s*false", re.IGNORECASE),
                re.compile(r"['\"]?require_auth['\"]?\s*[:=]\s*False", re.IGNORECASE),
                re.compile(r"ALLOW_ANONYMOUS\s*[:=]\s*True", re.IGNORECASE),
                re.compile(
                    r"['\"]?password['\"]?\s*[:=]\s*['\"](?:admin|password|123|test)['\"]",
                    re.IGNORECASE,
                ),
            ],
            # Pattern 3: Insecure CORS
            "insecure_cors": [
                re.compile(
                    r"['\"]?Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]?\*['\"]?",
                    re.IGNORECASE,
                ),
                re.compile(r"cors\s*\(\s*\*\s*\)", re.IGNORECASE),
                re.compile(r"CORS_ORIGINS?\s*=\s*\[\s*['\"\*]", re.IGNORECASE),
                re.compile(r"allow_origins\s*=\s*\[\s*['\"\*]", re.IGNORECASE),
                re.compile(r"AllowedOrigins?\s*:\s*\[\s*['\"\*]", re.IGNORECASE),
            ],
            # Pattern 4: Missing/insecure security headers
            "security_headers": [
                re.compile(
                    r"['\"]?X-Frame-Options['\"]?\s*[:=]\s*['\"]?(?!DENY|SAMEORIGIN)[A-Z]+",
                    re.IGNORECASE,
                ),
                re.compile(r"Strict-Transport-Security.*max-age\s*=\s*0", re.IGNORECASE),
                re.compile(r"Content-Security-Policy\s*[:=]\s*['\"]?.*unsafe", re.IGNORECASE),
                re.compile(r"HSTS\s*[:=]\s*False", re.IGNORECASE),
            ],
            # Pattern 5: Weak secrets/session config
            "weak_secrets": [
                re.compile(
                    r"SECRET_KEY\s*=\s*['\"](?:secret|changeme|default|test|dev)['\"]",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"(?:session_?secret|secret)\s*[:=]\s*['\"](?:secret|key|password)['\"]",
                    re.IGNORECASE,
                ),
                re.compile(r"SESSION_COOKIE_SECURE\s*=\s*False", re.IGNORECASE),
                re.compile(r"SESSION_COOKIE_HTTPONLY\s*=\s*False", re.IGNORECASE),
                re.compile(r"(?:secure|httpOnly)\s*:\s*false", re.IGNORECASE),
            ],
            # Pattern 6: Missing rate limiting
            "rate_limiting": [
                re.compile(
                    r"['\"]?(?:rate_?limit|rateLimit)['\"]?\s*[:=]\s*(?:None|False|false|null|0)(?:\s|,|$)",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"['\"]?RATE_LIMIT['\"]?\s*[:=]\s*(?:None|False|false|null|0)(?:\s|,|$)"
                ),  # No IGNORECASE - only match uppercase
                re.compile(
                    r"['\"]?disable_rate_limit['\"]?\s*[:=]\s*(?:True|true)(?:\s|,|$)",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"['\"]?throttle['\"]?\s*[:=]\s*(?:False|false)(?:\s|,|$)", re.IGNORECASE
                ),
            ],
            # Pattern 7: Insecure SSL/TLS
            "insecure_ssl": [
                re.compile(r"['\"]?SSL_VERIFY['\"]?\s*[:=]\s*False", re.IGNORECASE),
                re.compile(r"['\"]?verify['\"]?\s*[:=]\s*False", re.IGNORECASE),
                re.compile(r"['\"]?ssl_version['\"]?\s*[:=]\s*SSLv[23]", re.IGNORECASE),
                re.compile(r"['\"]?TLS_VERSION['\"]?\s*[:=]\s*['\"]1\.[01]['\"]", re.IGNORECASE),
                re.compile(r"['\"]?check_hostname['\"]?\s*[:=]\s*False", re.IGNORECASE),
            ],
            # Pattern 8: Exposed debug/admin endpoints
            "exposed_endpoints": [
                re.compile(r"@app\.route\(['\"](?:/debug|/admin)['\"].*\)", re.IGNORECASE),
                re.compile(
                    r"path\s*:\s*['\"](?:/debug|/admin|/__debug__|/graphql)['\"]", re.IGNORECASE
                ),
                # Match router.get/post/etc but not @app.route (handled above)
                re.compile(
                    r"(?<!@)(?:router)\.\w+\(['\"](?:/debug|/admin|/__debug__|/graphql)['\"]",
                    re.IGNORECASE,
                ),
                re.compile(r"ALLOWED_HOSTS\s*=\s*\[\s*['\"\*]", re.IGNORECASE),
            ],
        }

    def is_applicable(self, file_path: Path, file_type: str | None = None) -> bool:
        """
        Check if this detector should run on the given file.

        Args:
            file_path: Path to the file
            file_type: File type (optional)

        Returns:
            True for configuration files
        """
        if file_type:
            return file_type in [
                "python",
                "javascript",
                "typescript",
                "yaml",
                "json",
                "toml",
                "ini",
                "env",
                "config",
            ]

        # Check file extensions and names
        config_extensions = [
            ".py",
            ".js",
            ".ts",
            ".yaml",
            ".yml",
            ".json",
            ".toml",
            ".ini",
            ".env",
            ".conf",
            ".config",
        ]

        config_names = [
            "settings.py",
            "config.py",
            "configuration.py",
            "app.py",
            "server.py",
            "main.py",
            ".env",
            ".env.local",
            ".env.production",
            "config.json",
            "app.json",
            "package.json",
            "docker-compose.yml",
            "docker-compose.yaml",
            "nginx.conf",
            "apache.conf",
        ]

        return (
            file_path.suffix.lower() in config_extensions or file_path.name.lower() in config_names
        )

    async def detect(
        self, file_path: Path, content: str, file_type: str | None = None
    ) -> list[Vulnerability]:
        """
        Detect configuration security vulnerabilities in file content.

        Args:
            file_path: Path to the file
            content: File content
            file_type: File type (optional)

        Returns:
            List of detected configuration security vulnerabilities
        """
        vulnerabilities: list[Vulnerability] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            # Skip comments
            if self._is_comment(line, file_type):
                continue

            # Check all pattern categories
            for category, patterns in self.patterns.items():
                for pattern in patterns:
                    matches = pattern.finditer(line)

                    for match in matches:
                        # Additional context checks to reduce false positives
                        if not self._is_likely_false_positive(
                            line, match.group(0), category, file_path
                        ):
                            vuln = self._create_vulnerability(
                                category=category,
                                matched_text=match.group(0),
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=line.strip(),
                            )
                            vulnerabilities.append(vuln)

        return vulnerabilities

    def _is_comment(self, line: str, file_type: str | None) -> bool:
        """
        Check if line is a comment.

        Args:
            line: Line of code to check
            file_type: Type of file (optional)

        Returns:
            True if the line is a comment, False otherwise
        """
        stripped = line.strip()

        # Empty lines
        if not stripped:
            return False

        # Python comments
        if stripped.startswith("#"):
            return True

        # JavaScript/TypeScript comments
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            return True

        return False

    def _is_likely_false_positive(
        self, line: str, matched_text: str, category: str, file_path: Path = None
    ) -> bool:
        """
        Check if the match is likely a false positive.

        Args:
            line: The full line of code
            matched_text: The matched pattern text
            category: The pattern category
            file_path: Path to the file (optional)

        Returns:
            True if likely false positive, False otherwise
        """
        # Check for test/example indicators
        test_indicators = [
            "test",
            "example",
            "sample",
            "demo",
            "mock",
            "fixture",
            "stub",
            "TODO",
            "FIXME",
        ]

        line_lower = line.lower()
        for indicator in test_indicators:
            if indicator in line_lower:
                return True

        # For debug mode, allow if explicitly marked as local/dev config
        if category == "debug_mode":
            # Check file path for local/dev indicators (but not unit test files)
            if file_path:
                filename_lower = str(file_path).lower()
                # Only match local/dev config files, not unit test files
                if any(
                    marker in filename_lower
                    for marker in [
                        "local",
                        "dev",
                        "development",
                        ".env.local",
                        "settings_local",
                        "settings_dev",
                        "config_local",
                        "config_dev",
                        "_local.",
                        "_dev.",
                        ".local.",
                        ".dev.",
                    ]
                ):
                    return True

            # Also check line content
            if any(
                marker in line_lower
                for marker in ["local", ".env.local", "development.py", "settings_dev"]
            ):
                return True

        # For secrets, allow if using environment variables
        if category == "weak_secrets":
            if "os.environ" in line or "process.env" in line or "${" in line:
                return True

        return False

    def _create_vulnerability(
        self,
        category: str,
        matched_text: str,
        file_path: Path,
        line_number: int,
        code_snippet: str,
    ) -> Vulnerability:
        """
        Create a vulnerability object from detected pattern.

        Args:
            category: The vulnerability category
            matched_text: The matched text
            file_path: Path to the file
            line_number: Line number where vulnerability was found
            code_snippet: The code snippet containing the vulnerability

        Returns:
            Vulnerability object
        """
        vuln_metadata = {
            "debug_mode": {
                "title": "Config: Debug Mode Enabled",
                "cwe_id": "CWE-489",
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cvss_score": 7.5,
                "description": (
                    f"Detected debug mode enabled: '{matched_text}'. "
                    "Running applications in debug mode in production exposes sensitive information "
                    "including stack traces, environment variables, and internal application structure. "
                    "Attackers can use this information to identify vulnerabilities and plan attacks. "
                    "This is critical for MCP servers which may handle sensitive user data."
                ),
                "remediation": (
                    "1. Disable debug mode in production environments\n"
                    "2. Use environment variables to control debug settings\n"
                    "3. Set DEBUG=False or debug: false in production configs\n"
                    "4. Use separate configuration files for dev and production\n"
                    "5. Implement proper logging without exposing internals\n"
                    "6. Configure error pages that don't leak information\n"
                    "7. Review deployment checklist before production releases"
                ),
                "mitre_attack_ids": ["T1082", "T1592"],
            },
            "weak_auth": {
                "title": "Config: Weak or Missing Authentication",
                "cwe_id": "CWE-306",
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "cvss_score": 9.8,
                "description": (
                    f"Detected weak authentication configuration: '{matched_text}'. "
                    "Missing or weak authentication allows unauthorized access to MCP server endpoints, "
                    "potentially exposing sensitive tools, data, and functionality. Default passwords "
                    "or disabled authentication are common attack vectors."
                ),
                "remediation": (
                    "1. Enable authentication for all endpoints\n"
                    "2. Use strong, randomly generated passwords/secrets\n"
                    "3. Never use default credentials (admin/password/etc)\n"
                    "4. Implement multi-factor authentication where possible\n"
                    "5. Use OAuth2, JWT, or other modern auth mechanisms\n"
                    "6. Require authentication for MCP server connections\n"
                    "7. Regularly rotate credentials and tokens"
                ),
                "mitre_attack_ids": ["T1078", "T1110"],
            },
            "insecure_cors": {
                "title": "Config: Insecure CORS Configuration",
                "cwe_id": "CWE-942",
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cvss_score": 7.4,
                "description": (
                    f"Detected insecure CORS configuration: '{matched_text}'. "
                    "Wildcard CORS origins (*) allow any website to make requests to your MCP server, "
                    "potentially enabling cross-site attacks, data theft, and unauthorized operations. "
                    "This is especially dangerous for authenticated endpoints."
                ),
                "remediation": (
                    "1. Never use wildcard (*) for CORS origins\n"
                    "2. Specify exact allowed origins (e.g., https://app.example.com)\n"
                    "3. Validate Origin header on server side\n"
                    "4. Use credentials: true only with specific origins\n"
                    "5. Implement proper preflight request handling\n"
                    "6. Consider using CSRF tokens for state-changing operations\n"
                    "7. Review CORS configuration in production deployments"
                ),
                "mitre_attack_ids": ["T1189", "T1557"],
            },
            "security_headers": {
                "title": "Config: Missing/Insecure Security Headers",
                "cwe_id": "CWE-693",
                "severity": Severity.MEDIUM,
                "confidence": Confidence.MEDIUM,
                "cvss_score": 5.3,
                "description": (
                    f"Detected missing or insecure security header: '{matched_text}'. "
                    "Security headers protect against common web attacks including clickjacking, "
                    "XSS, and protocol downgrade attacks. Missing headers leave MCP web UIs vulnerable."
                ),
                "remediation": (
                    "1. Set X-Frame-Options: DENY or SAMEORIGIN\n"
                    "2. Enable HSTS with max-age of at least 31536000 seconds\n"
                    "3. Implement strong Content-Security-Policy\n"
                    "4. Set X-Content-Type-Options: nosniff\n"
                    "5. Configure Referrer-Policy appropriately\n"
                    "6. Use Permissions-Policy to limit browser features\n"
                    "7. Test headers with security scanners"
                ),
                "mitre_attack_ids": ["T1189", "T1190"],
            },
            "weak_secrets": {
                "title": "Config: Weak Session/Secret Configuration",
                "cwe_id": "CWE-798",
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "cvss_score": 9.1,
                "description": (
                    f"Detected weak secret configuration: '{matched_text}'. "
                    "Weak or default secret keys allow attackers to forge sessions, decrypt data, "
                    "and bypass authentication. Insecure cookie settings enable session theft."
                ),
                "remediation": (
                    "1. Use strong, randomly generated secret keys (32+ bytes)\n"
                    "2. Store secrets in environment variables, not code\n"
                    "3. Set SESSION_COOKIE_SECURE=True (HTTPS only)\n"
                    "4. Set SESSION_COOKIE_HTTPONLY=True (prevent XSS)\n"
                    "5. Set SESSION_COOKIE_SAMESITE='Lax' or 'Strict'\n"
                    "6. Rotate secrets regularly\n"
                    "7. Use secret management tools (Vault, AWS Secrets Manager)"
                ),
                "mitre_attack_ids": ["T1078", "T1539"],
            },
            "rate_limiting": {
                "title": "Config: Missing Rate Limiting",
                "cwe_id": "CWE-770",
                "severity": Severity.MEDIUM,
                "confidence": Confidence.MEDIUM,
                "cvss_score": 6.5,
                "description": (
                    f"Detected missing rate limiting: '{matched_text}'. "
                    "Without rate limiting, MCP servers are vulnerable to brute force attacks, "
                    "denial of service, and resource exhaustion. Critical for public-facing endpoints."
                ),
                "remediation": (
                    "1. Implement rate limiting on all public endpoints\n"
                    "2. Use stricter limits for authentication endpoints\n"
                    "3. Implement both per-IP and per-user rate limits\n"
                    "4. Return 429 Too Many Requests with Retry-After header\n"
                    "5. Consider using tools like Redis for distributed rate limiting\n"
                    "6. Monitor and alert on rate limit violations\n"
                    "7. Implement exponential backoff for repeated violations"
                ),
                "mitre_attack_ids": ["T1110", "T1499"],
            },
            "insecure_ssl": {
                "title": "Config: Insecure SSL/TLS Configuration",
                "cwe_id": "CWE-327",
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cvss_score": 7.5,
                "description": (
                    f"Detected insecure SSL/TLS configuration: '{matched_text}'. "
                    "Disabling SSL verification or using outdated protocols enables "
                    "man-in-the-middle attacks, allowing attackers to intercept and modify "
                    "communications with MCP servers."
                ),
                "remediation": (
                    "1. Always enable SSL/TLS verification\n"
                    "2. Use TLS 1.2 or higher (TLS 1.3 recommended)\n"
                    "3. Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1\n"
                    "4. Use strong cipher suites only\n"
                    "5. Enable hostname verification\n"
                    "6. Use valid, trusted certificates\n"
                    "7. Implement certificate pinning for critical connections"
                ),
                "mitre_attack_ids": ["T1040", "T1557"],
            },
            "exposed_endpoints": {
                "title": "Config: Exposed Debug/Admin Endpoints",
                "cwe_id": "CWE-11 59",
                "severity": Severity.HIGH,
                "confidence": Confidence.MEDIUM,
                "cvss_score": 7.5,
                "description": (
                    f"Detected exposed debug or admin endpoint: '{matched_text}'. "
                    "Debug and admin endpoints often expose sensitive functionality and data. "
                    "If accessible in production, they provide attackers with powerful tools "
                    "for reconnaissance and exploitation."
                ),
                "remediation": (
                    "1. Remove debug endpoints from production code\n"
                    "2. Protect admin endpoints with authentication\n"
                    "3. Use IP whitelisting for admin access\n"
                    "4. Disable debug endpoints via configuration\n"
                    "5. Implement separate admin interface with proper auth\n"
                    "6. Use ALLOWED_HOSTS to restrict access\n"
                    "7. Monitor access to sensitive endpoints"
                ),
                "mitre_attack_ids": ["T1190", "T1592"],
            },
        }

        metadata = vuln_metadata.get(category, {})

        return Vulnerability(
            type=VulnerabilityType.CONFIG_SECURITY,
            title=metadata.get("title", "Configuration Security Issue"),
            description=metadata.get("description", f"Detected: {matched_text}"),
            severity=metadata.get("severity", Severity.MEDIUM),
            confidence=metadata.get("confidence", Confidence.MEDIUM),
            file_path=str(file_path),
            line_number=line_number,
            code_snippet=code_snippet,
            cwe_id=metadata.get("cwe_id", "CWE-16"),
            cvss_score=metadata.get("cvss_score", 5.0),
            remediation=metadata.get("remediation", "Review and fix configuration"),
            references=[
                "https://owasp.org/www-project-secure-configuration-guide/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/16.html",
                "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-123.pdf",
            ],
            detector=self.name,
            engine="static",
            mitre_attack_ids=metadata.get("mitre_attack_ids", []),
        )
