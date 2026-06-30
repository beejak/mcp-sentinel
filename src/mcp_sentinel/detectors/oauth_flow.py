"""OAuth authorization flow vulnerability detector."""

import re
from pathlib import Path
from typing import Optional

from mcp_sentinel.detectors.base import BaseDetector
from mcp_sentinel.models.vulnerability import (
    Confidence,
    Severity,
    Vulnerability,
    VulnerabilityType,
)

_OWASP_ID = "ASI04"
_OWASP_NAME = "Insecure Direct Tool Invocation"

_APPLICABLE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java"}

_OAUTH_KEYWORDS = (
    "oauth",
    "access_token",
    "refresh_token",
    "client_secret",
    "redirect_uri",
    "authorization_code",
    "bearer",
    "id_token",
    "response_type",
    "grant_type",
    "jwt",
    "verify_exp",
    "verify_signature",
)


class OAuthFlowDetector(BaseDetector):
    """
    Detects OAuth/authorization-flow vulnerabilities in MCP server code.

    Covers the CVE-2025-6514 class of MCP OAuth attacks: open redirect via
    unvalidated redirect_uri, token credential exposure, deprecated implicit
    grant, missing PKCE, and disabled JWT verification.
    """

    def __init__(self) -> None:
        super().__init__(name="OAuthFlowDetector", enabled=True)
        self.patterns = self._compile_patterns()

    def _compile_patterns(self) -> dict[str, list]:
        return {
            "open_redirect": [
                re.compile(r"redirect_uri\s*=\s*request\.(args|params|GET|query)", re.IGNORECASE),
                re.compile(r"redirect_uri\s*=\s*\w+\.(get|args|params)\[", re.IGNORECASE),
                re.compile(r"callback\w*\s*=\s*request\.(args|params|GET|query)", re.IGNORECASE),
            ],
            "token_in_logs": [
                re.compile(
                    r"(logger|logging)\.(info|debug|warning|error|warn)\s*\(.*"
                    r"(?:access_token|refresh_token|id_token|bearer|oauth_token)",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"print\s*\(.*(?:access_token|refresh_token|bearer_token|oauth_token)",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"console\.(log|info|debug|warn)\s*\(.*(?:access_token|refresh_token|bearer)",
                    re.IGNORECASE,
                ),
            ],
            "token_in_browser_storage": [
                re.compile(r"localStorage\.setItem\s*\([^)]*(?:token|access_token|auth)", re.IGNORECASE),
                re.compile(r"sessionStorage\.setItem\s*\([^)]*(?:token|access_token|auth)", re.IGNORECASE),
            ],
            "hardcoded_client_secret": [
                re.compile(r'client_secret\s*=\s*["\'][A-Za-z0-9_\-]{8,}["\']'),
                re.compile(r'CLIENT_SECRET\s*=\s*["\'][A-Za-z0-9_\-]{8,}["\']'),
                re.compile(r'"client_secret"\s*:\s*"[A-Za-z0-9_\-]{8,}"'),
            ],
            "implicit_grant": [
                re.compile(r'response_type\s*=\s*["\']token["\']', re.IGNORECASE),
                re.compile(r'"response_type"\s*:\s*"token"', re.IGNORECASE),
                re.compile(r'response_type=token\b', re.IGNORECASE),  # URL query-param form
                re.compile(r'grant_type\s*=\s*["\']implicit["\']', re.IGNORECASE),
            ],
            "missing_pkce": [
                re.compile(r'response_type\s*=\s*["\']code["\'](?!.*code_challenge)', re.IGNORECASE),
                re.compile(r'grant_type\s*=\s*["\']authorization_code["\'](?!.*code_verifier)', re.IGNORECASE),
                re.compile(r'"grant_type"\s*:\s*"authorization_code"(?!.*"code_verifier")', re.IGNORECASE),
            ],
            "missing_token_validation": [
                re.compile(r'"verify_exp"\s*:\s*[Ff]alse'),
                re.compile(r'algorithms\s*=\s*\[\s*["\']none["\']', re.IGNORECASE),
                re.compile(r'decode\([^)]*verify\s*=\s*False', re.IGNORECASE),
            ],
        }

    def is_applicable(self, file_path: Path, file_type: Optional[str] = None) -> bool:
        if file_type:
            return file_type in ("python", "javascript", "typescript", "go", "java")
        return file_path.suffix.lower() in _APPLICABLE_EXTENSIONS

    def detect_sync(
        self, file_path: Path, content: str, file_type: Optional[str] = None
    ) -> list[Vulnerability]:
        if self._is_test_file(file_path):
            return []

        content_lower = content.lower()
        if not any(kw in content_lower for kw in _OAUTH_KEYWORDS):
            return []

        vulns: list[Vulnerability] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//")):
                continue

            for category, patterns in self.patterns.items():
                for pattern in patterns:
                    if pattern.search(line):
                        vuln = self._make_vuln(category, file_path, line_num, stripped)
                        if vuln:
                            vulns.append(vuln)
                        break

        return self._deduplicate(vulns)

    def _make_vuln(
        self, category: str, file_path: Path, line_num: int, snippet: str
    ) -> Optional[Vulnerability]:
        _SPECS: dict[str, dict] = {
            "open_redirect": {
                "title": "OAuth: Open Redirect via Unvalidated redirect_uri",
                "description": (
                    "The OAuth redirect_uri is taken directly from the request without validation. "
                    "An attacker can supply a malicious callback URL to intercept the authorization "
                    "code and hijack the OAuth flow (CVE-2025-6514 class)."
                ),
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-601",
                "cvss_score": 8.1,
                "remediation": (
                    "1. Maintain a server-side allowlist of pre-registered redirect URIs.\n"
                    "2. Reject any redirect_uri that does not exactly match the allowlist.\n"
                    "3. Never derive redirect_uri from query parameters at runtime."
                ),
                "mitre": ["T1528", "T1550.001"],
                "refs": [
                    "https://datatracker.ietf.org/doc/html/rfc6749#section-10.6",
                    "https://nvd.nist.gov/vuln/detail/CVE-2025-6514",
                    "https://owasp.org/www-project-web-security-testing-guide/",
                ],
            },
            "token_in_logs": {
                "title": "OAuth: Access/Refresh Token Written to Logs",
                "description": (
                    "An OAuth token is passed to a logging call. Log files are often retained "
                    "long-term, forwarded to SIEM/observability platforms, and accessible to "
                    "multiple services, creating a persistent credential exposure risk."
                ),
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-532",
                "cvss_score": 7.5,
                "remediation": (
                    "1. Never log tokens, secrets, or credentials.\n"
                    "2. Mask sensitive fields before logging (e.g., show only last 4 chars).\n"
                    "3. Use structured logging with field-level redaction."
                ),
                "mitre": ["T1552", "T1528"],
                "refs": [
                    "https://cwe.mitre.org/data/definitions/532.html",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
                ],
            },
            "token_in_browser_storage": {
                "title": "OAuth: Token Stored in localStorage/sessionStorage",
                "description": (
                    "An OAuth token is stored in browser Web Storage (localStorage/sessionStorage). "
                    "These are accessible to any JavaScript on the page, making the token trivially "
                    "stealable via XSS attacks."
                ),
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-922",
                "cvss_score": 7.4,
                "remediation": (
                    "1. Store tokens in httpOnly, Secure cookies instead of Web Storage.\n"
                    "2. Use the Backend-for-Frontend (BFF) pattern for token management.\n"
                    "3. Implement Content-Security-Policy to limit XSS attack surface."
                ),
                "mitre": ["T1539", "T1528"],
                "refs": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html",
                    "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps",
                ],
            },
            "hardcoded_client_secret": {
                "title": "OAuth: Hardcoded client_secret in Source Code",
                "description": (
                    "An OAuth client_secret is hardcoded. Anyone with repository access can "
                    "impersonate this OAuth client, perform token exchanges, and access protected "
                    "resources on behalf of users."
                ),
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-798",
                "cvss_score": 9.1,
                "remediation": (
                    "1. Move client_secret to environment variables or a secrets manager immediately.\n"
                    "2. Rotate the exposed secret.\n"
                    "3. For public clients use PKCE instead of a client secret."
                ),
                "mitre": ["T1552.001", "T1528"],
                "refs": [
                    "https://cwe.mitre.org/data/definitions/798.html",
                    "https://datatracker.ietf.org/doc/html/rfc6749#section-2.3",
                ],
            },
            "implicit_grant": {
                "title": "OAuth: Deprecated Implicit Grant Flow (response_type=token)",
                "description": (
                    "The OAuth implicit grant flow is used. This flow was deprecated in OAuth 2.1 "
                    "because tokens are returned in URL fragments (exposed in browser history, "
                    "Referer headers, and server logs) without any PKCE protection."
                ),
                "severity": Severity.MEDIUM,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-287",
                "cvss_score": 6.5,
                "remediation": (
                    "1. Migrate to the Authorization Code flow with PKCE.\n"
                    "2. Never use response_type=token for new implementations.\n"
                    "3. Reference OAuth 2.1 draft for current best practices."
                ),
                "mitre": ["T1528"],
                "refs": [
                    "https://oauth.net/2/grant-types/implicit/",
                    "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics",
                ],
            },
            "missing_pkce": {
                "title": "OAuth: Authorization Code Flow — Verify PKCE is Present",
                "description": (
                    "An authorization code flow is detected. Without PKCE (Proof Key for Code "
                    "Exchange), authorization codes can be intercepted and exchanged by a malicious "
                    "app on the same device. Verify code_challenge and code_verifier are included."
                ),
                "severity": Severity.MEDIUM,
                "confidence": Confidence.LOW,
                "cwe_id": "CWE-287",
                "cvss_score": 5.9,
                "remediation": (
                    "1. Generate a cryptographically random code_verifier (43-128 chars).\n"
                    "2. Hash it with SHA-256 to create code_challenge.\n"
                    "3. Include code_challenge_method=S256 in the authorization request.\n"
                    "4. Send code_verifier in the token exchange request."
                ),
                "mitre": ["T1528"],
                "refs": [
                    "https://datatracker.ietf.org/doc/html/rfc7636",
                    "https://oauth.net/2/pkce/",
                ],
            },
            "missing_token_validation": {
                "title": "OAuth: JWT Token Signature or Expiry Verification Disabled",
                "description": (
                    "Token signature verification or expiry validation is explicitly disabled "
                    "(verify=False, verify_exp=False, algorithm='none'). An attacker can craft "
                    "or replay expired tokens to gain unauthorized access."
                ),
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-347",
                "cvss_score": 9.1,
                "remediation": (
                    "1. Never set verify=False or verify_exp=False in production.\n"
                    "2. Always verify signature against the identity provider's public key.\n"
                    "3. Validate exp, iss, and aud claims on every token decode."
                ),
                "mitre": ["T1550.001", "T1528"],
                "refs": [
                    "https://cwe.mitre.org/data/definitions/347.html",
                    "https://jwt.io/introduction",
                ],
            },
        }

        spec = _SPECS.get(category)
        if not spec:
            return None

        return Vulnerability(
            type=VulnerabilityType.OAUTH_FLOW,
            title=spec["title"],
            description=spec["description"],
            severity=spec["severity"],
            confidence=spec["confidence"],
            file_path=str(file_path),
            line_number=line_num,
            code_snippet=snippet[:200],
            cwe_id=spec["cwe_id"],
            cvss_score=spec["cvss_score"],
            remediation=spec["remediation"],
            references=spec["refs"],
            detector=self.name,
            engine="static",
            mitre_attack_ids=spec["mitre"],
            owasp_asi_id=_OWASP_ID,
            owasp_asi_name=_OWASP_NAME,
        )

    @staticmethod
    def _deduplicate(vulns: list[Vulnerability]) -> list[Vulnerability]:
        seen: set[tuple] = set()
        result = []
        for v in vulns:
            key = (v.file_path, v.line_number, v.title)
            if key not in seen:
                seen.add(key)
                result.append(v)
        return result
