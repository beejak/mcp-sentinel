"""
Missing authentication detector for MCP security.

Detects route/endpoint definitions without authentication decorators or middleware.
MCP servers that expose management, admin, or system-operation endpoints without
authentication are immediately exploitable by any reachable client.

Uses a multi-line lookahead/lookback approach: for each route definition found,
scans the surrounding lines for auth patterns. Confidence is MEDIUM since auth
middleware may be applied at a higher level (class decorator, global middleware).
"""

import re
from pathlib import Path
from re import Pattern
from typing import Optional

from mcp_sentinel.detectors.base import BaseDetector
from mcp_sentinel.models.vulnerability import (
    Confidence,
    Severity,
    Vulnerability,
    VulnerabilityType,
)

# How many lines to look backwards/forwards for auth decorators
_LOOKBACK = 5
_LOOKAHEAD = 3

# Route path segments that indicate sensitive functionality
_SENSITIVE_PATHS = frozenset({
    "admin", "debug", "management", "internal", "sys", "config",
    "system", "superuser", "root", "operator", "console", "panel",
    "diagnostic", "health", "metrics", "status", "backstage",
})


class MissingAuthDetector(BaseDetector):
    """
    Detector for routes and endpoints missing authentication.

    Detects:
    1. Flask/FastAPI Python route decorators without auth decorators above them
    2. Express.js routes without auth middleware in the handler list
    3. Sensitive path segments (/admin, /debug, /internal) in route definitions
    4. MCP tool definitions that expose system operations without access checks
    """

    def __init__(self):
        """Initialize the missing auth detector."""
        super().__init__(name="MissingAuthDetector", enabled=True)
        self.route_patterns: dict[str, list[Pattern]] = self._compile_route_patterns()
        self.auth_patterns: list[Pattern] = self._compile_auth_patterns()

    def _compile_route_patterns(self) -> dict[str, list[Pattern]]:
        """Compile regex patterns that identify route/endpoint definitions."""
        return {
            # Python Flask/FastAPI decorators
            "python_route": [
                re.compile(r"@app\.(route|get|post|put|delete|patch|head)\s*\(", re.IGNORECASE),
                re.compile(r"@router\.(get|post|put|delete|patch|head)\s*\(", re.IGNORECASE),
                re.compile(r"@blueprint\.(route|get|post|put|delete|patch)\s*\(", re.IGNORECASE),
                re.compile(r"@api\.(route|get|post|put|delete|patch)\s*\(", re.IGNORECASE),
            ],
            # Express.js route definitions
            "express_route": [
                re.compile(
                    r"(?:app|router)\.(get|post|put|delete|patch|head)\s*\(\s*['\"`]",
                    re.IGNORECASE,
                ),
            ],
            # Sensitive path segments in any route definition
            "sensitive_path": [
                re.compile(
                    r"['\"`/](" + "|".join(_SENSITIVE_PATHS) + r")['\"`/]",
                    re.IGNORECASE,
                ),
            ],
            # MCP tool definitions that expose system operations
            "mcp_system_tool": [
                re.compile(
                    r'"name"\s*:\s*"[^"]*(?:exec|shell|run_command|system|execute|spawn|'
                    r'subprocess|cmd|terminal)[^"]*"',
                    re.IGNORECASE,
                ),
                re.compile(
                    r"name\s*=\s*['\"][^'\"]*(?:exec|shell|run_command|system|execute|spawn|cmd)[^'\"]*['\"]",
                    re.IGNORECASE,
                ),
            ],
        }

    def _compile_auth_patterns(self) -> list[Pattern]:
        """Compile patterns indicating auth IS present (used as negative check)."""
        return [
            # Python decorators
            re.compile(r"@(?:require_login|login_required|authenticate|auth_required|requires_auth)", re.IGNORECASE),
            re.compile(r"@jwt_required", re.IGNORECASE),
            re.compile(r"@permission_required", re.IGNORECASE),
            re.compile(r"@token_required", re.IGNORECASE),
            re.compile(r"@authenticated", re.IGNORECASE),
            # FastAPI Depends
            re.compile(r"Depends\s*\(\s*(?:get_current_user|verify_token|authenticate|require_auth|get_user|current_user)", re.IGNORECASE),
            re.compile(r"Security\s*\(\s*", re.IGNORECASE),
            # JavaScript/TypeScript middleware
            re.compile(r"\b(?:verifyToken|authenticate|checkAuth|isAuthenticated|requireAuth)\b"),
            re.compile(r"\b(?:authMiddleware|auth_middleware|require_auth|ensureAuth)\b"),
            re.compile(r"\bpassport\.authenticate\b"),
            re.compile(r"\bjwt\.verify\b"),
            # Generic auth indicators
            re.compile(r"authorization\s*:", re.IGNORECASE),
            re.compile(r"bearer\s+token", re.IGNORECASE),
        ]

    def is_applicable(self, file_path: Path, file_type: Optional[str] = None) -> bool:
        """Apply to Python, JavaScript, TypeScript, and JSON (MCP tool schemas)."""
        if file_type:
            return file_type in ["python", "javascript", "typescript", "json"]

        return file_path.suffix.lower() in {".py", ".js", ".jsx", ".ts", ".tsx", ".json"}

    def detect_sync(
        self, file_path: Path, content: str, file_type: Optional[str] = None
    ) -> list[Vulnerability]:
        """Detect missing authentication on routes and endpoints."""
        vulnerabilities: list[Vulnerability] = []
        lines = content.split("\n")
        seen: set[int] = set()  # deduplicate by line number

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Skip comments
            if stripped.startswith(("#", "//", "*", "/*")):
                continue

            for category, patterns in self.route_patterns.items():
                for pattern in patterns:
                    if not pattern.search(line):
                        continue

                    # Check surrounding lines for auth patterns
                    if self._has_auth_nearby(lines, line_num - 1):
                        continue

                    # Deduplicate
                    if line_num in seen:
                        continue
                    seen.add(line_num)

                    # Determine if sensitive path
                    is_sensitive = self._has_sensitive_path(line)

                    vuln = self._create_vulnerability(
                        category=category,
                        is_sensitive=is_sensitive,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line.strip(),
                    )
                    vulnerabilities.append(vuln)
                    break  # one finding per line

        return vulnerabilities

    def _has_auth_nearby(self, lines: list[str], line_idx: int) -> bool:
        """Check if auth patterns appear in surrounding lines."""
        start = max(0, line_idx - _LOOKBACK)
        end = min(len(lines), line_idx + _LOOKAHEAD + 1)
        window = lines[start:end]
        return any(
            auth_pattern.search(line)
            for line in window
            for auth_pattern in self.auth_patterns
        )

    def _has_sensitive_path(self, line: str) -> bool:
        """Check if the line contains a sensitive path segment."""
        line_lower = line.lower()
        return any(f"/{seg}" in line_lower or f'"{seg}' in line_lower for seg in _SENSITIVE_PATHS)

    def _create_vulnerability(
        self,
        category: str,
        is_sensitive: bool,
        file_path: Path,
        line_number: int,
        code_snippet: str,
    ) -> Vulnerability:
        """Create a missing auth vulnerability object."""

        if category == "mcp_system_tool":
            return Vulnerability(
                type=VulnerabilityType.MISSING_AUTH,
                title="Missing Auth: MCP Tool Exposes System Operation Without Access Check",
                description=(
                    f"An MCP tool exposes a system-level operation (exec, shell, command execution) "
                    f"without an apparent access check: '{code_snippet[:120]}'. "
                    "MCP tools that run shell commands or system operations should verify the caller "
                    "is authorized. Without this, any agent connected to the server can invoke the tool. "
                    "In multi-tenant or shared deployments this is immediately exploitable."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                file_path=str(file_path),
                line_number=line_number,
                code_snippet=code_snippet,
                cwe_id="CWE-306",
                cvss_score=8.6,
                remediation=(
                    "1. Add an authorization check at the start of the tool handler\n"
                    "2. Validate the caller's identity before executing system operations\n"
                    "3. Use allowlists for permitted commands rather than arbitrary execution\n"
                    "4. Consider whether this tool should exist at all — shell execution tools\n"
                    "   have a very large blast radius in an agentic context"
                ),
                references=[
                    "https://cwe.mitre.org/data/definitions/306.html",
                    "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                ],
                detector=self.name,
                engine="static",
                mitre_attack_ids=["T1059", "T1078"],
            )

        if category == "sensitive_path" or is_sensitive:
            return Vulnerability(
                type=VulnerabilityType.MISSING_AUTH,
                title="Missing Auth: Sensitive Endpoint Without Authentication",
                description=(
                    f"A sensitive route (admin/debug/management/internal) appears to lack "
                    f"authentication: '{code_snippet[:120]}'. "
                    "Sensitive endpoints expose privileged functionality. Without authentication, "
                    "any reachable client — including agents operating via SSRF — can access them. "
                    "Auth may be enforced globally (middleware), but that is not detectable statically."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                file_path=str(file_path),
                line_number=line_number,
                code_snippet=code_snippet,
                cwe_id="CWE-306",
                cvss_score=8.2,
                remediation=(
                    "1. Add @login_required / @auth_required decorator to the route function\n"
                    "2. FastAPI: add Depends(get_current_user) to the function signature\n"
                    "3. Express: add auth middleware before the handler: router.get('/admin', authMiddleware, handler)\n"
                    "4. Consider IP allowlisting for admin endpoints in addition to auth\n"
                    "5. If global middleware handles auth, add a comment to suppress this finding"
                ),
                references=[
                    "https://cwe.mitre.org/data/definitions/306.html",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                ],
                detector=self.name,
                engine="static",
                mitre_attack_ids=["T1078", "T1190"],
            )

        # Generic route without auth
        return Vulnerability(
            type=VulnerabilityType.MISSING_AUTH,
            title="Missing Auth: Route Definition Without Apparent Authentication",
            description=(
                f"A route or endpoint is defined without apparent authentication: '{code_snippet[:120]}'. "
                "No auth decorator or middleware was found in the surrounding lines. "
                "If this endpoint handles sensitive operations or data, unauthenticated access "
                "could be a security risk. Note: global middleware may handle auth — review in context."
            ),
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            file_path=str(file_path),
            line_number=line_number,
            code_snippet=code_snippet,
            cwe_id="CWE-306",
            cvss_score=6.5,
            remediation=(
                "1. Add authentication to the route:\n"
                "   Flask:   @login_required\n"
                "   FastAPI: async def handler(user=Depends(get_current_user))\n"
                "   Express: router.get('/path', authMiddleware, handler)\n"
                "2. If global auth middleware covers all routes, this finding can be suppressed\n"
                "3. Verify that unauthenticated access is intentional for public routes"
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/306.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            ],
            detector=self.name,
            engine="static",
            mitre_attack_ids=["T1078"],
        )
