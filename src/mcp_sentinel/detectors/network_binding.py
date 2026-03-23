"""
Network binding security detector for MCP security.

Detects servers bound to 0.0.0.0 (all interfaces) instead of 127.0.0.1.
Over 8,000 MCP servers are publicly exposed due to this misconfiguration.

Binding to 0.0.0.0 makes the service reachable on every network interface,
including public-facing ones. MCP servers are typically meant for local use
(STDIO transport or localhost HTTP) and should not be publicly reachable.
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


class NetworkBindingDetector(BaseDetector):
    """
    Detector for insecure network binding configurations.

    Detects servers bound to 0.0.0.0 across:
    1. Python (Flask, FastAPI, uvicorn, raw socket)
    2. JavaScript/TypeScript (Express, Node.js http)
    3. Go (net.Listen, ListenAndServe)
    4. Java (ServerSocket, InetSocketAddress)
    5. Config files (.env, YAML, TOML, ini)
    """

    def __init__(self):
        """Initialize the network binding detector."""
        super().__init__(name="NetworkBindingDetector", enabled=True)
        self.patterns: dict[str, list[Pattern]] = self._compile_patterns()

    def _compile_patterns(self) -> dict[str, list[Pattern]]:
        """Compile regex patterns for network binding detection."""
        return {
            # Python: host="0.0.0.0" in server calls
            "python_wildcard": [
                re.compile(r"host\s*=\s*['\"]0\.0\.0\.0['\"]", re.IGNORECASE),
                re.compile(
                    r"app\.run\s*\([^)]*host\s*=\s*['\"]0\.0\.0\.0['\"]",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"uvicorn\.run\s*\([^)]*host\s*=\s*['\"]0\.0\.0\.0['\"]",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"gunicorn.*--bind\s+0\.0\.0\.0",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"socket\.bind\s*\(\s*\(\s*['\"]0\.0\.0\.0['\"]",
                    re.IGNORECASE,
                ),
            ],
            # JavaScript/TypeScript: server binds to 0.0.0.0
            "js_wildcard": [
                re.compile(
                    r"\.listen\s*\(\s*\d+\s*,\s*['\"]0\.0\.0\.0['\"]",
                    re.IGNORECASE,
                ),
                re.compile(r"hostname\s*[:=]\s*['\"]0\.0\.0\.0['\"]", re.IGNORECASE),
                re.compile(r"host\s*[:=]\s*['\"]0\.0\.0\.0['\"]", re.IGNORECASE),
                re.compile(
                    r"createServer.*\.listen.*['\"]0\.0\.0\.0['\"]",
                    re.IGNORECASE,
                ),
            ],
            # Go: net.Listen or ListenAndServe binding to all interfaces
            "go_wildcard": [
                re.compile(
                    r'net\.Listen\s*\(\s*["`]tcp["`]\s*,\s*["`]0\.0\.0\.0:\d+["`]',
                ),
                re.compile(
                    # Shorthand ":8080" binds to all interfaces in Go
                    r'net\.Listen\s*\(\s*["`]tcp["`]\s*,\s*["`]:\d+["`]',
                ),
                re.compile(
                    r'ListenAndServe\s*\(\s*["`]0\.0\.0\.0:\d+["`]',
                ),
                re.compile(
                    # ListenAndServe(":8080", ...) binds to 0.0.0.0 in Go
                    r'ListenAndServe\s*\(\s*["`]:\d+["`]',
                ),
                re.compile(
                    r'ListenAndServeTLS\s*\(\s*["`]:\d+["`]',
                ),
            ],
            # Java: ServerSocket or InetSocketAddress without explicit host
            "java_wildcard": [
                re.compile(
                    r"new\s+ServerSocket\s*\(\s*\d+\s*\)",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"InetAddress\.getByName\s*\(\s*['\"]0\.0\.0\.0['\"]",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"new\s+InetSocketAddress\s*\(\s*\d+\s*\)",
                    re.IGNORECASE,
                ),
            ],
            # Config files
            "config_wildcard": [
                re.compile(r"^BIND_HOST\s*[=:]\s*0\.0\.0\.0", re.IGNORECASE | re.MULTILINE),
                re.compile(r"^HOST\s*=\s*0\.0\.0\.0", re.MULTILINE),
                re.compile(r"^LISTEN\s*[=:]\s*0\.0\.0\.0", re.IGNORECASE | re.MULTILINE),
                re.compile(r"bind[-_]?address\s*[=:]\s*['\"]?0\.0\.0\.0['\"]?", re.IGNORECASE),
                re.compile(r"listen[-_]?address\s*[=:]\s*['\"]?0\.0\.0\.0['\"]?", re.IGNORECASE),
            ],
        }

    def is_applicable(self, file_path: Path, file_type: Optional[str] = None) -> bool:
        """Apply to code files and configuration files."""
        if file_type:
            return file_type in [
                "python", "javascript", "typescript", "go", "java",
                "yaml", "toml", "env", "ini", "config",
            ]

        return file_path.suffix.lower() in {
            ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java",
            ".yaml", ".yml", ".env", ".toml", ".ini", ".cfg", ".conf",
        } or file_path.name.lower() in {
            ".env", ".env.local", ".env.production", ".env.development",
        }

    def detect_sync(
        self, file_path: Path, content: str, file_type: Optional[str] = None
    ) -> list[Vulnerability]:
        """Detect insecure network binding in file content."""
        vulnerabilities: list[Vulnerability] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Skip comment lines
            if stripped.startswith(("#", "//", "*", "/*")):
                continue

            for category, patterns in self.patterns.items():
                for pattern in patterns:
                    if pattern.search(line):
                        if not self._is_likely_false_positive(line):
                            vuln = self._create_vulnerability(
                                category=category,
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=line.strip(),
                            )
                            vulnerabilities.append(vuln)
                            break  # one finding per category per line

        return vulnerabilities

    def _is_likely_false_positive(self, line: str) -> bool:
        """Suppress common false positives."""
        line_lower = line.lower()
        return any(kw in line_lower for kw in ["test", "example", "mock", "fixture", "sample"])

    def _create_vulnerability(
        self,
        category: str,
        file_path: Path,
        line_number: int,
        code_snippet: str,
    ) -> Vulnerability:
        """Create a network binding vulnerability object."""

        # Go shorthand note: ":8080" is equivalent to "0.0.0.0:8080" in Go
        is_go_shorthand = category == "go_wildcard" and "0.0.0.0" not in code_snippet

        extra_note = (
            " Note: In Go, listening on ':<port>' (e.g. ':8080') is equivalent to binding "
            "to 0.0.0.0 — all interfaces."
            if is_go_shorthand
            else ""
        )

        return Vulnerability(
            type=VulnerabilityType.NETWORK_BINDING,
            title="Network Binding: Server Exposed on All Interfaces (0.0.0.0)",
            description=(
                f"Server is bound to 0.0.0.0 (all network interfaces): '{code_snippet}'.{extra_note} "
                "This makes the service reachable on every network interface including public-facing ones. "
                "MCP servers are typically designed for local use via STDIO transport or localhost HTTP. "
                "Binding to 0.0.0.0 is the primary reason 8,000+ MCP servers are publicly accessible. "
                "An exposed MCP server gives any reachable client access to all registered tools, "
                "potentially including file system access, code execution, and external API calls."
            ),
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            file_path=str(file_path),
            line_number=line_number,
            code_snippet=code_snippet,
            cwe_id="CWE-284",
            cvss_score=6.5,
            remediation=(
                "1. Bind to 127.0.0.1 for localhost-only access:\n"
                "   Python:  host='127.0.0.1'\n"
                "   Go:      net.Listen(\"tcp\", \"127.0.0.1:8080\")\n"
                "   Node.js: server.listen(8080, '127.0.0.1')\n"
                "2. If external access is required, bind to a specific interface IP\n"
                "3. Use a reverse proxy (nginx, caddy) to front the service with TLS and auth\n"
                "4. In containers: if 0.0.0.0 is intentional, ensure the container network\n"
                "   is not exposed to the public internet and authentication is enforced\n"
                "5. Add authentication middleware before exposing any MCP HTTP endpoints"
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/284.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Network_Segmentation_Cheat_Sheet.html",
                "https://cikce.medium.com/8-000-mcp-servers-exposed-the-agentic-ai-security-crisis-of-2026-e8cb45f09115",
            ],
            detector=self.name,
            engine="static",
            mitre_attack_ids=["T1049", "T1046"],
        )
