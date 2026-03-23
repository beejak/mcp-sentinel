"""
SSRF (Server-Side Request Forgery) detector for MCP security.

Detects patterns where tool implementations accept URL inputs and make
outbound HTTP requests without allowlist validation. SSRF is the third
most common vulnerability in real-world MCP server scans (30% exposure).

Critical for MCP servers deployed in cloud environments where SSRF enables
access to AWS IMDSv1, GCP metadata, and Azure IMDS endpoints.
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


class SSRFDetector(BaseDetector):
    """
    Detector for Server-Side Request Forgery (SSRF) vulnerabilities.

    Detects:
    1. Unvalidated URL variables passed to Python HTTP clients (requests, httpx, aiohttp, urllib)
    2. Unvalidated URL variables passed to JavaScript fetch/axios
    3. Hardcoded cloud metadata endpoint references (169.254.169.254, metadata.google.internal)
    4. Redirect/callback/webhook URL parameters without validation
    5. Go http.Get/Post with variable arguments
    6. Java URL.openConnection() with variable arguments
    """

    def __init__(self):
        """Initialize the SSRF detector."""
        super().__init__(name="SSRFDetector", enabled=True)
        self.patterns: dict[str, list[Pattern]] = self._compile_patterns()

    def _compile_patterns(self) -> dict[str, list[Pattern]]:
        """Compile regex patterns for SSRF detection."""
        return {
            # Python HTTP clients with variable (non-literal) URL argument
            "python_http_variable": [
                re.compile(
                    r"requests\.(get|post|put|delete|patch|request|head)\s*\(\s*(?!['\"])[a-zA-Z_]\w*",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"urllib\.request\.urlopen\s*\(\s*(?!['\"])[a-zA-Z_]\w*",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"urllib\.urlopen\s*\(\s*(?!['\"])[a-zA-Z_]\w*",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"httpx\.(get|post|put|delete|patch|request|head)\s*\(\s*(?!['\"])[a-zA-Z_]\w*",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"httpx\.AsyncClient\s*\(\s*\).*\.(get|post|put|delete)\s*\(\s*(?!['\"])[a-zA-Z_]\w*",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"aiohttp\.\w+\.(get|post|put|delete|request)\s*\(\s*(?!['\"])[a-zA-Z_]\w*",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"session\.(get|post|put|delete|request)\s*\(\s*(?!['\"])[a-zA-Z_]\w*",
                    re.IGNORECASE,
                ),
            ],
            # JavaScript/TypeScript fetch and axios with variable URL
            "js_fetch_variable": [
                re.compile(
                    r"\bfetch\s*\(\s*(?!['\"`])[a-zA-Z_$]\w*",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"axios\.(get|post|put|delete|patch|request|head)\s*\(\s*(?!['\"`])[a-zA-Z_$]\w*",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"http\.(get|request)\s*\(\s*(?!['\"`])[a-zA-Z_$]\w*",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"node-?fetch\s*\(\s*(?!['\"`])[a-zA-Z_$]\w*",
                    re.IGNORECASE,
                ),
            ],
            # Hardcoded cloud metadata endpoints
            "cloud_metadata": [
                re.compile(r"169\.254\.169\.254"),  # AWS/general IMDS
                re.compile(r"metadata\.google\.internal", re.IGNORECASE),
                re.compile(r"169\.254\.170\.2"),  # AWS ECS metadata
                re.compile(r"fd00:ec2::254"),  # AWS IMDSv6
                re.compile(r"metadata\.azure\.internal", re.IGNORECASE),
                re.compile(r"169\.254\.169\.123"),  # AWS Time Sync Service
            ],
            # Redirect/callback/webhook URL parameters
            "redirect_params": [
                re.compile(
                    r"['\"]?(redirect_uri|redirect_url|callback_url|webhook_url|return_url|"
                    r"next_url|next|returnTo|return_to|forward_url|goto)['\"]?\s*[=:]",
                    re.IGNORECASE,
                ),
            ],
            # Go HTTP client with variable URL
            "go_http_variable": [
                re.compile(
                    r"http\.(Get|Post|Head|Do)\s*\(\s*(?![`\"])[a-zA-Z_]\w*",
                ),
                re.compile(
                    r"client\.(Get|Post|Do|Head)\s*\(\s*(?![`\"])[a-zA-Z_]\w*",
                ),
                re.compile(
                    r"http\.NewRequest\s*\([^,]+,\s*(?![`\"])[a-zA-Z_]\w*",
                ),
            ],
            # Java URL/HttpClient with variable
            "java_url_variable": [
                re.compile(
                    r"new\s+URL\s*\(\s*(?![\"'])[a-zA-Z_]\w*\s*\)\s*\.open",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"URI\.create\s*\(\s*(?![\"'])[a-zA-Z_]\w*",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"HttpRequest\.newBuilder\s*\(\s*\)\s*\.uri\s*\(\s*URI\.create\s*\(\s*(?![\"'])",
                    re.IGNORECASE,
                ),
            ],
        }

    def is_applicable(self, file_path: Path, file_type: Optional[str] = None) -> bool:
        """Apply to code files where HTTP client calls are made."""
        if file_type:
            return file_type in ["python", "javascript", "typescript", "go", "java"]

        return file_path.suffix.lower() in {
            ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java",
        }

    def detect_sync(
        self, file_path: Path, content: str, file_type: Optional[str] = None
    ) -> list[Vulnerability]:
        """Detect SSRF vulnerabilities in file content."""
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
                        if not self._is_likely_false_positive(line, category):
                            vuln = self._create_vulnerability(
                                category=category,
                                matched_text=line.strip(),
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=line.strip(),
                            )
                            vulnerabilities.append(vuln)
                            break  # one finding per category per line

        return vulnerabilities

    # Word-boundary false-positive keywords (avoid matching substrings like "latest" -> "test")
    _FP_WORDS = re.compile(
        r"\b(?:test|example|mock|fixture|stub|sample)\b", re.IGNORECASE
    )

    def _is_likely_false_positive(self, line: str, category: str) -> bool:
        """Suppress common false positives."""
        if self._FP_WORDS.search(line):
            return True

        # For redirect params: suppress if it's clearly a config key definition not user input
        if category == "redirect_params":
            line_lower = line.lower()
            if any(kw in line_lower for kw in ["localhost", "example.com", "127.0.0.1"]):
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
        """Create a SSRF vulnerability object."""

        metadata_map = {
            "python_http_variable": {
                "title": "SSRF: Unvalidated URL in Python HTTP Request",
                "description": (
                    f"A variable URL is passed directly to a Python HTTP client: '{matched_text[:120]}'. "
                    "If this variable originates from user input or tool arguments without allowlist "
                    "validation, an attacker can redirect the request to internal services, cloud metadata "
                    "endpoints (169.254.169.254), or internal infrastructure. In MCP servers, tool "
                    "arguments are controllable by the agent and potentially by prompt injection."
                ),
                "severity": Severity.HIGH,
                "confidence": Confidence.MEDIUM,
                "cwe_id": "CWE-918",
                "cvss_score": 8.6,
                "remediation": (
                    "1. Validate URLs against an allowlist of permitted hosts/schemes\n"
                    "2. Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x)\n"
                    "3. Resolve hostnames and check the resolved IP against the blocklist\n"
                    "4. Use a dedicated HTTP proxy that enforces egress rules\n"
                    "5. If the URL must be dynamic, use a strict allowlist: allowed_hosts = {'api.example.com'}"
                ),
                "mitre_attack_ids": ["T1090", "T1071.001"],
            },
            "js_fetch_variable": {
                "title": "SSRF: Unvalidated URL in JavaScript fetch/axios",
                "description": (
                    f"A variable URL is passed directly to fetch() or axios: '{matched_text[:120]}'. "
                    "Without URL validation, an attacker can cause the server to make requests to "
                    "arbitrary internal or external hosts. In Node.js MCP servers, this can expose "
                    "cloud metadata services and internal network endpoints."
                ),
                "severity": Severity.HIGH,
                "confidence": Confidence.MEDIUM,
                "cwe_id": "CWE-918",
                "cvss_score": 8.6,
                "remediation": (
                    "1. Validate the URL using the URL constructor and check the hostname\n"
                    "2. Maintain an allowlist of permitted hostnames\n"
                    "3. Block requests to 169.254.x.x, 10.x.x.x, 172.16-31.x.x, 192.168.x.x\n"
                    "4. Use a request interceptor to enforce URL validation centrally"
                ),
                "mitre_attack_ids": ["T1090", "T1071.001"],
            },
            "cloud_metadata": {
                "title": "SSRF: Cloud Metadata Endpoint Reference",
                "description": (
                    f"Hardcoded cloud metadata service endpoint detected: '{matched_text[:120]}'. "
                    "The AWS Instance Metadata Service (169.254.169.254), GCP metadata "
                    "(metadata.google.internal), and Azure IMDS are accessible from cloud instances. "
                    "If an SSRF vulnerability exists anywhere in the server, attackers can use these "
                    "endpoints to steal cloud credentials (IAM roles, service account tokens). "
                    "This finding may indicate the server is aware of and interacts with metadata services."
                ),
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-918",
                "cvss_score": 9.8,
                "remediation": (
                    "1. Remove direct references to cloud metadata endpoints from application code\n"
                    "2. Use IMDSv2 (AWS) which requires a PUT request with a session token\n"
                    "3. Use IAM roles and SDKs instead of direct metadata endpoint access\n"
                    "4. Block 169.254.169.254 at the network level with security groups/firewall rules\n"
                    "5. Enable IMDSv2 only and set hop limit to 1 to prevent SSRF access"
                ),
                "mitre_attack_ids": ["T1552.005", "T1078.004"],
            },
            "redirect_params": {
                "title": "SSRF: Redirect/Callback URL Parameter Without Validation",
                "description": (
                    f"A redirect, callback, or webhook URL parameter is defined: '{matched_text[:120]}'. "
                    "Without strict validation, these parameters can be used for open redirect attacks "
                    "or SSRF if the server follows the redirect. In MCP OAuth flows, unvalidated "
                    "redirect_uri parameters enable authorization code theft (CWE-601)."
                ),
                "severity": Severity.MEDIUM,
                "confidence": Confidence.LOW,
                "cwe_id": "CWE-601",
                "cvss_score": 6.1,
                "remediation": (
                    "1. Validate redirect_uri against a pre-registered allowlist\n"
                    "2. Never redirect to user-supplied URLs without validation\n"
                    "3. For webhooks: validate the URL scheme (https only) and hostname\n"
                    "4. Log all redirect/callback URL usage for audit trails"
                ),
                "mitre_attack_ids": ["T1090"],
            },
            "go_http_variable": {
                "title": "SSRF: Unvalidated URL in Go HTTP Client",
                "description": (
                    f"A variable URL is passed directly to a Go HTTP client: '{matched_text[:120]}'. "
                    "Without URL validation, the server can be directed to make requests to internal "
                    "services or cloud metadata endpoints. Go's net/http client follows redirects by "
                    "default, which can extend the SSRF reach."
                ),
                "severity": Severity.HIGH,
                "confidence": Confidence.MEDIUM,
                "cwe_id": "CWE-918",
                "cvss_score": 8.6,
                "remediation": (
                    "1. Parse the URL and validate hostname against an allowlist\n"
                    "2. Use a custom http.Transport with DialContext to block private IP ranges\n"
                    "3. Disable redirect following: client.CheckRedirect = func(...) error { return http.ErrUseLastResponse }\n"
                    "4. Consider using a dedicated egress proxy"
                ),
                "mitre_attack_ids": ["T1090", "T1071.001"],
            },
            "java_url_variable": {
                "title": "SSRF: Unvalidated URL in Java HTTP Client",
                "description": (
                    f"A variable URL is passed to a Java URL/HttpClient: '{matched_text[:120]}'. "
                    "Java's URL.openConnection() and HttpClient follow redirects by default and will "
                    "access any URL including cloud metadata endpoints and internal services."
                ),
                "severity": Severity.HIGH,
                "confidence": Confidence.MEDIUM,
                "cwe_id": "CWE-918",
                "cvss_score": 8.6,
                "remediation": (
                    "1. Validate the URL host against an allowlist before connecting\n"
                    "2. Use InetAddress.getByName() to resolve and check the IP\n"
                    "3. Block private IP ranges: 10.x, 172.16-31.x, 192.168.x, 169.254.x\n"
                    "4. Disable automatic redirect following in HttpClient"
                ),
                "mitre_attack_ids": ["T1090", "T1071.001"],
            },
        }

        meta = metadata_map[category]

        return Vulnerability(
            type=VulnerabilityType.SSRF,
            title=meta["title"],
            description=meta["description"],
            severity=meta["severity"],
            confidence=meta["confidence"],
            file_path=str(file_path),
            line_number=line_number,
            code_snippet=code_snippet,
            cwe_id=meta["cwe_id"],
            cvss_score=meta["cvss_score"],
            remediation=meta["remediation"],
            references=[
                f"https://cwe.mitre.org/data/definitions/{meta['cwe_id'].split('-')[1]}.html",
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                "https://portswigger.net/web-security/ssrf",
            ],
            detector=self.name,
            engine="static",
            mitre_attack_ids=meta["mitre_attack_ids"],
        )
