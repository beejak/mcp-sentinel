"""
Supply Chain & Package Integrity detector for MCP security.

Detects patterns indicating compromised or malicious packages:
- Encoded payload execution (base64-encoded eval, obfuscated code)
- Install-time shell execution (setup.py, postinstall hooks)
- Install-time network calls (data exfiltration on install)
- Covert data exfiltration (env vars / secrets sent outbound)
- Silent BCC/forward injection (hardcoded addresses in email tools)
- Dependency confusion (non-standard registry configuration)
- Known typosquatted package names (real-world PyPI/npm incidents)

These attack vectors are specific to MCP server packages distributed via
PyPI or npm, where a compromised or impersonating package can execute
arbitrary code during `pip install` or `npm install`.
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


class SupplyChainDetector(BaseDetector):
    """
    Detector for supply chain attack patterns in MCP server packages.

    Detects:
    1. Encoded payload execution (eval(base64.b64decode(...)), eval(atob(...)))
    2. Install-time shell execution (cmdclass in setup.py, postinstall/prepare npm hooks)
    3. Install-time network calls (HTTP requests inside install hooks)
    4. Covert data exfiltration (outbound calls containing os.environ or file reads)
    5. Silent BCC/forward injection (hardcoded emails in BCC/forward fields)
    6. Dependency confusion (--extra-index-url, non-standard registry URLs)
    7. Known typosquatted package names (curated list from real incidents)
    """

    def __init__(self) -> None:
        """Initialize the supply chain detector."""
        super().__init__(name="SupplyChainDetector", enabled=True)
        self.patterns: dict[str, list[Pattern[str]]] = self._compile_patterns()

    def _compile_patterns(self) -> dict[str, list[Pattern[str]]]:
        """Compile regex patterns for supply chain attack detection."""
        return {
            # Encoded payload execution — base64-wrapped eval/exec
            "encoded_payload": [
                re.compile(
                    r"eval\s*\(\s*(?:base64\.b64decode|base64\.urlsafe_b64decode"
                    r"|codecs\.decode|binascii\.a2b_base64)\s*\(",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"exec\s*\(\s*(?:base64\.b64decode|base64\.urlsafe_b64decode"
                    r"|codecs\.decode|binascii\.a2b_base64)\s*\(",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"eval\s*\(\s*atob\s*\(",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"eval\s*\(\s*Buffer\.from\s*\([^,)]+,\s*['\"]base64['\"]\s*\)\s*\.toString",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"exec\s*\(\s*compile\s*\(\s*(?:base64|zlib|gzip|lzma)",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"__import__\s*\(\s*['\"]base64['\"]\s*\).*\.b64decode",
                    re.IGNORECASE,
                ),
                # Compressed + encoded payloads (common obfuscation)
                re.compile(
                    r"zlib\.decompress\s*\(\s*base64\.b64decode",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"marshal\.loads\s*\(\s*(?:base64|zlib|gzip)",
                    re.IGNORECASE,
                ),
            ],
            # Install-time shell execution (setup.py cmdclass, npm postinstall)
            "install_script_exec": [
                # Python setup.py with subprocess/os.system in install commands
                re.compile(
                    r"class\s+\w+\s*\(\s*(?:install|build_ext|develop|egg_info)\s*\)",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"cmdclass\s*=\s*\{",
                    re.IGNORECASE,
                ),
                # npm/yarn lifecycle hooks that execute shell commands
                re.compile(
                    r'"(?:preinstall|postinstall|prepare|prepack)"\s*:\s*"(?!(?:echo|node\s+\.|npm\s+run\s+build))',
                    re.IGNORECASE,
                ),
                # Direct shell execution inside setup.py / install hooks
                re.compile(
                    r"subprocess\.(call|run|Popen|check_output)\s*\(\s*\[?\s*['\"](?:sh|bash|cmd|powershell|curl|wget|nc|python)",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"os\.system\s*\(\s*['\"](?:sh|bash|curl|wget|nc|python|powershell)",
                    re.IGNORECASE,
                ),
            ],
            # Install-time network calls (HTTP requests inside setup.py / install hooks)
            "install_script_network": [
                re.compile(
                    r"(?:urllib|requests|httpx|aiohttp|http\.client)\b.*(?:get|post|urlopen|request)\s*\(",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"(?:curl|wget)\s+(?:-[a-zA-Z]*\s+)*https?://(?!(?:pypi\.org|files\.pythonhosted\.org|registry\.npmjs\.org|github\.com|raw\.githubusercontent\.com))",
                    re.IGNORECASE,
                ),
            ],
            # Covert data exfiltration — outbound HTTP containing environment/secrets
            "covert_exfiltration": [
                # Python: requests/httpx/urllib with os.environ or open() in payload
                re.compile(
                    r"requests\.(get|post|put)\s*\([^)]*(?:os\.environ|os\.getenv|open\s*\()",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"requests\.post\s*\([^)]*(?:data|json|params)\s*=\s*(?:os\.|dict\(|{[^}]*os\.)",
                    re.IGNORECASE,
                ),
                # DNS exfiltration pattern (encoding data in DNS lookups)
                re.compile(
                    r"socket\.(gethostbyname|getaddrinfo)\s*\([^\n]*?(?:\+|format|f['\"])",
                    re.IGNORECASE,
                ),
                # JavaScript: fetch/axios with env vars in body
                re.compile(
                    r"(?:fetch|axios\.post)\s*\([^)]*process\.env",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"(?:fetch|axios)\s*\([^)]*(?:fs\.readFile|fs\.readFileSync)",
                    re.IGNORECASE,
                ),
                # subprocess output piped to network
                re.compile(
                    r"subprocess\.\w+\s*\([^)]*\)\s*.*requests\.",
                    re.IGNORECASE,
                ),
            ],
            # Silent BCC/forward injection in email-sending MCP tools
            "silent_bcc": [
                re.compile(
                    r"['\"]bcc['\"]?\s*[=:]\s*['\"][a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}['\"]",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"Bcc\s*:\s*[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"msg\[[\'\"]Bcc[\'\"]\]\s*=\s*['\"][a-zA-Z0-9._%+\-]+@",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"forward[-_]?to\s*=\s*['\"][a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}['\"]",
                    re.IGNORECASE,
                ),
                # SMTP addheader BCC
                re.compile(
                    r"\.(?:add_header|addheader)\s*\(['\"](?:Bcc|X-Forward-To|X-Redirect-To)['\"]",
                    re.IGNORECASE,
                ),
            ],
            # Dependency confusion — non-standard registries / index overrides
            "dependency_confusion": [
                re.compile(
                    r"--extra-index-url\s+https?://(?!(?:pypi\.org|files\.pythonhosted\.org))",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"--index-url\s+https?://(?!(?:pypi\.org|files\.pythonhosted\.org))",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"index-url\s*=\s*https?://(?!(?:pypi\.org|files\.pythonhosted\.org))",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"registry\s*=\s*https?://(?!(?:registry\.npmjs\.org|npmjs\.com))",
                    re.IGNORECASE,
                ),
                re.compile(
                    r'"registry"\s*:\s*"https?://(?!(?:registry\.npmjs\.org|npmjs\.com))',
                    re.IGNORECASE,
                ),
                # pip.conf or .npmrc with alternative registry
                re.compile(
                    r"\[global\]\s*\n[^\[]*index\s*=\s*https?://(?!(?:pypi\.org|files\.pythonhosted\.org))",
                    re.IGNORECASE | re.MULTILINE,
                ),
            ],
            # Known typosquatted package names (real PyPI/npm incidents)
            "known_typosquat": [
                # PyPI typosquats (real incidents)
                re.compile(
                    r"(?:import|from|install|pip\s+install|requires\s*=.*?['\"])\s*['\"]?"
                    r"(?:colourama|urllib3-compat|djago|reqests|requets|request2|"
                    r"python-dateutil2|pycryto|cryptography2|setup-tools|"
                    r"python-opencv|openssl-python|pyyaml2|boto|boto4|"
                    r"aiohttp-requests|python-requests|request-plus|"
                    r"inflect2|distutils2|pip-install|pip2|pip-utils)['\"]?",
                    re.IGNORECASE,
                ),
                # npm typosquats (real incidents)
                re.compile(
                    r"(?:require\s*\(|import\s+.*from|\"dependencies\"[^}]*?\")"
                    r"['\"](?:crossenv|loadyaml|mongose|mongosse|nodecord|"
                    r"discordjs-next|discord-js|reactor-dom|reacr|react-core|"
                    r"exprees|expresss|koa2|lodahs|underscorejs|"
                    r"event-stream2|event-source|colors2)['\"]",
                    re.IGNORECASE,
                ),
            ],
        }

    def is_applicable(self, file_path: Path, file_type: Optional[str] = None) -> bool:
        """Apply to package manifests, install scripts, and code files."""
        name = file_path.name.lower()

        # Always check these specific filenames regardless of extension
        always_check = {
            "setup.py", "setup.cfg", "pyproject.toml", "pipfile",
            "requirements.txt", "requirements-dev.txt", "package.json",
            ".npmrc", "pip.conf", "pip.ini",
        }
        if name in always_check:
            return True

        if file_type:
            return file_type in ["python", "javascript", "typescript", "shell"]

        return file_path.suffix.lower() in {
            ".py", ".js", ".jsx", ".ts", ".tsx", ".sh", ".bash",
        }

    def detect_sync(
        self, file_path: Path, content: str, file_type: Optional[str] = None
    ) -> list[Vulnerability]:
        """Detect supply chain attack patterns in file content."""
        vulnerabilities: list[Vulnerability] = []
        lines = content.split("\n")

        # Determine context for smarter detection
        is_install_script = file_path.name.lower() in {"setup.py", "setup.cfg"}
        is_package_json = file_path.name.lower() == "package.json"

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Skip blank lines and pure comment lines
            if not stripped or stripped.startswith(("#", "//", "*", "/*")):
                continue

            for category, patterns in self.patterns.items():
                # install_script_network only fires inside setup.py-like files
                if category == "install_script_network" and not is_install_script:
                    continue

                # install_script_exec: only flag npm hooks in package.json
                if category == "install_script_exec" and not (
                    is_install_script or is_package_json
                ):
                    # Still detect subprocess/os.system patterns in .py files
                    patterns = [
                        p for p in patterns
                        if re.search(r"subprocess|os\.system", p.pattern)
                    ]
                    if not patterns:
                        continue

                for pattern in patterns:
                    if pattern.search(line):
                        if not self._is_likely_false_positive(line, category, file_path):
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

    _FP_WORDS = re.compile(
        r"\b(?:test|example|mock|fixture|stub|sample|dummy|fake|placeholder)\b",
        re.IGNORECASE,
    )

    def _is_likely_false_positive(
        self, line: str, category: str, file_path: Path
    ) -> bool:
        """Suppress common false positives."""
        # Dependency confusion and typosquat patterns use URLs/package names that
        # can legitimately contain words like "example" or "test" — skip generic check.
        if category not in ("dependency_confusion", "known_typosquat"):
            if self._FP_WORDS.search(line):
                return True

        # base64.b64decode for legitimate data (not wrapped in eval/exec) — handled by pattern
        # BCC in test files / documentation — handled by _FP_WORDS above

        if category == "silent_bcc":
            # Only flag if it looks like a code assignment, not a comment or doc
            if not any(ch in line for ch in ("=", ":", "[", "(")):
                return True

        if category == "dependency_confusion":
            # Skip lines that are clearly comments
            stripped = line.strip()
            if stripped.startswith(("#", ";")):
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
        """Create a supply chain vulnerability object."""

        metadata_map = {
            "encoded_payload": {
                "title": "Supply Chain: Encoded Payload Execution",
                "description": (
                    f"Base64-encoded or otherwise obfuscated code is being executed: "
                    f"'{matched_text[:120]}'. "
                    "This is a primary indicator of malicious package compromise. "
                    "Legitimate packages have no reason to base64-encode executable code — "
                    "this pattern is used to evade static analysis scanners. "
                    "The decoded payload may steal credentials, exfiltrate data, or install backdoors."
                ),
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-506",
                "cvss_score": 9.8,
                "remediation": (
                    "1. Do not use eval/exec with encoded content in any production package\n"
                    "2. If this is in a dependency, treat the package as compromised — "
                    "pin to a known-good version hash or switch to an audited alternative\n"
                    "3. Audit all recent installs if this was in a transitive dependency\n"
                    "4. Report the package to PyPI/npm security teams"
                ),
                "mitre_attack_ids": ["T1027", "T1059.006"],
            },
            "install_script_exec": {
                "title": "Supply Chain: Shell Execution During Package Install",
                "description": (
                    f"Shell commands are executed during package installation: "
                    f"'{matched_text[:120]}'. "
                    "Install-time code execution (setup.py cmdclass, npm postinstall hooks) "
                    "runs with the installing user's privileges. A malicious package can use "
                    "this to steal credentials, install persistence mechanisms, or pivot to "
                    "internal systems. This is a common vector in PyPI/npm supply chain attacks."
                ),
                "severity": Severity.HIGH,
                "confidence": Confidence.MEDIUM,
                "cwe_id": "CWE-829",
                "cvss_score": 8.8,
                "remediation": (
                    "1. Audit all code in setup.py cmdclass overrides and npm lifecycle hooks\n"
                    "2. Prefer packages that use only declarative configuration (pyproject.toml)\n"
                    "3. Use `pip install --no-build-isolation` and review build logs\n"
                    "4. Enable `--require-hashes` in requirements files to pin to known-good content\n"
                    "5. Use a package firewall (Artifactory, Sonatype Nexus) to block untrusted packages"
                ),
                "mitre_attack_ids": ["T1195.001", "T1059"],
            },
            "install_script_network": {
                "title": "Supply Chain: Network Call During Package Install",
                "description": (
                    f"An outbound network call is made during package installation: "
                    f"'{matched_text[:120]}'. "
                    "Legitimate packages do not make network calls during installation. "
                    "This pattern is used by malicious packages to exfiltrate system information "
                    "(hostname, username, environment variables, SSH keys) to attacker-controlled servers "
                    "at install time, before the package is ever used."
                ),
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-829",
                "cvss_score": 9.3,
                "remediation": (
                    "1. Treat any package that makes network calls during installation as malicious\n"
                    "2. Immediately revoke any credentials present in the environment at time of install\n"
                    "3. Report the package to PyPI/npm security teams\n"
                    "4. Use network isolation for CI environments running `pip install`\n"
                    "5. Prefer lock files with content hashes (`pip install --require-hashes`)"
                ),
                "mitre_attack_ids": ["T1195.001", "T1041"],
            },
            "covert_exfiltration": {
                "title": "Supply Chain: Covert Data Exfiltration",
                "description": (
                    f"Environment variables or file contents are being sent in an outbound HTTP request: "
                    f"'{matched_text[:120]}'. "
                    "This pattern sends sensitive data (API keys, tokens, credentials from environment "
                    "variables or local files) to a remote server. In MCP servers with broad filesystem "
                    "or environment access, this can silently exfiltrate user credentials, SSH keys, "
                    "cloud credentials, and other secrets."
                ),
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-200",
                "cvss_score": 9.8,
                "remediation": (
                    "1. Audit all outbound HTTP calls — verify the destination and payload\n"
                    "2. Never include os.environ, file reads, or credential stores in HTTP request bodies\n"
                    "3. Use egress filtering in production to restrict outbound connections\n"
                    "4. If found in a dependency, treat as a compromised package\n"
                    "5. Rotate all credentials that may have been in the environment"
                ),
                "mitre_attack_ids": ["T1041", "T1552.001"],
            },
            "silent_bcc": {
                "title": "Supply Chain: Silent BCC/Forward Injection",
                "description": (
                    f"A hardcoded email address is set as BCC or forward recipient: "
                    f"'{matched_text[:120]}'. "
                    "MCP servers that send emails on behalf of users may silently BCC all sent messages "
                    "to an attacker-controlled address. This enables surveillance of all communications "
                    "processed by the tool without any visible indication to the user."
                ),
                "severity": Severity.HIGH,
                "confidence": Confidence.MEDIUM,
                "cwe_id": "CWE-200",
                "cvss_score": 7.5,
                "remediation": (
                    "1. Remove all hardcoded BCC/forward addresses\n"
                    "2. BCC recipients must be explicitly provided by the user, not the package\n"
                    "3. Log all BCC/forward headers added to outgoing email for audit\n"
                    "4. Review the full email sending codepath for any hardcoded recipients"
                ),
                "mitre_attack_ids": ["T1114.003", "T1020"],
            },
            "dependency_confusion": {
                "title": "Supply Chain: Non-Standard Package Registry",
                "description": (
                    f"A non-standard package registry is configured: '{matched_text[:120]}'. "
                    "Configuring a private or unknown registry as the primary index can expose the "
                    "project to dependency confusion attacks, where a malicious public package with the "
                    "same name as an internal package takes precedence. This is exploitable when "
                    "internal package names are known to an attacker."
                ),
                "severity": Severity.MEDIUM,
                "confidence": Confidence.MEDIUM,
                "cwe_id": "CWE-829",
                "cvss_score": 6.8,
                "remediation": (
                    "1. Use `--extra-index-url` only with trusted private registries\n"
                    "2. Set `PIP_NO_INDEX=1` and only use `--find-links` for fully air-gapped builds\n"
                    "3. Use package namespacing (e.g., `@myorg/` npm scope) for internal packages\n"
                    "4. Enable registry integrity checking in your package manager\n"
                    "5. Use a package firewall that enforces namespace isolation"
                ),
                "mitre_attack_ids": ["T1195.001"],
            },
            "known_typosquat": {
                "title": "Supply Chain: Known Typosquatted Package Name",
                "description": (
                    f"A package name matching a known typosquat was found: '{matched_text[:120]}'. "
                    "Typosquatting attacks use package names that are visually similar to popular "
                    "packages (e.g., 'colourama' instead of 'colorama') to trick developers into "
                    "installing malicious code. These packages have been involved in real-world "
                    "credential theft and backdoor installation incidents."
                ),
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-829",
                "cvss_score": 8.1,
                "remediation": (
                    "1. Verify the exact package name — check PyPI/npm for the correct spelling\n"
                    "2. Remove the suspect package and install the correct one\n"
                    "3. Audit any systems that installed this package for signs of compromise\n"
                    "4. Rotate credentials that were accessible in those environments\n"
                    "5. Enable typosquatting protection in your package manager/firewall"
                ),
                "mitre_attack_ids": ["T1195.001"],
            },
        }

        meta = metadata_map[category]

        return Vulnerability(
            type=VulnerabilityType.SUPPLY_CHAIN,
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
                f"https://cwe.mitre.org/data/definitions/{str(meta['cwe_id']).split('-')[1]}.html",
                "https://owasp.org/www-project-top-ten/",
                "https://slsa.dev/",
                "https://blog.phylum.io/pypi-malware-rolls-out-red-team-tools/",
                "https://thehackernews.com/2022/08/researchers-warn-of-pypi-packages.html",
            ],
            detector=self.name,
            engine="static",
            mitre_attack_ids=meta["mitre_attack_ids"],
        )
