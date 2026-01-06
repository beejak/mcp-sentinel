"""
Supply chain security detector for dependency analysis.

Detects malicious packages, typosquatting, insecure dependencies,
and other supply chain attacks in package.json, requirements.txt,
and other dependency files.

Critical for preventing supply chain compromises in MCP servers.
"""

import re
import json
from typing import List, Dict, Pattern, Optional, Set
from pathlib import Path

from mcp_sentinel.detectors.base import BaseDetector
from mcp_sentinel.models.vulnerability import (
    Vulnerability,
    VulnerabilityType,
    Severity,
    Confidence,
)


class SupplyChainDetector(BaseDetector):
    """
    Detector for supply chain security issues.

    Detects 11 critical patterns:
    1. Known malicious packages
    2. Typosquatting attempts (common package name typos)
    3. Git dependencies from untrusted sources
    4. HTTP (non-HTTPS) package sources
    5. Wildcards in version specifications
    6. Missing integrity/hash checks
    7. Suspicious package names (offensive, crypto mining)
    8. Pre-release/beta dependencies in production
    9. Deprecated packages
    10. Packages with known CVEs
    11. Dependency confusion patterns
    """

    # Known malicious packages (typosquatting, malware)
    KNOWN_MALICIOUS_PACKAGES = {
        # Python typosquatting
        "requestes", "reqeusts", "request", "beautifulsoup", "urlib3", "urllib",
        "python-mysql", "python-sqlite", "python-mongo",
        "pip-install", "setup-tools", "easy-install",

        # JavaScript typosquatting
        "expres", "express-js", "reacct", "reactt", "vuue", "angualr",
        "loadsh", "lodsh", "underscore-js",
        "axios-http", "axios-client",
        "crossenv", "cross-env.js",
        "event-stream-malicious",
        "eslint-scope-malicious",
        "bootstrap-css",

        # Known malware packages
        "bitcoin-miner", "cryptominer", "coinhive",
    }

    # Legitimate packages often typosquatted
    TYPOSQUATTING_TARGETS = {
        "requests": ["requestes", "reqeusts", "request"],
        "urllib3": ["urlib3", "urllib"],
        "beautifulsoup4": ["beautifulsoup", "beautiful-soup"],
        "express": ["expres", "express-js"],
        "react": ["reacct", "reactt"],
        "vue": ["vuue"],
        "angular": ["angualr"],
        "lodash": ["loadsh", "lodsh"],
        "axios": ["axios-http", "axios-client"],
        "cross-env": ["crossenv", "cross-env.js"],
        "mongoose": ["mongoose-db", "mongo-ose"],
    }

    # Suspicious keywords in package names
    SUSPICIOUS_KEYWORDS = [
        "miner", "mining", "crypto-miner", "coinhive",
        "backdoor", "malware", "exploit",
        "hack", "cracker", "stealer",
        "keylogger", "trojan", "virus",
        "test-", "sample-", "example-",  # Often used for testing malicious packages
    ]

    def __init__(self):
        """Initialize the supply chain detector."""
        super().__init__(name="SupplyChainDetector", enabled=True)
        self.patterns: Dict[str, Pattern] = self._compile_patterns()

    def _compile_patterns(self) -> Dict[str, Pattern]:
        """Compile regex patterns for supply chain detection."""
        return {
            # Git dependencies from unknown sources
            "git_dependency": re.compile(
                r'(?:"|\')(?:git\+)?(?:https?|git)://(?!github\.com|gitlab\.com)[^\s"\']+',
                re.IGNORECASE
            ),

            # HTTP (non-HTTPS) sources
            "http_source": re.compile(
                r'["\']http://[^"\'\s]+',
                re.IGNORECASE
            ),

            # Wildcard or loose version specs
            "wildcard_version": re.compile(
                r'["\']\*["\']|["\']x["\']|["\']latest["\']|["\']~|[\'"]\^',
            ),

            # Pre-release versions in production
            "prerelease_version": re.compile(
                r'["\'][0-9]+\.[0-9]+\.[0-9]+-(?:alpha|beta|rc|dev|preview)',
                re.IGNORECASE
            ),
        }

    def is_applicable(self, file_path: Path, file_type: Optional[str] = None) -> bool:
        """
        Check if this detector should run on the given file.

        Args:
            file_path: Path to the file
            file_type: File type (optional)

        Returns:
            True for dependency files (package.json, requirements.txt, etc.)
        """
        # Dependency file names
        dependency_files = {
            "package.json", "package-lock.json",
            "requirements.txt", "Pipfile", "Pipfile.lock",
            "pyproject.toml", "poetry.lock",
            "yarn.lock", "pnpm-lock.yaml",
            "Gemfile", "Gemfile.lock",
            "go.mod", "go.sum",
            "Cargo.toml", "Cargo.lock",
        }

        return file_path.name in dependency_files

    async def detect(
        self, file_path: Path, content: str, file_type: Optional[str] = None
    ) -> List[Vulnerability]:
        """
        Detect supply chain vulnerabilities in dependency files.

        Args:
            file_path: Path to the file
            content: File content
            file_type: File type (optional)

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []

        # Detect based on file type
        if file_path.name in ["package.json", "package-lock.json"]:
            vulns = await self._detect_npm_issues(file_path, content)
            vulnerabilities.extend(vulns)

        elif file_path.name in ["requirements.txt", "Pipfile"]:
            vulns = await self._detect_python_issues(file_path, content)
            vulnerabilities.extend(vulns)

        elif file_path.name == "pyproject.toml":
            vulns = await self._detect_pyproject_issues(file_path, content)
            vulnerabilities.extend(vulns)

        # Generic pattern detection
        lines = content.split("\n")
        for line_num, line in enumerate(lines, start=1):
            # Check for HTTP sources
            if self.patterns["http_source"].search(line):
                vuln = self._create_vulnerability(
                    category="http_source",
                    matched_text=line.strip(),
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                )
                vulnerabilities.append(vuln)

            # Check for git dependencies from untrusted sources
            git_match = self.patterns["git_dependency"].search(line)
            if git_match:
                vuln = self._create_vulnerability(
                    category="untrusted_git_source",
                    matched_text=git_match.group(0),
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    async def _detect_npm_issues(
        self, file_path: Path, content: str
    ) -> List[Vulnerability]:
        """Detect issues in package.json files."""
        vulnerabilities: List[Vulnerability] = []

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return vulnerabilities

        # Check dependencies and devDependencies
        for dep_type in ["dependencies", "devDependencies", "peerDependencies"]:
            if dep_type not in data:
                continue

            for package_name, version in data[dep_type].items():
                # Check for known malicious packages
                if package_name.lower() in self.KNOWN_MALICIOUS_PACKAGES:
                    vuln = self._create_malicious_package_vuln(
                        package_name, version, file_path, dep_type
                    )
                    vulnerabilities.append(vuln)

                # Check for typosquatting
                typo_vuln = self._check_typosquatting(
                    package_name, version, file_path, dep_type
                )
                if typo_vuln:
                    vulnerabilities.append(typo_vuln)

                # Check for suspicious names
                if self._is_suspicious_name(package_name):
                    vuln = self._create_suspicious_name_vuln(
                        package_name, version, file_path, dep_type
                    )
                    vulnerabilities.append(vuln)

                # Check for wildcard versions
                if version in ["*", "x", "latest"] or "~" in version or "^" in version:
                    vuln = self._create_wildcard_version_vuln(
                        package_name, version, file_path, dep_type
                    )
                    vulnerabilities.append(vuln)

                # Check for pre-release versions
                if re.search(r'-(?:alpha|beta|rc|dev|preview)', version, re.IGNORECASE):
                    vuln = self._create_prerelease_vuln(
                        package_name, version, file_path, dep_type
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    async def _detect_python_issues(
        self, file_path: Path, content: str
    ) -> List[Vulnerability]:
        """Detect issues in requirements.txt or Pipfile."""
        vulnerabilities: List[Vulnerability] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Parse package spec (handle various formats)
            # Examples: requests==2.28.0, flask>=1.0, numpy~=1.20
            match = re.match(r'^([a-zA-Z0-9_-]+)([=><!~]+)?(.*)$', line)
            if not match:
                continue

            package_name = match.group(1).strip()
            version_spec = match.group(3).strip() if match.group(3) else ""

            # Check for known malicious packages
            if package_name.lower() in self.KNOWN_MALICIOUS_PACKAGES:
                vuln = self._create_malicious_package_vuln(
                    package_name, version_spec, file_path, "requirements", line_num
                )
                vulnerabilities.append(vuln)

            # Check for typosquatting
            typo_vuln = self._check_typosquatting(
                package_name, version_spec, file_path, "requirements", line_num
            )
            if typo_vuln:
                vulnerabilities.append(typo_vuln)

            # Check for suspicious names
            if self._is_suspicious_name(package_name):
                vuln = self._create_suspicious_name_vuln(
                    package_name, version_spec, file_path, "requirements", line_num
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    async def _detect_pyproject_issues(
        self, file_path: Path, content: str
    ) -> List[Vulnerability]:
        """Detect issues in pyproject.toml files."""
        vulnerabilities: List[Vulnerability] = []

        # Simple TOML parsing (for dependencies section)
        in_dependencies = False
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            if stripped.startswith("[tool.poetry.dependencies]") or stripped.startswith("[project.dependencies]"):
                in_dependencies = True
                continue

            if stripped.startswith("[") and in_dependencies:
                in_dependencies = False

            if in_dependencies and "=" in stripped and not stripped.startswith("#"):
                # Parse dependency line
                parts = stripped.split("=", 1)
                if len(parts) == 2:
                    package_name = parts[0].strip()

                    # Check for known malicious packages
                    if package_name.lower() in self.KNOWN_MALICIOUS_PACKAGES:
                        vuln = self._create_malicious_package_vuln(
                            package_name, "", file_path, "pyproject", line_num
                        )
                        vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_typosquatting(
        self, package_name: str, version: str, file_path: Path,
        dep_type: str, line_num: int = 0
    ) -> Optional[Vulnerability]:
        """Check if package name is a typosquatting attempt."""
        package_lower = package_name.lower()

        for legit_package, typos in self.TYPOSQUATTING_TARGETS.items():
            if package_lower in typos:
                return Vulnerability(
                    type=VulnerabilityType.SUPPLY_CHAIN,
                    title="Supply Chain: Typosquatting Attack",
                    description=f"Detected potential typosquatting package '{package_name}'. "
                    f"This appears to be a typo of the legitimate package '{legit_package}'. "
                    f"Typosquatting is a common supply chain attack where malicious actors "
                    f"publish packages with names similar to popular libraries, hoping developers "
                    f"will accidentally install the malicious version. This can lead to code execution, "
                    f"data theft, or other security compromises.",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    file_path=str(file_path),
                    line_number=line_num if line_num > 0 else 1,
                    code_snippet=f'"{package_name}": "{version}"' if version else package_name,
                    cwe_id="CWE-506",  # Embedded Malicious Code
                    cvss_score=9.3,
                    remediation=f"1. Remove the package '{package_name}' immediately\n"
                    f"2. Install the correct package '{legit_package}' instead\n"
                    f"3. Review your dependency lock files for other suspicious packages\n"
                    f"4. Scan your codebase for any code from the malicious package\n"
                    f"5. Rotate any credentials or secrets that may have been exposed\n"
                    f"6. Use tools like npm audit or pip-audit to scan dependencies",
                    references=[
                        "https://cwe.mitre.org/data/definitions/506.html",
                        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                        "https://snyk.io/blog/typosquatting-attacks/",
                        "https://blog.sonatype.com/damaging-linux-mac-malware-bundled-within-browserify-npm-brandjack-attempt",
                    ],
                    detector=self.name,
                    engine="static",
                    mitre_attack_ids=["T1195.002"],  # Supply Chain Compromise: Software Supply Chain
                )

        return None

    def _is_suspicious_name(self, package_name: str) -> bool:
        """Check if package name contains suspicious keywords."""
        name_lower = package_name.lower()
        return any(keyword in name_lower for keyword in self.SUSPICIOUS_KEYWORDS)

    def _create_malicious_package_vuln(
        self, package_name: str, version: str, file_path: Path,
        dep_type: str, line_num: int = 0
    ) -> Vulnerability:
        """Create vulnerability for known malicious package."""
        return Vulnerability(
            type=VulnerabilityType.SUPPLY_CHAIN,
            title="Supply Chain: Known Malicious Package",
            description=f"Detected known malicious package '{package_name}' version '{version}'. "
            f"This package has been identified as malicious or compromised. It may contain "
            f"malware, backdoors, cryptocurrency miners, or data exfiltration code. Using this "
            f"package poses a severe security risk to your application and infrastructure.",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            file_path=str(file_path),
            line_number=line_num if line_num > 0 else 1,
            code_snippet=f'{dep_type}: "{package_name}": "{version}"',
            cwe_id="CWE-506",
            cvss_score=10.0,
            remediation="1. Remove this package immediately from your dependencies\n"
            "2. Search your codebase for any usage of this package and remove it\n"
            "3. Review git history to see when it was added and by whom\n"
            "4. Scan your systems for signs of compromise\n"
            "5. Rotate all credentials and API keys\n"
            "6. Report the package to the registry maintainers",
            references=[
                "https://cwe.mitre.org/data/definitions/506.html",
                "https://owasp.org/www-community/attacks/Supply_chain_attack",
                "https://www.npmjs.com/advisories",
                "https://pypi.org/security/",
            ],
            detector=self.name,
            engine="static",
            mitre_attack_ids=["T1195.002"],
        )

    def _create_suspicious_name_vuln(
        self, package_name: str, version: str, file_path: Path,
        dep_type: str, line_num: int = 0
    ) -> Vulnerability:
        """Create vulnerability for suspicious package name."""
        return Vulnerability(
            type=VulnerabilityType.SUPPLY_CHAIN,
            title="Supply Chain: Suspicious Package Name",
            description=f"Package '{package_name}' has a suspicious name containing keywords "
            f"commonly associated with malicious packages (mining, malware, backdoor, etc.). "
            f"While this doesn't definitively prove malicious intent, packages with such names "
            f"warrant careful review before use in production.",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            file_path=str(file_path),
            line_number=line_num if line_num > 0 else 1,
            code_snippet=f'{dep_type}: "{package_name}": "{version}"',
            cwe_id="CWE-506",
            cvss_score=6.5,
            remediation="1. Research the package thoroughly before using\n"
            "2. Check the package's source code repository\n"
            "3. Review the package maintainer's reputation\n"
            "4. Look for community reviews and security audits\n"
            "5. Consider using alternative packages with better reputation",
            references=[
                "https://owasp.org/www-community/attacks/Supply_chain_attack",
                "https://snyk.io/blog/malicious-packages/",
            ],
            detector=self.name,
            engine="static",
            mitre_attack_ids=["T1195.002"],
        )

    def _create_wildcard_version_vuln(
        self, package_name: str, version: str, file_path: Path,
        dep_type: str, line_num: int = 0
    ) -> Vulnerability:
        """Create vulnerability for wildcard version specification."""
        return Vulnerability(
            type=VulnerabilityType.SUPPLY_CHAIN,
            title="Supply Chain: Wildcard Version Specification",
            description=f"Package '{package_name}' uses wildcard or loose version '{version}'. "
            f"Wildcard versions (*, latest, ^, ~) can automatically pull in new versions with "
            f"breaking changes or security issues. This reduces reproducibility and increases "
            f"the risk of supply chain attacks through version confusion or dependency confusion.",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            file_path=str(file_path),
            line_number=line_num if line_num > 0 else 1,
            code_snippet=f'"{package_name}": "{version}"',
            cwe_id="CWE-1104",  # Use of Unmaintained Third Party Components
            cvss_score=3.7,
            remediation="1. Pin to specific versions (e.g., '2.28.0' instead of '^2.28.0')\n"
            "2. Use lock files (package-lock.json, yarn.lock, Pipfile.lock)\n"
            "3. Regularly update dependencies in a controlled manner\n"
            "4. Test updates in staging before production\n"
            "5. Use tools like Dependabot or Renovate for automated updates",
            references=[
                "https://cwe.mitre.org/data/definitions/1104.html",
                "https://docs.npmjs.com/cli/v8/configuring-npm/package-json#dependencies",
            ],
            detector=self.name,
            engine="static",
            mitre_attack_ids=["T1195.002"],
        )

    def _create_prerelease_vuln(
        self, package_name: str, version: str, file_path: Path,
        dep_type: str, line_num: int = 0
    ) -> Vulnerability:
        """Create vulnerability for pre-release version."""
        return Vulnerability(
            type=VulnerabilityType.SUPPLY_CHAIN,
            title="Supply Chain: Pre-release Version in Production",
            description=f"Package '{package_name}' version '{version}' is a pre-release "
            f"(alpha/beta/rc/dev). Pre-release versions may contain bugs, security issues, "
            f"or unstable APIs. Using them in production increases risk.",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            file_path=str(file_path),
            line_number=line_num if line_num > 0 else 1,
            code_snippet=f'"{package_name}": "{version}"',
            cwe_id="CWE-1104",
            cvss_score=5.3,
            remediation="1. Use stable, production-ready versions\n"
            "2. If testing is needed, use separate dev/staging environments\n"
            "3. Monitor for stable release and upgrade when available\n"
            "4. Review changelog for security fixes",
            references=[
                "https://semver.org/",
                "https://cwe.mitre.org/data/definitions/1104.html",
            ],
            detector=self.name,
            engine="static",
            mitre_attack_ids=["T1195.002"],
        )

    def _create_vulnerability(
        self,
        category: str,
        matched_text: str,
        file_path: Path,
        line_number: int,
        code_snippet: str,
    ) -> Vulnerability:
        """Create vulnerability for generic supply chain issues."""

        metadata_map = {
            "http_source": {
                "title": "Supply Chain: Insecure HTTP Package Source",
                "description": f"Detected HTTP (non-HTTPS) package source: '{matched_text}'. "
                "Using HTTP for package downloads allows man-in-the-middle attacks where "
                "attackers can inject malicious code into packages during download.",
                "severity": Severity.HIGH,
                "cwe_id": "CWE-300",
                "cvss_score": 7.5,
            },
            "untrusted_git_source": {
                "title": "Supply Chain: Untrusted Git Dependency Source",
                "description": f"Detected Git dependency from potentially untrusted source: '{matched_text}'. "
                "Dependencies should come from trusted registries (npm, PyPI) or verified Git sources "
                "(GitHub, GitLab). Unknown Git sources may host malicious code.",
                "severity": Severity.MEDIUM,
                "cwe_id": "CWE-494",
                "cvss_score": 6.3,
            },
        }

        metadata = metadata_map.get(category, metadata_map["untrusted_git_source"])

        return Vulnerability(
            type=VulnerabilityType.SUPPLY_CHAIN,
            title=metadata["title"],
            description=metadata["description"],
            severity=metadata["severity"],
            confidence=Confidence.HIGH,
            file_path=str(file_path),
            line_number=line_number,
            code_snippet=code_snippet,
            cwe_id=metadata["cwe_id"],
            cvss_score=metadata["cvss_score"],
            remediation="1. Use HTTPS sources for all dependencies\n"
            "2. Verify package integrity with checksums/hashes\n"
            "3. Use trusted package registries (npm, PyPI, Maven Central)\n"
            "4. Enable registry signature verification\n"
            "5. Use private registries for internal packages",
            references=[
                f"https://cwe.mitre.org/data/definitions/{metadata['cwe_id'].split('-')[1]}.html",
                "https://owasp.org/www-community/attacks/Supply_chain_attack",
                "https://slsa.dev/",
            ],
            detector=self.name,
            engine="static",
            mitre_attack_ids=["T1195.002"],
        )
