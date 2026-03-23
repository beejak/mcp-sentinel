"""
Insecure Deserialization detector for MCP security.

Deserialization of untrusted data is one of the most critical vulnerability
classes — OWASP Top 10 A8. MCP servers that deserialize tool arguments,
file contents, or network responses using unsafe deserializers can be
exploited for remote code execution.

Detects:
- pickle.loads() / pickle.load() on untrusted input
- yaml.load() without safe loader (arbitrary code via !!python/object)
- marshal.loads() on untrusted input (bypasses many Python sandboxes)
- eval() used to parse JSON or config instead of json.loads()
- shelve.open() with user-controlled paths (pickle-backed)
- jsonpickle.decode() without safe=True
- Java ObjectInputStream on untrusted data
- PHP unserialize() on untrusted input
- Node.js eval()/vm.runInContext() for JSON parsing
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


class InsecureDeserializationDetector(BaseDetector):
    """
    Detector for insecure deserialization vulnerabilities in MCP server code.

    Detects:
    1. pickle.loads/load() — Python object deserialization with RCE potential
    2. yaml.load() without SafeLoader — !!python/object YAML constructor
    3. marshal.loads() — bypasses Python import restrictions
    4. eval() used as a JSON/config parser
    5. shelve.open() with user-controlled path (pickle-backed)
    6. jsonpickle.decode() without restrictions
    7. Java ObjectInputStream on network/user input
    8. PHP unserialize() on user input
    9. Node.js eval() / vm.runInContext() for data parsing
    """

    def __init__(self):
        """Initialize the insecure deserialization detector."""
        super().__init__(name="InsecureDeserializationDetector", enabled=True)
        self.patterns: dict[str, list[Pattern]] = self._compile_patterns()

    def _compile_patterns(self) -> dict[str, list[Pattern]]:
        """Compile regex patterns for insecure deserialization detection."""
        return {
            # Python pickle — arbitrary RCE via __reduce__
            "pickle_loads": [
                re.compile(
                    r"pickle\.(loads?|Unpickler)\s*\(",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"cPickle\.(loads?|Unpickler)\s*\(",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"_pickle\.(loads?|Unpickler)\s*\(",
                    re.IGNORECASE,
                ),
            ],
            # YAML without safe loader — !!python/object RCE
            "unsafe_yaml": [
                re.compile(
                    r"yaml\.load\s*\(\s*(?!.*Loader\s*=\s*yaml\.(?:Safe|Base)Loader)",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"yaml\.load\s*\([^)]*\)\s*(?!.*SafeLoader)",
                    re.IGNORECASE,
                ),
                # explicit unsafe loaders
                re.compile(
                    r"yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.(?:Full|Unsafe)Loader",
                    re.IGNORECASE,
                ),
            ],
            # marshal.loads — bypasses import restrictions, faster RCE than pickle
            "marshal_loads": [
                re.compile(
                    r"marshal\.loads?\s*\(",
                    re.IGNORECASE,
                ),
            ],
            # eval() used to parse JSON, config, or serialized data
            "eval_deserialization": [
                re.compile(
                    r"eval\s*\(\s*(?!base64)",  # eval on non-base64 data (base64 caught by supply chain)
                    re.IGNORECASE,
                ),
                re.compile(
                    r"eval\s*\(\s*(?:request\.|req\.|body|data|payload|input|args|params|"
                    r"environ|os\.environ|sys\.stdin)",
                    re.IGNORECASE,
                ),
            ],
            # shelve — pickle-backed key/value store
            "shelve_open": [
                re.compile(
                    r"shelve\.open\s*\(",
                    re.IGNORECASE,
                ),
            ],
            # jsonpickle — deserializes arbitrary Python objects from JSON
            "jsonpickle": [
                re.compile(
                    r"jsonpickle\.decode\s*\(",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"jsonpickle\.unpickler\.decode\s*\(",
                    re.IGNORECASE,
                ),
            ],
            # Java ObjectInputStream — gadget chain RCE
            "java_object_stream": [
                re.compile(
                    r"new\s+ObjectInputStream\s*\(",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"ObjectInputStream\s+\w+\s*=\s*new\s+ObjectInputStream",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"\.readObject\s*\(\s*\)",
                    re.IGNORECASE,
                ),
                # XStream without security configuration
                re.compile(
                    r"new\s+XStream\s*\(\s*\)",
                    re.IGNORECASE,
                ),
            ],
            # PHP unserialize — arbitrary object injection / RCE via magic methods
            "php_unserialize": [
                re.compile(
                    r"\bunserialize\s*\(",
                    re.IGNORECASE,
                ),
            ],
            # Node.js eval / vm.runInContext used for data parsing
            "node_eval": [
                re.compile(
                    r"\beval\s*\(\s*(?:JSON\.stringify|body|data|payload|input|req\.|request\.)",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"vm\.runInContext\s*\(",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"vm\.runInNewContext\s*\(",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"vm\.runInThisContext\s*\(",
                    re.IGNORECASE,
                ),
            ],
        }

    def is_applicable(self, file_path: Path, file_type: Optional[str] = None) -> bool:
        """Apply to code files where deserialization can occur."""
        if file_type:
            return file_type in ["python", "javascript", "typescript", "java", "php"]

        return file_path.suffix.lower() in {
            ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".php",
        }

    def detect_sync(
        self, file_path: Path, content: str, file_type: Optional[str] = None
    ) -> list[Vulnerability]:
        """Detect insecure deserialization patterns in file content."""
        vulnerabilities: list[Vulnerability] = []
        lines = content.split("\n")

        is_php = file_path.suffix.lower() == ".php"

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            if not stripped or stripped.startswith(("#", "//", "*", "/*")):
                continue

            for category, patterns in self.patterns.items():
                # PHP unserialize only for PHP files
                if category == "php_unserialize" and not is_php:
                    continue

                # Java patterns only for .java files
                if category == "java_object_stream" and file_path.suffix.lower() != ".java":
                    continue

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

    _FP_WORDS = re.compile(
        r"\b(?:test|example|mock|fixture|stub|safe|trusted|internal)\b",
        re.IGNORECASE,
    )

    # yaml.load with safe loaders is fine
    _SAFE_YAML_LOADER = re.compile(
        r"Loader\s*=\s*yaml\.(?:Safe|Base)Loader",
        re.IGNORECASE,
    )

    # eval() on clear string literals is benign
    _EVAL_LITERAL = re.compile(
        r"eval\s*\(\s*['\"`]",
    )

    def _is_likely_false_positive(self, line: str, category: str) -> bool:
        """Suppress common false positives."""
        if self._FP_WORDS.search(line):
            return True

        if category == "unsafe_yaml":
            if self._SAFE_YAML_LOADER.search(line):
                return True

        if category in ("eval_deserialization", "node_eval"):
            # eval on string literals is usually benign (template evaluation)
            if self._EVAL_LITERAL.search(line):
                return True

        if category == "shelve_open":
            # shelve with hardcoded path is less risky than user-controlled
            if re.search(r"shelve\.open\s*\(\s*['\"]", line):
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
        """Create an insecure deserialization vulnerability object."""

        metadata_map = {
            "pickle_loads": {
                "title": "Insecure Deserialization: pickle.loads() on Untrusted Data",
                "description": (
                    f"Python pickle deserialization detected: '{matched_text[:120]}'. "
                    "pickle.loads() deserializes arbitrary Python objects including code. "
                    "A malicious pickle payload can execute arbitrary code via `__reduce__` "
                    "during deserialization — before any validation logic runs. In MCP servers, "
                    "if tool arguments, file contents, or cached data are pickled by an attacker, "
                    "this is a direct remote code execution vector."
                ),
                "severity": Severity.CRITICAL,
                "confidence": Confidence.MEDIUM,
                "cwe_id": "CWE-502",
                "cvss_score": 9.8,
                "remediation": (
                    "1. Never use pickle to deserialize data from untrusted sources\n"
                    "2. Use JSON, MessagePack, or Protocol Buffers for inter-process data\n"
                    "3. If pickle is required: use HMAC signing to verify the payload first\n"
                    "4. Consider `restrictedhash` or `SafeUnpickler` for controlled deserialization\n"
                    "5. Sandbox pickle operations in a separate process with no network/filesystem access"
                ),
                "mitre_attack_ids": ["T1059.006", "T1203"],
            },
            "unsafe_yaml": {
                "title": "Insecure Deserialization: yaml.load() Without Safe Loader",
                "description": (
                    f"YAML deserialization without a safe loader: '{matched_text[:120]}'. "
                    "PyYAML's default Loader supports `!!python/object` tags which instantiate "
                    "arbitrary Python objects during parsing. A crafted YAML payload can achieve "
                    "remote code execution: `!!python/object/apply:os.system ['id']`. "
                    "MCP servers that parse YAML tool configurations or user-supplied data "
                    "are vulnerable if the Loader is not restricted."
                ),
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-502",
                "cvss_score": 9.8,
                "remediation": (
                    "1. Always use `yaml.safe_load(data)` instead of `yaml.load(data)`\n"
                    "2. If `yaml.load()` is needed: pass `Loader=yaml.SafeLoader` explicitly\n"
                    "3. Audit all yaml.load() calls in the codebase\n"
                    "4. Use `ruamel.yaml` in safe mode as an alternative"
                ),
                "mitre_attack_ids": ["T1059.006", "T1203"],
            },
            "marshal_loads": {
                "title": "Insecure Deserialization: marshal.loads() on Untrusted Data",
                "description": (
                    f"Python marshal deserialization detected: '{matched_text[:120]}'. "
                    "marshal is Python's internal bytecode serialization format. "
                    "It can deserialize code objects, enabling arbitrary code execution "
                    "when combined with `exec()`. Unlike pickle, marshal bypasses many "
                    "sandboxing mechanisms and is not designed for untrusted input."
                ),
                "severity": Severity.CRITICAL,
                "confidence": Confidence.MEDIUM,
                "cwe_id": "CWE-502",
                "cvss_score": 9.8,
                "remediation": (
                    "1. Do not use marshal for anything other than CPython internal bytecode\n"
                    "2. Never deserialize marshal data from network or user input\n"
                    "3. Use JSON or Protocol Buffers for structured data exchange\n"
                    "4. If bytecode caching is needed: use Python's built-in .pyc mechanism with integrity checks"
                ),
                "mitre_attack_ids": ["T1059.006", "T1027"],
            },
            "eval_deserialization": {
                "title": "Insecure Deserialization: eval() Used for Data Parsing",
                "description": (
                    f"eval() is used to parse or deserialize data: '{matched_text[:120]}'. "
                    "Using eval() to parse JSON, configuration, or serialized data is equivalent "
                    "to executing arbitrary code. Any attacker-controlled input to eval() "
                    "results in remote code execution. This is distinct from obfuscated payload "
                    "execution (supply chain) — this is dynamic evaluation of data that should "
                    "use a proper parser."
                ),
                "severity": Severity.CRITICAL,
                "confidence": Confidence.MEDIUM,
                "cwe_id": "CWE-95",
                "cvss_score": 9.8,
                "remediation": (
                    "1. Replace eval(json_string) with json.loads(json_string)\n"
                    "2. Replace eval(config) with configparser or ast.literal_eval()\n"
                    "3. ast.literal_eval() safely parses Python literals (no code execution)\n"
                    "4. For structured data: use json, tomllib, yaml.safe_load, or protobuf"
                ),
                "mitre_attack_ids": ["T1059.006"],
            },
            "shelve_open": {
                "title": "Insecure Deserialization: shelve (Pickle-Backed Storage)",
                "description": (
                    f"shelve.open() is used with a potentially user-controlled path: "
                    f"'{matched_text[:120]}'. "
                    "Python's shelve module uses pickle for serialization. "
                    "If the database path is user-controlled, an attacker can point it to "
                    "a malicious pickle database. Even with a fixed path, the database file "
                    "itself could be replaced by an attacker with write access."
                ),
                "severity": Severity.HIGH,
                "confidence": Confidence.MEDIUM,
                "cwe_id": "CWE-502",
                "cvss_score": 8.1,
                "remediation": (
                    "1. Use SQLite (sqlite3) or a JSON file for key/value storage\n"
                    "2. If shelve is required: use only with hardcoded paths in trusted locations\n"
                    "3. Protect the shelve database file with filesystem permissions\n"
                    "4. Consider `dbm.dumb` with custom serialization for simple use cases"
                ),
                "mitre_attack_ids": ["T1059.006", "T1203"],
            },
            "jsonpickle": {
                "title": "Insecure Deserialization: jsonpickle.decode() Without Restrictions",
                "description": (
                    f"jsonpickle deserialization detected: '{matched_text[:120]}'. "
                    "jsonpickle stores Python class information in JSON and reconstructs "
                    "arbitrary objects on decode. An attacker can craft a jsonpickle payload "
                    "that instantiates dangerous classes (subprocess.Popen, os.system) during "
                    "decoding. This is effectively pickle-as-JSON."
                ),
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-502",
                "cvss_score": 9.8,
                "remediation": (
                    "1. Do not use jsonpickle.decode() on untrusted input\n"
                    "2. Use jsonpickle.decode(data, safe=True, classes=[AllowedClass]) to restrict\n"
                    "3. Prefer standard json.loads() for data exchange\n"
                    "4. If object reconstruction is needed: use pydantic with explicit schemas"
                ),
                "mitre_attack_ids": ["T1059.006", "T1203"],
            },
            "java_object_stream": {
                "title": "Insecure Deserialization: Java ObjectInputStream",
                "description": (
                    f"Java object deserialization detected: '{matched_text[:120]}'. "
                    "Java's ObjectInputStream.readObject() deserializes arbitrary Java objects. "
                    "Known gadget chains in common libraries (Commons Collections, Spring, "
                    "Hibernate) enable RCE on any JVM that processes attacker-controlled "
                    "serialized data. CVE-2015-4852, CVE-2016-4437, and hundreds of similar "
                    "CVEs exploit this pattern."
                ),
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-502",
                "cvss_score": 9.8,
                "remediation": (
                    "1. Use JSON (Jackson, Gson) or Protocol Buffers instead of Java serialization\n"
                    "2. If ObjectInputStream is required: use a deserialization filter (JEP 290)\n"
                    "3. Implement ObjectInputFilter to allowlist safe classes only\n"
                    "4. Consider SerialKiller or NotSoSerial Java agent as a defense-in-depth measure"
                ),
                "mitre_attack_ids": ["T1059.007", "T1203"],
            },
            "php_unserialize": {
                "title": "Insecure Deserialization: PHP unserialize() on Untrusted Input",
                "description": (
                    f"PHP unserialize() detected: '{matched_text[:120]}'. "
                    "PHP's unserialize() reconstructs arbitrary PHP objects. "
                    "If user input reaches unserialize(), magic method chains (__wakeup, "
                    "__destruct, __toString) in loaded classes can be exploited for RCE, "
                    "file writes, or SQL injection. This pattern is behind numerous CVEs "
                    "in WordPress plugins, Laravel, and Drupal."
                ),
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-502",
                "cvss_score": 9.8,
                "remediation": (
                    "1. Never pass user input to unserialize()\n"
                    "2. Use JSON (json_decode) for data exchange\n"
                    "3. If PHP serialization is needed: use HMAC-signed payloads\n"
                    "4. Set `allowed_classes` parameter: unserialize($data, ['allowed_classes' => false])"
                ),
                "mitre_attack_ids": ["T1059.005", "T1203"],
            },
            "node_eval": {
                "title": "Insecure Deserialization: Node.js eval()/vm for Data Parsing",
                "description": (
                    f"Node.js eval() or vm module used for data evaluation: "
                    f"'{matched_text[:120]}'. "
                    "eval() executes arbitrary JavaScript — any attacker-controlled data "
                    "reaching eval() is RCE. The vm module provides a sandbox but is not "
                    "a security boundary — breakout techniques are well documented. "
                    "JSON.parse() is the correct way to parse JSON in Node.js."
                ),
                "severity": Severity.CRITICAL,
                "confidence": Confidence.MEDIUM,
                "cwe_id": "CWE-95",
                "cvss_score": 9.8,
                "remediation": (
                    "1. Replace eval(json) with JSON.parse(json)\n"
                    "2. Do not use the vm module as a security sandbox — it is not one\n"
                    "3. Use vm.Script with timeouts only for trusted configuration scripts\n"
                    "4. For dynamic code execution: use a Worker thread with message passing"
                ),
                "mitre_attack_ids": ["T1059.007"],
            },
        }

        meta = metadata_map[category]

        return Vulnerability(
            type=VulnerabilityType.INSECURE_DESERIALIZATION,
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
                "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
                "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
                "https://portswigger.net/web-security/deserialization",
            ],
            detector=self.name,
            engine="static",
            mitre_attack_ids=meta["mitre_attack_ids"],
        )
