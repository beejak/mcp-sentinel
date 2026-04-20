"""
Weak Cryptography detector for MCP security.

Detects cryptographic weaknesses that undermine the security guarantees
of MCP servers handling sensitive data:
- Broken hash algorithms (MD5, SHA-1) used for security purposes
- Insecure random number generation (random module for secrets/tokens)
- Hardcoded cryptographic salts or initialization vectors
- ECB mode block cipher usage
- Insecure key derivation (weak iteration counts, no salt)
- Deprecated/broken symmetric ciphers (DES, RC4, Blowfish)

These weaknesses are particularly dangerous in MCP servers that handle
authentication tokens, session IDs, or encrypt user data.
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


class WeakCryptoDetector(BaseDetector):
    """
    Detector for weak cryptographic patterns in MCP server code.

    Detects:
    1. MD5/SHA-1 used for password hashing or security-sensitive digests
    2. random.random()/randint()/choice() used for tokens, secrets, or session IDs
    3. Hardcoded salts or initialization vectors (fixed byte strings)
    4. ECB mode cipher usage (no diffusion — identical blocks → identical ciphertext)
    5. Weak key derivation (PBKDF2/bcrypt with very low iteration counts)
    6. Deprecated ciphers: DES, RC4, Blowfish, ARC2, ARC4
    7. Static/predictable nonces or IVs set to zeros or constants
    """

    def __init__(self) -> None:
        """Initialize the weak crypto detector."""
        super().__init__(name="WeakCryptoDetector", enabled=True)
        self.patterns: dict[str, list[Pattern[str]]] = self._compile_patterns()

    def _compile_patterns(self) -> dict[str, list[Pattern[str]]]:
        """Compile regex patterns for weak crypto detection."""
        return {
            # MD5 / SHA-1 in security contexts (password, token, signature, auth)
            "broken_hash": [
                re.compile(
                    r"hashlib\.(md5|sha1)\s*\(",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"MD5\s*\(",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"MessageDigest\.getInstance\s*\(\s*['\"](?:MD5|SHA-1|SHA1)['\"]",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"crypto\.createHash\s*\(\s*['\"](?:md5|sha1)['\"]",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"Digest::(?:MD5|SHA1)\b",
                ),
            ],
            # Insecure random for security purposes
            "insecure_random": [
                re.compile(
                    r"random\.(random|randint|randrange|choice|choices|sample|uniform)\s*\(",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"Math\.random\s*\(\s*\)",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"std::rand\s*\(\s*\)",
                ),
                re.compile(
                    r"rand\(\s*\)\s*%",  # C-style rand() modulo
                ),
            ],
            # ECB mode — identical plaintext blocks → identical ciphertext
            "ecb_mode": [
                re.compile(
                    r"\.new\s*\([^)]*modes?\.ECB\b",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"AES\.new\s*\([^,)]+,\s*AES\.MODE_ECB\b",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"Cipher\.getInstance\s*\(\s*['\"](?:[A-Za-z0-9]+/ECB/[A-Za-z0-9]+|AES/ECB)['\"]",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"createCipheriv\s*\(\s*['\"][a-z0-9-]*-ecb['\"]",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"MODE_ECB\b",
                ),
            ],
            # Deprecated / broken symmetric ciphers
            "deprecated_cipher": [
                re.compile(
                    r"\bDES\.new\s*\(",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"Cipher\.getInstance\s*\(\s*['\"](?:DES|DESede|RC2|RC4|Blowfish|ARCFOUR)[/'\"]",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"(?:ARC4|ARC2|Blowfish|DES3?)\s*\.new\s*\(",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"createCipheriv\s*\(\s*['\"](?:des|des-ede|des3|rc4|bf|blowfish)",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"(?:RC4|Arcfour)\s*\(",
                    re.IGNORECASE,
                ),
            ],
            # Hardcoded / static IV or nonce (all-zeros, fixed bytes, string literals)
            "static_iv": [
                re.compile(
                    r"\biv\s*=\s*b?['\"][\x00-\xff]{8,}['\"]",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"\b(?:iv|nonce|salt)\s*=\s*(?:b'\\x00'|b\"\\x00\"|bytes\(\d+\)|b'\\0+\b)",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"\b(?:iv|nonce)\s*=\s*b?\s*['\"][0-9a-fA-F]{16,}['\"]",
                    re.IGNORECASE,
                ),
                # Hardcoded zeros — IV/nonce of all zeros
                re.compile(
                    r"\b(?:iv|nonce)\s*=\s*\\x00\s*\*\s*\d+",
                    re.IGNORECASE,
                ),
            ],
            # Weak key derivation — very low iteration count
            "weak_kdf": [
                re.compile(
                    r"pbkdf2_hmac\s*\([^)]*iterations\s*=\s*(?:[1-9]\d{0,3})\b",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"PBKDF2\s*\([^)]*,\s*(?:[1-9]\d{0,3})\s*[,)]",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"bcrypt\.hashpw\s*\([^)]*rounds\s*=\s*[1-9]\b",
                    re.IGNORECASE,
                ),
            ],
        }

    def is_applicable(self, file_path: Path, file_type: Optional[str] = None) -> bool:
        """Apply to code files where cryptographic operations occur."""
        if file_type:
            return file_type in ["python", "javascript", "typescript", "java", "go"]

        return file_path.suffix.lower() in {
            ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go",
        }

    def detect_sync(
        self, file_path: Path, content: str, file_type: Optional[str] = None
    ) -> list[Vulnerability]:
        """Detect weak cryptographic patterns in file content."""
        vulnerabilities: list[Vulnerability] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            if not stripped or stripped.startswith(("#", "//", "*", "/*")):
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

    _FP_WORDS = re.compile(
        r"\b(?:test|example|mock|fixture|stub)\b",
        re.IGNORECASE,
    )

    # MD5/SHA-1 are fine for non-security uses (checksums, ETags, cache keys)
    _CHECKSUM_CONTEXT = re.compile(
        r"(?:checksum|etag|cache_key|cache_bust|content_hash|file_hash|integrity|"
        r"fingerprint|dedup|idempotent|download|verify_file)",
        re.IGNORECASE,
    )

    def _is_likely_false_positive(self, line: str, category: str) -> bool:
        """Suppress common false positives."""
        if self._FP_WORDS.search(line):
            return True

        # MD5/SHA-1 for content addressing / checksums is acceptable
        if category == "broken_hash":
            if self._CHECKSUM_CONTEXT.search(line):
                return True

        # random module imports (not usage for security) — only flag actual calls
        if category == "insecure_random":
            stripped = line.strip()
            if stripped.startswith(("import random", "from random import")):
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
        """Create a weak crypto vulnerability object."""

        metadata_map = {
            "broken_hash": {
                "title": "Weak Crypto: Broken Hash Algorithm (MD5/SHA-1)",
                "description": (
                    f"MD5 or SHA-1 is used in a security-sensitive context: '{matched_text[:120]}'. "
                    "MD5 and SHA-1 are cryptographically broken — collision attacks are practical "
                    "(MD5: 2^18 operations; SHA-1: SHAttered attack 2017). Using these for password "
                    "hashing, token generation, or signature verification allows attackers to forge "
                    "values. In MCP servers, a forged token or session ID gives full account access."
                ),
                "severity": Severity.HIGH,
                "confidence": Confidence.MEDIUM,
                "cwe_id": "CWE-327",
                "cvss_score": 7.4,
                "remediation": (
                    "1. Replace MD5/SHA-1 with SHA-256 or SHA-3 for integrity checks\n"
                    "2. For password hashing: use bcrypt, scrypt, or Argon2id\n"
                    "3. For tokens/session IDs: use secrets.token_hex(32) or secrets.token_urlsafe()\n"
                    "4. For HMACs: use HMAC-SHA-256 or HMAC-SHA-3\n"
                    "5. If MD5 is used only for non-security checksums (cache keys, ETags), it is acceptable"
                ),
                "mitre_attack_ids": ["T1600", "T1212"],
            },
            "insecure_random": {
                "title": "Weak Crypto: Insecure Random Number Generator",
                "description": (
                    f"The insecure `random` module (or Math.random) is used in a security context: "
                    f"'{matched_text[:120]}'. "
                    "Python's `random` module uses the Mersenne Twister PRNG, which is not "
                    "cryptographically secure — its state can be recovered from 624 consecutive "
                    "outputs. Math.random() in JavaScript has similar weaknesses. "
                    "An attacker who can observe generated values can predict future tokens, "
                    "session IDs, or passwords."
                ),
                "severity": Severity.HIGH,
                "confidence": Confidence.MEDIUM,
                "cwe_id": "CWE-338",
                "cvss_score": 7.5,
                "remediation": (
                    "1. Use `secrets.token_hex(n)` or `secrets.token_urlsafe(n)` for tokens/IDs\n"
                    "2. Use `secrets.randbelow(n)` instead of random.randint(0, n)\n"
                    "3. Use `os.urandom(n)` for raw random bytes\n"
                    "4. In Node.js: use `crypto.randomBytes()` or `crypto.randomUUID()`\n"
                    "5. Never seed random with time-based values (datetime.now(), Date.now())"
                ),
                "mitre_attack_ids": ["T1600"],
            },
            "ecb_mode": {
                "title": "Weak Crypto: ECB Mode Block Cipher",
                "description": (
                    f"ECB (Electronic Codebook) mode is used for block cipher encryption: "
                    f"'{matched_text[:120]}'. "
                    "ECB mode encrypts each block independently — identical plaintext blocks "
                    "produce identical ciphertext blocks. This leaks data structure and enables "
                    "pattern analysis attacks. The 'ECB penguin' demonstrates this: an ECB-encrypted "
                    "image of a penguin retains the penguin's visible shape in the ciphertext."
                ),
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-327",
                "cvss_score": 7.4,
                "remediation": (
                    "1. Use AES-GCM (authenticated encryption) instead of AES-ECB\n"
                    "2. If confidentiality only: use AES-CBC or AES-CTR with a random IV\n"
                    "3. Never reuse an IV with the same key in CBC/CTR modes\n"
                    "4. Prefer AES-GCM — it provides both confidentiality and integrity"
                ),
                "mitre_attack_ids": ["T1600"],
            },
            "deprecated_cipher": {
                "title": "Weak Crypto: Deprecated/Broken Cipher Algorithm",
                "description": (
                    f"A deprecated or broken cipher algorithm is used: '{matched_text[:120]}'. "
                    "DES has a 56-bit key (breakable in hours with modern hardware). "
                    "RC4 has multiple statistical biases and is banned by RFC 7465 for TLS. "
                    "Blowfish/ARC2 have small block sizes (64-bit) that enable birthday attacks "
                    "after ~32GB of data. These ciphers should not be used in new code."
                ),
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-327",
                "cvss_score": 7.4,
                "remediation": (
                    "1. Replace DES/3DES with AES-256\n"
                    "2. Replace RC4 with ChaCha20-Poly1305 or AES-GCM\n"
                    "3. Replace Blowfish with AES-256-GCM\n"
                    "4. Use cryptography library's high-level Fernet for symmetric encryption"
                ),
                "mitre_attack_ids": ["T1600"],
            },
            "static_iv": {
                "title": "Weak Crypto: Hardcoded or Static IV/Nonce",
                "description": (
                    f"A hardcoded or static initialization vector (IV) or nonce is used: "
                    f"'{matched_text[:120]}'. "
                    "Reusing an IV with the same key breaks the security of CBC mode (enables "
                    "IV oracle attacks) and completely breaks CTR and GCM modes (nonce reuse "
                    "in GCM leaks the authentication key). A static zero IV is equivalent to "
                    "no IV — the encryption becomes deterministic and attackable."
                ),
                "severity": Severity.HIGH,
                "confidence": Confidence.MEDIUM,
                "cwe_id": "CWE-329",
                "cvss_score": 7.5,
                "remediation": (
                    "1. Generate a fresh random IV for every encryption operation: "
                    "`iv = os.urandom(16)`\n"
                    "2. Prepend the IV to the ciphertext so it can be used for decryption\n"
                    "3. Never hardcode an IV or derive it from a static value\n"
                    "4. For GCM: use a 96-bit (12-byte) nonce, never reuse with the same key\n"
                    "5. Use AES-GCM via `cryptography.hazmat.primitives.ciphers.aead.AESGCM`"
                ),
                "mitre_attack_ids": ["T1600"],
            },
            "weak_kdf": {
                "title": "Weak Crypto: Insufficient Key Derivation Iterations",
                "description": (
                    f"A key derivation function is used with too few iterations: "
                    f"'{matched_text[:120]}'. "
                    "Low iteration counts make offline brute-force attacks fast. OWASP recommends "
                    "PBKDF2-HMAC-SHA256 with ≥600,000 iterations (2023), bcrypt with cost ≥12, "
                    "and Argon2id with ≥2 passes and 64MB memory. Fewer iterations than these "
                    "thresholds allow GPU-accelerated cracking."
                ),
                "severity": Severity.MEDIUM,
                "confidence": Confidence.HIGH,
                "cwe_id": "CWE-916",
                "cvss_score": 6.5,
                "remediation": (
                    "1. PBKDF2-HMAC-SHA256: use ≥600,000 iterations (OWASP 2023)\n"
                    "2. bcrypt: use cost factor ≥12 (adjust up as hardware improves)\n"
                    "3. Prefer Argon2id over PBKDF2 and bcrypt for new implementations\n"
                    "4. Use `passlib` or `cryptography` library wrappers for correct defaults"
                ),
                "mitre_attack_ids": ["T1110.002"],
            },
        }

        meta = metadata_map[category]

        return Vulnerability(
            type=VulnerabilityType.WEAK_CRYPTO,
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
                "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
                "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf",
            ],
            detector=self.name,
            engine="static",
            mitre_attack_ids=meta["mitre_attack_ids"],
        )
