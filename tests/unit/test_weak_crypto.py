"""
Unit tests for WeakCryptoDetector.

Covers:
- Broken hash algorithms (MD5, SHA-1)
- Insecure random number generation
- ECB mode cipher usage
- Deprecated/broken ciphers (DES, RC4, Blowfish)
- Hardcoded/static IV or nonce
- Weak key derivation iteration counts
- False-positive suppression
- Applicability / file type filtering
- Detector metadata
"""

import pytest
from pathlib import Path

from mcp_sentinel.detectors.weak_crypto import WeakCryptoDetector
from mcp_sentinel.models.vulnerability import Severity


@pytest.fixture
def detector():
    return WeakCryptoDetector()


# ---------------------------------------------------------------------------
# Detector metadata
# ---------------------------------------------------------------------------

def test_detector_name(detector):
    assert detector.name == "WeakCryptoDetector"


def test_detector_enabled_by_default(detector):
    assert detector.enabled is True


# ---------------------------------------------------------------------------
# is_applicable
# ---------------------------------------------------------------------------

def test_applicable_python(detector):
    assert detector.is_applicable(Path("server.py")) is True


def test_applicable_javascript(detector):
    assert detector.is_applicable(Path("auth.js")) is True


def test_applicable_typescript(detector):
    assert detector.is_applicable(Path("crypto.ts")) is True


def test_applicable_java(detector):
    assert detector.is_applicable(Path("Auth.java")) is True


def test_applicable_go(detector):
    assert detector.is_applicable(Path("hash.go")) is True


def test_not_applicable_yaml(detector):
    assert detector.is_applicable(Path("config.yaml")) is False


def test_not_applicable_markdown(detector):
    assert detector.is_applicable(Path("README.md")) is False


def test_not_applicable_json(detector):
    assert detector.is_applicable(Path("package.json")) is False


# ---------------------------------------------------------------------------
# Broken hash — MD5 / SHA-1
# ---------------------------------------------------------------------------

async def test_detect_hashlib_md5(detector):
    content = "digest = hashlib.md5(data).hexdigest()"
    vulns = await detector.detect(Path("auth.py"), content)
    assert len(vulns) >= 1
    assert any("MD5" in v.title or "SHA-1" in v.title for v in vulns)


async def test_detect_hashlib_sha1(detector):
    content = "token = hashlib.sha1(secret).digest()"
    vulns = await detector.detect(Path("tokens.py"), content)
    assert len(vulns) >= 1


async def test_detect_crypto_create_hash_md5(detector):
    content = "const hash = crypto.createHash('md5').update(data).digest('hex')"
    vulns = await detector.detect(Path("auth.js"), content)
    assert len(vulns) >= 1


async def test_detect_crypto_create_hash_sha1(detector):
    content = "const sig = crypto.createHash('sha1').update(payload).digest()"
    vulns = await detector.detect(Path("sign.js"), content)
    assert len(vulns) >= 1


async def test_detect_java_message_digest_md5(detector):
    content = 'MessageDigest md = MessageDigest.getInstance("MD5");'
    vulns = await detector.detect(Path("Hash.java"), content)
    assert len(vulns) >= 1


async def test_detect_java_message_digest_sha1(detector):
    content = 'MessageDigest md = MessageDigest.getInstance("SHA-1");'
    vulns = await detector.detect(Path("Hash.java"), content)
    assert len(vulns) >= 1


async def test_broken_hash_severity_is_high(detector):
    content = "hashlib.md5(password).hexdigest()"
    vulns = await detector.detect(Path("auth.py"), content)
    hashes = [v for v in vulns if "Hash" in v.title]
    assert all(v.severity.value == "high" for v in hashes)


async def test_no_false_positive_md5_for_checksum(detector):
    # MD5 used as a file checksum (non-security use) should be suppressed
    content = "checksum = hashlib.md5(file_data).hexdigest()"
    vulns = await detector.detect(Path("utils.py"), content)
    hash_vulns = [v for v in vulns if "Hash" in v.title]
    assert len(hash_vulns) == 0


async def test_no_false_positive_md5_for_etag(detector):
    content = "etag = hashlib.md5(content).hexdigest()"
    vulns = await detector.detect(Path("cache.py"), content)
    hash_vulns = [v for v in vulns if "Hash" in v.title]
    assert len(hash_vulns) == 0


# ---------------------------------------------------------------------------
# Insecure random
# ---------------------------------------------------------------------------

async def test_detect_random_random(detector):
    content = "token = random.random()"
    vulns = await detector.detect(Path("tokens.py"), content)
    assert len(vulns) >= 1
    assert any("Random" in v.title for v in vulns)


async def test_detect_random_randint(detector):
    content = "session_id = str(random.randint(0, 2**32))"
    vulns = await detector.detect(Path("session.py"), content)
    assert len(vulns) >= 1


async def test_detect_random_choice_token(detector):
    content = "key = random.choice(alphabet)"
    vulns = await detector.detect(Path("keygen.py"), content)
    assert len(vulns) >= 1


async def test_detect_math_random_js(detector):
    content = "const token = Math.random().toString(36)"
    vulns = await detector.detect(Path("auth.js"), content)
    assert len(vulns) >= 1


async def test_insecure_random_severity_is_high(detector):
    content = "session_id = str(random.randint(0, 9999999))"
    vulns = await detector.detect(Path("session.py"), content)
    rand_vulns = [v for v in vulns if "Random" in v.title]
    assert all(v.severity.value == "high" for v in rand_vulns)


async def test_no_false_positive_import_random(detector):
    # Import statement alone should not be flagged
    content = "import random"
    vulns = await detector.detect(Path("server.py"), content)
    rand_vulns = [v for v in vulns if "Random" in v.title]
    assert len(rand_vulns) == 0


# ---------------------------------------------------------------------------
# ECB mode
# ---------------------------------------------------------------------------

async def test_detect_aes_mode_ecb(detector):
    content = "cipher = AES.new(key, AES.MODE_ECB)"
    vulns = await detector.detect(Path("crypto.py"), content)
    assert len(vulns) >= 1
    assert any("ECB" in v.title for v in vulns)


async def test_detect_mode_ecb_constant(detector):
    content = "cipher = Cipher.getInstance('AES/ECB/PKCS5Padding')"
    vulns = await detector.detect(Path("Cipher.java"), content)
    assert len(vulns) >= 1


async def test_detect_createcipheriv_ecb(detector):
    content = "const cipher = crypto.createCipheriv('aes-256-ecb', key, null)"
    vulns = await detector.detect(Path("crypto.js"), content)
    assert len(vulns) >= 1


async def test_ecb_severity_is_high(detector):
    content = "cipher = AES.new(key, AES.MODE_ECB)"
    vulns = await detector.detect(Path("crypto.py"), content)
    ecb_vulns = [v for v in vulns if "ECB" in v.title]
    assert all(v.severity.value == "high" for v in ecb_vulns)


# ---------------------------------------------------------------------------
# Deprecated ciphers
# ---------------------------------------------------------------------------

async def test_detect_des_new(detector):
    content = "cipher = DES.new(key)"
    vulns = await detector.detect(Path("legacy.py"), content)
    assert len(vulns) >= 1
    assert any("Cipher" in v.title or "Deprecated" in v.title for v in vulns)


async def test_detect_rc4(detector):
    content = "cipher = ARC4.new(key)"
    vulns = await detector.detect(Path("legacy.py"), content)
    assert len(vulns) >= 1


async def test_detect_java_des(detector):
    content = 'Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");'
    vulns = await detector.detect(Path("Legacy.java"), content)
    assert len(vulns) >= 1


async def test_detect_createcipheriv_rc4(detector):
    content = "const cipher = crypto.createCipheriv('rc4', key, '')"
    vulns = await detector.detect(Path("crypto.js"), content)
    assert len(vulns) >= 1


async def test_deprecated_cipher_severity_is_high(detector):
    content = "cipher = DES.new(key)"
    vulns = await detector.detect(Path("legacy.py"), content)
    cipher_vulns = [v for v in vulns if "Deprecated" in v.title or "Cipher" in v.title]
    assert all(v.severity.value == "high" for v in cipher_vulns)


# ---------------------------------------------------------------------------
# Static / hardcoded IV
# ---------------------------------------------------------------------------

async def test_detect_static_iv_zeros(detector):
    content = r"iv = b'\x00' * 16"
    vulns = await detector.detect(Path("crypto.py"), content)
    assert len(vulns) >= 1
    assert any("IV" in v.title or "Nonce" in v.title for v in vulns)


async def test_detect_hardcoded_iv_hex_string(detector):
    content = "iv = b'0000000000000000'"
    vulns = await detector.detect(Path("crypto.py"), content)
    assert len(vulns) >= 1


# ---------------------------------------------------------------------------
# Weak KDF
# ---------------------------------------------------------------------------

async def test_detect_pbkdf2_low_iterations(detector):
    content = "key = hashlib.pbkdf2_hmac('sha256', password, salt, iterations=1000)"
    vulns = await detector.detect(Path("auth.py"), content)
    assert len(vulns) >= 1
    assert any("KDF" in v.title or "Iteration" in v.title for v in vulns)


async def test_weak_kdf_severity_is_medium(detector):
    content = "key = hashlib.pbkdf2_hmac('sha256', password, salt, iterations=100)"
    vulns = await detector.detect(Path("auth.py"), content)
    kdf_vulns = [v for v in vulns if "KDF" in v.title or "Iteration" in v.title]
    assert all(v.severity.value == "medium" for v in kdf_vulns)


# ---------------------------------------------------------------------------
# General false-positive suppression
# ---------------------------------------------------------------------------

async def test_no_false_positive_comment_line(detector):
    content = "# cipher = AES.new(key, AES.MODE_ECB)"
    vulns = await detector.detect(Path("crypto.py"), content)
    assert len(vulns) == 0


async def test_no_false_positive_test_word(detector):
    # Standalone word "test" in context suppresses the finding
    content = "cipher = AES.new(test, AES.MODE_ECB)"
    vulns = await detector.detect(Path("crypto.py"), content)
    assert len(vulns) == 0


async def test_empty_file(detector):
    vulns = await detector.detect(Path("crypto.py"), "")
    assert vulns == []


# ---------------------------------------------------------------------------
# Vulnerability metadata quality
# ---------------------------------------------------------------------------

async def test_vulnerability_has_cwe(detector):
    content = "hashlib.md5(password).hexdigest()"
    vulns = await detector.detect(Path("auth.py"), content)
    assert all(v.cwe_id is not None for v in vulns)


async def test_vulnerability_has_remediation(detector):
    content = "hashlib.md5(password).hexdigest()"
    vulns = await detector.detect(Path("auth.py"), content)
    assert all(v.remediation for v in vulns)


async def test_vulnerability_has_references(detector):
    content = "hashlib.md5(password).hexdigest()"
    vulns = await detector.detect(Path("auth.py"), content)
    assert all(len(v.references) > 0 for v in vulns)


async def test_vulnerability_detector_field(detector):
    content = "hashlib.md5(data).hexdigest()"
    vulns = await detector.detect(Path("auth.py"), content)
    assert all(v.detector == "WeakCryptoDetector" for v in vulns)


async def test_vulnerability_engine_field(detector):
    content = "hashlib.md5(data).hexdigest()"
    vulns = await detector.detect(Path("auth.py"), content)
    assert all(v.engine == "static" for v in vulns)


async def test_line_number_accuracy(detector):
    content = "import hashlib\nimport os\nhashlib.md5(data).hexdigest()\n"
    vulns = await detector.detect(Path("auth.py"), content)
    assert any(v.line_number == 3 for v in vulns)


async def test_code_snippet_captured(detector):
    content = "hashlib.sha1(secret_key).hexdigest()"
    vulns = await detector.detect(Path("auth.py"), content)
    assert any("sha1" in v.code_snippet.lower() for v in vulns)


# ============================================================================
# Edge Case / Variant Coverage
# ============================================================================


async def test_detect_random_randrange(detector):
    """random.randrange() — same insecure Mersenne Twister PRNG."""
    content = "session_id = random.randrange(1000000)"
    vulns = await detector.detect(Path("auth.py"), content)
    assert len(vulns) >= 1
    assert vulns[0].severity == Severity.HIGH


async def test_detect_random_uniform(detector):
    """random.uniform() for security use is insecure."""
    content = "token = random.uniform(0, 1)"
    vulns = await detector.detect(Path("auth.py"), content)
    assert len(vulns) >= 1


async def test_detect_random_choices(detector):
    """random.choices() used for password generation is insecure."""
    content = "password = ''.join(random.choices(string.ascii_letters, k=16))"
    vulns = await detector.detect(Path("auth.py"), content)
    assert len(vulns) >= 1


async def test_detect_random_sample(detector):
    """random.sample() is not cryptographically secure."""
    content = "token_chars = random.sample(ALPHABET, 32)"
    vulns = await detector.detect(Path("auth.py"), content)
    assert len(vulns) >= 1


async def test_detect_blowfish_new(detector):
    """Blowfish.new() — 64-bit block size enables birthday attacks."""
    content = "cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)"
    vulns = await detector.detect(Path("crypto.py"), content)
    assert len(vulns) >= 1
    assert vulns[0].severity == Severity.HIGH


async def test_detect_des3_new(detector):
    """DES3.new() (Triple DES) — deprecated per NIST SP 800-131A."""
    content = "cipher = DES3.new(key, DES3.MODE_CBC)"
    vulns = await detector.detect(Path("crypto.py"), content)
    assert len(vulns) >= 1
    assert vulns[0].severity == Severity.HIGH


async def test_detect_createcipheriv_des(detector):
    """Node.js createCipheriv with 'des' should be flagged."""
    content = "const cipher = crypto.createCipheriv('des', key, iv);"
    vulns = await detector.detect(Path("crypto.js"), content)
    assert len(vulns) >= 1
    assert vulns[0].severity == Severity.HIGH


async def test_detect_createcipheriv_blowfish(detector):
    """Node.js createCipheriv with blowfish ('bf-cbc') should be flagged."""
    content = "const enc = crypto.createCipheriv('bf-cbc', key, iv);"
    vulns = await detector.detect(Path("crypto.js"), content)
    assert len(vulns) >= 1


async def test_detect_bcrypt_low_rounds(detector):
    """bcrypt with rounds=4 is too weak — below recommended cost factor 12."""
    content = "hashed = bcrypt.hashpw(password, bcrypt.gensalt(rounds=4))"
    vulns = await detector.detect(Path("auth.py"), content)
    assert len(vulns) >= 1
    assert vulns[0].severity == Severity.MEDIUM


async def test_multiple_weaknesses_same_file(detector):
    """Multiple weak crypto patterns in one file all detected independently."""
    content = (
        "h = hashlib.md5(password)\n"
        "token = random.randint(0, 999999)\n"
        "cipher = AES.new(key, AES.MODE_ECB)\n"
    )
    vulns = await detector.detect(Path("bad_crypto.py"), content)
    assert len(vulns) >= 3


async def test_not_applicable_php(detector):
    """.php files are excluded — no PHP crypto patterns covered."""
    assert not detector.is_applicable(Path("server.php"))


async def test_not_applicable_ruby(detector):
    """.rb files are excluded."""
    assert not detector.is_applicable(Path("server.rb"))
