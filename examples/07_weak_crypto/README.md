# Weak Cryptography

## What Is This? (Plain English)

Imagine locking your house with a padlock that anyone can open with a paperclip because the design is 30 years old and the flaws are published in every locksmith magazine. That's what happens when you use MD5 or SHA1 to "protect" passwords: these algorithms were broken years ago, and databases of pre-computed MD5 hashes for billions of common passwords (rainbow tables) are freely available online. Similarly, using Python's `random` module — which is designed for simulations, not security — to generate login tokens is like using a "random" number that can be predicted from a few observations.

## What Does the Attack Look Like?

```python
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()  # broken

def generate_token() -> str:
    return str(random.randint(100000, 999999))  # only 900,000 options
```

If an attacker obtains your user database, they look up MD5 hashes in rainbow tables and recover most passwords instantly. If they intercept a few of your 6-digit reset tokens, they can predict future tokens (Mersenne Twister's state is fully recoverable after 624 observations). A 6-digit token has only 900,000 possibilities — brute-forceable in under a minute at typical rate-limit thresholds.

## The Technical Detail

MD5 and SHA1 are fast general-purpose hash functions — fast is the enemy of password security, because it means an attacker can hash billions of guesses per second on a GPU. bcrypt, scrypt, and argon2 are purpose-built password hashing functions with configurable computational cost. Python's `random` module uses the Mersenne Twister PRNG, which is not cryptographically secure: its full state can be recovered after observing 624 32-bit outputs, allowing an attacker to predict all future outputs. The `secrets` module uses the OS CSPRNG, which is seeded from hardware entropy and cannot be predicted.

## Vulnerable Code

See [`vulnerable.py`](vulnerable.py)

## Safe Code

See [`safe.py`](safe.py)

## How MCP Sentinel Detects This

The `WeakCryptoDetector` matches `hashlib.md5(`, `hashlib.sha1(`, `random.randint(`, `random.choice(`, `DES.new(`, and ECB mode usage, emitting a `WEAK_CRYPTO` finding with `HIGH` severity.

## Official References

- **OWASP**: [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) and [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- **NIST / NVD**: [NIST SP 800-132 Password-Based Key Derivation](https://csrc.nist.gov/publications/detail/sp/800-132/final)
- **CISA**: [CISA — Using Passwords to Protect Data](https://www.cisa.gov/secure-our-world/use-strong-passwords)
- **CWE**: [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html) and [CWE-338: Use of Cryptographically Weak PRNG](https://cwe.mitre.org/data/definitions/338.html)
