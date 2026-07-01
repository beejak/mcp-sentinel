"""
Vulnerable: Weak cryptography — WEAK_CRYPTO

Run: mcp-sentinel scan examples/07_weak_crypto/vulnerable.py
Expected: HIGH WEAK_CRYPTO findings
"""
import hashlib, random, string
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Vulnerable Server")

def hash_password(password: str) -> str:
    # VULNERABLE: MD5 is broken — collisions found, rainbow tables exist
    return hashlib.md5(password.encode()).hexdigest()

def generate_session_token() -> str:
    # VULNERABLE: random is not cryptographically secure (predictable seed)
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(32))

def encrypt_data(data: str, key: str) -> bytes:
    # VULNERABLE: ECB mode — identical plaintext blocks produce identical ciphertext
    from Crypto.Cipher import AES
    cipher = AES.new(key.encode()[:16], AES.MODE_ECB)
    padded = data + " " * (16 - len(data) % 16)
    return cipher.encrypt(padded.encode())

@mcp.tool()
def store_user(username: str, password: str) -> str:
    """Store a user — hashes password with broken MD5."""
    token = generate_session_token()
    hashed = hash_password(password)
    return f"stored user {username}, hash={hashed}, token={token}"
