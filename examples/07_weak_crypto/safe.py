"""
Safe: bcrypt for passwords, secrets module for tokens, AES-GCM for encryption.
"""
import secrets
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Safe Server")

def hash_password(password: str) -> str:
    # SAFE: bcrypt with cost factor — slow by design, salt included
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

def verify_password(password: str, hashed: str) -> bool:
    import bcrypt
    return bcrypt.checkpw(password.encode(), hashed.encode())

def generate_session_token() -> str:
    # SAFE: secrets.token_urlsafe uses os.urandom — cryptographically secure
    return secrets.token_urlsafe(32)

@mcp.tool()
def store_user(username: str, password: str) -> str:
    """Store a user — uses bcrypt and cryptographically secure token."""
    token = generate_session_token()
    hashed = hash_password(password)
    return f"stored user {username} securely"
