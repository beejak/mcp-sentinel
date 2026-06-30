"""
OAuth vulnerability fixtures — CVE-pattern code that SHOULD be detected.

Based on CVE-2025-6514 class (mcp-remote OAuth RCE) and OWASP OAuth Security
Best Practices violations. Each function represents a real attack vector.
"""

# =============================================================================
# VULNERABLE PATTERNS — all of these should be detected
# =============================================================================

# ---- Open redirect via unvalidated redirect_uri (CVE-2025-6514 class) ----
from flask import request, redirect


def vulnerable_open_redirect_flask():
    redirect_uri = request.args.get("redirect_uri")  # VULNERABLE: user-controlled
    return redirect(f"https://auth.example.com/oauth?redirect_uri={redirect_uri}")


def vulnerable_open_redirect_params():
    callback = request.params.get("callback")  # VULNERABLE: user-controlled callback
    return start_oauth_flow(callback_url=callback)


# ---- Token written to logs ----
import logging

logger = logging.getLogger(__name__)


def vulnerable_token_logged():
    access_token = exchange_code_for_token(code)
    logger.info(f"Got access_token: {access_token}")  # VULNERABLE: token in logs
    return access_token


def vulnerable_token_debug_logged():
    token = fetch_oauth_token()
    logging.debug("oauth_token=" + token)  # VULNERABLE
    store_token(token)


def vulnerable_token_printed():
    access_token = get_access_token()
    print(f"access_token={access_token}")  # VULNERABLE: token to stdout
    return access_token


# ---- Hardcoded client_secret ----
CLIENT_SECRET = "s3cr3t-oauth-key-abc123"  # VULNERABLE: hardcoded secret

OAUTH_CONFIG = {
    "client_id": "my-mcp-app",
    "client_secret": "hardcoded-secret-xyz789",  # VULNERABLE
    "redirect_uri": "https://app.example.com/callback",
}


def get_token_vulnerable():
    return requests.post(
        TOKEN_URL,
        data={
            "client_secret": "abc123secretkey",  # VULNERABLE
            "grant_type": "authorization_code",
            "code": code,
        },
    )


# ---- Deprecated implicit grant ----
def build_implicit_auth_url():
    # VULNERABLE: response_type=token is deprecated (OAuth 2.1)
    return f"https://auth.example.com/authorize?response_type=token&client_id={client_id}"


IMPLICIT_PARAMS = {
    "response_type": "token",  # VULNERABLE
    "client_id": CLIENT_ID,
    "scope": "read write",
}


# ---- Token in browser localStorage (JavaScript-style, referenced in Python template) ----
VULNERABLE_JS_SNIPPET = """
localStorage.setItem('access_token', response.token);  // VULNERABLE
sessionStorage.setItem('auth_token', token);            // VULNERABLE
"""


# ---- Missing JWT verification ----
import jwt


def vulnerable_jwt_no_verify():
    payload = jwt.decode(token, options={"verify_signature": False})  # VULNERABLE
    return payload


def vulnerable_jwt_verify_false():
    data = jwt.decode(token, verify=False)  # VULNERABLE
    return data["user_id"]


def vulnerable_jwt_algorithm_none():
    decoded = jwt.decode(token, algorithms=["none"])  # VULNERABLE
    return decoded


# ---- Authorization code flow without PKCE (flagged for review) ----
def build_auth_url_no_pkce():
    params = {
        "response_type": "code",  # FLAGGED: verify PKCE is present
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        # Missing: code_challenge, code_challenge_method
    }
    return AUTH_URL + "?" + urlencode(params)


def exchange_code_no_pkce():
    return requests.post(
        TOKEN_URL,
        data={
            "grant_type": "authorization_code",  # FLAGGED: verify PKCE
            "code": code,
            "client_id": CLIENT_ID,
        },
    )


# =============================================================================
# SAFE PATTERNS — these should NOT trigger findings
# =============================================================================


def safe_redirect_uri_allowlist():
    ALLOWED_URIS = {"https://app.example.com/callback", "https://staging.example.com/callback"}
    redirect_uri = request.args.get("redirect_uri")
    if redirect_uri not in ALLOWED_URIS:
        return error("Invalid redirect_uri"), 400
    return start_oauth_flow(redirect_uri=redirect_uri)


def safe_token_redacted_log():
    access_token = get_access_token()
    logger.info("Token acquired: ***%s", access_token[-4:])  # SAFE: masked


def safe_secret_from_env():
    import os
    client_secret = os.environ["CLIENT_SECRET"]  # SAFE: from environment
    return client_secret


def safe_jwt_with_verification():
    payload = jwt.decode(
        token,
        key=PUBLIC_KEY,
        algorithms=["RS256"],
        audience="mcp-app",
        issuer="https://auth.example.com",
    )
    return payload


def safe_pkce_auth_flow():
    import secrets
    import hashlib
    import base64

    code_verifier = secrets.token_urlsafe(96)
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "redirect_uri": REDIRECT_URI,
    }
    return AUTH_URL + "?" + urlencode(params)
