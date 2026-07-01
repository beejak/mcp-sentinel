"""
Safe: JWT authentication required on all sensitive routes.
"""
import os, functools
from flask import Flask, request, jsonify, abort
import jwt

app = Flask(__name__)
JWT_SECRET = os.environ["JWT_SECRET"]
users = {}

def require_auth(role: str = "user"):
    """Decorator: validates Bearer JWT and checks role."""
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                abort(401)
            token = auth[7:]
            try:
                payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            except jwt.InvalidTokenError:
                abort(401)
            if role == "admin" and payload.get("role") != "admin":
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator

@app.route("/admin/users")
@require_auth(role="admin")
def list_all_users():
    """List users — admin JWT required."""
    return jsonify(list(users.values()))

@app.route("/admin/delete_user", methods=["DELETE"])
@require_auth(role="admin")
def delete_user():
    """Delete user — admin JWT required."""
    user_id = request.args.get("id")
    users.pop(user_id, None)
    return jsonify({"deleted": user_id})
