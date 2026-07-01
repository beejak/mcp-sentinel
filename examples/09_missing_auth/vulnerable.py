"""
Vulnerable: Missing authentication on sensitive routes — MISSING_AUTH

Run: mcp-sentinel scan examples/09_missing_auth/vulnerable.py
Expected: HIGH MISSING_AUTH findings
"""
from flask import Flask, request, jsonify

app = Flask(__name__)

# Simulated database
users = {"alice": {"role": "admin", "email": "alice@example.com"}}

@app.route("/admin/users")
def list_all_users():
    """List all users — VULNERABLE: no authentication check."""
    return jsonify(list(users.values()))

@app.route("/admin/delete_user", methods=["DELETE"])
def delete_user():
    """Delete a user — VULNERABLE: anyone can delete any user."""
    user_id = request.args.get("id")
    users.pop(user_id, None)
    return jsonify({"deleted": user_id})

@app.route("/admin/export_database")
def export_database():
    """Export entire database — VULNERABLE: no auth, no logging."""
    return jsonify(users)

@app.route("/internal/debug")
def debug_info():
    """Debug endpoint — VULNERABLE: exposes internals with no auth."""
    import os, sys
    return jsonify({
        "env": dict(os.environ),
        "python": sys.version,
        "cwd": os.getcwd(),
    })
