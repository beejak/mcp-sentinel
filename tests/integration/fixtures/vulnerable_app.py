
import os
import subprocess
from flask import Flask, request

app = Flask(__name__)

# Hardcoded secret (should be detected by static/regex)
AWS_ACCESS_KEY = "AKIA1234567890ABCDEF"

@app.route("/run")
def run_command():
    # Command injection (should be detected by SAST/AI)
    cmd = request.args.get("cmd")
    subprocess.run(f"echo {cmd}", shell=True)
    return "Executed"

@app.route("/sql")
def sql_query():
    # SQL injection (should be detected by SAST/AI)
    user_id = request.args.get("id")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

if __name__ == "__main__":
    app.run(debug=True)
