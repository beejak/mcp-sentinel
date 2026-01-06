"""
Test fixtures for code injection detection - Python examples.

Contains both vulnerable and safe code patterns for testing.
"""

# ============================================================================
# VULNERABLE PATTERNS - Should be detected
# ============================================================================

# 1. os.system() - Command Injection
import os

def vulnerable_os_system_1():
    user_input = input("Enter filename: ")
    os.system(f"cat {user_input}")  # VULNERABLE

def vulnerable_os_system_2():
    command = "ls -la " + get_user_path()
    os.system(command)  # VULNERABLE


# 2. subprocess.call() with shell=True
import subprocess

def vulnerable_subprocess_call():
    user_file = request.args.get('file')
    subprocess.call(f"cat {user_file}", shell=True)  # VULNERABLE

def vulnerable_subprocess_call_2():
    subprocess.call("rm -rf " + user_input, shell=True)  # VULNERABLE


# 3. subprocess.run() with shell=True
def vulnerable_subprocess_run():
    cmd = f"ping {hostname}"
    subprocess.run(cmd, shell=True)  # VULNERABLE

def vulnerable_subprocess_run_2():
    subprocess.run("echo " + user_data, shell=True)  # VULNERABLE


# 4. subprocess.Popen() with shell=True
def vulnerable_subprocess_popen():
    process = subprocess.Popen(
        f"grep {pattern} {filename}",
        shell=True,  # VULNERABLE
        stdout=subprocess.PIPE
    )

def vulnerable_subprocess_popen_2():
    subprocess.Popen("wget " + url, shell=True)  # VULNERABLE


# 5. eval() - Code Injection
def vulnerable_eval_1():
    user_code = request.form.get('expression')
    result = eval(user_code)  # VULNERABLE
    return result

def vulnerable_eval_2():
    math_expr = get_user_input()
    value = eval(math_expr)  # VULNERABLE


# 6. exec() - Code Injection
def vulnerable_exec_1():
    code = request.json.get('code')
    exec(code)  # VULNERABLE

def vulnerable_exec_2():
    script = load_from_database()
    exec(script)  # VULNERABLE


# ============================================================================
# SAFE PATTERNS - Should NOT be detected (or low confidence)
# ============================================================================

def safe_subprocess_no_shell():
    # Safe: shell=False with list arguments
    subprocess.run(['ls', '-la', directory])  # SAFE

def safe_subprocess_default():
    # Safe: shell defaults to False
    subprocess.call(['echo', 'hello'])  # SAFE

def safe_literal_eval():
    import ast
    # Safe: ast.literal_eval instead of eval
    data = ast.literal_eval(user_input)  # SAFE

def safe_json_loads():
    import json
    # Safe: json.loads instead of eval
    data = json.loads(user_input)  # SAFE

# Comments should be ignored
# os.system("this is just a comment")
# eval("this is documentation")
# subprocess.run("example", shell=True)  # This is commented out
