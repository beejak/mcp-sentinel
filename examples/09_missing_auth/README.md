# Missing Authentication

## What Is This? (Plain English)

Imagine a bank where anyone can walk up to the vault door, knock, and the teller opens it — no ID, no PIN, no questions. Missing authentication means your admin endpoints, user data, and destructive operations are fully accessible to anyone who knows (or guesses) the URL. This is one of the most common real-world breaches: attackers scan for `/admin`, `/debug`, `/api/users` and simply call them.

## What Does the Attack Look Like?

```bash
# No credentials needed — any attacker can do this
curl http://your-mcp-server/admin/export_database
curl -X DELETE "http://your-mcp-server/admin/delete_user?id=alice"
curl http://your-mcp-server/internal/debug  # returns AWS keys from env vars
```

## The Technical Detail

Routes decorated with `@app.route()` without an authentication decorator (`@login_required`, `Depends(get_current_user)`, middleware) are publicly accessible. Admin and debug paths are high-value targets — attackers run automated scanners that probe thousands of common admin paths per second. Even behind a firewall, lateral movement from a compromised internal host can reach unauthenticated endpoints.

## Vulnerable Code

See [`vulnerable.py`](vulnerable.py)

## Safe Code

See [`safe.py`](safe.py)

## How MCP Sentinel Detects This

`MissingAuthDetector` flags routes with `/admin`, `/debug`, `/internal` paths that lack authentication decorators within a ±5-line context window, emitting `MISSING_AUTH` at HIGH severity.

## Official References

- **OWASP**: [OWASP A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- **OWASP**: [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- **CISA**: [CISA — Securing Web Applications](https://www.cisa.gov/sites/default/files/publications/CISA_MS-ISAC_Ransomware%20Guide_S508C_.pdf)
- **CWE**: [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- **NIST**: [NIST SP 800-63B — Authentication Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
