# 09 — Missing Authentication

## The Analogy

A bank vault with no lock — anyone who walks up can open it. "Admin" tools that perform privileged actions without checking who's calling are that vault. In an MCP server deployed to production, every connected AI agent (or attacker) can invoke every tool unless access is explicitly controlled.

## What an Attacker Does

1. Attacker connects an MCP client to the server.
2. Calls `admin_delete_user` with any `userId` — no password, no token needed.
3. Or calls `admin_read_secrets` with `path=/etc/shadow` to dump all system password hashes.
4. Zero friction, zero barriers.

## Technical Detail

- **CWE-306**: Missing Authentication for Critical Function — critical operations callable without proving identity.
- MCP servers often run as trusted local processes or internal services, creating a false sense of security ("it's on the internal network").
- Tools named `admin_*`, `delete_*`, `shutdown_*`, or `reset_*` with no auth guard are the clearest signal.

## The Fix

- Require a secret token, API key, or session credential for all privileged tools.
- Store the expected credential in an environment variable, never hardcoded.
- Return a structured `Unauthorized` error before executing any destructive logic.
- Consider capability-based models: the AI agent should only receive a token scoped to what it legitimately needs.

## Detector

MCP Sentinel's **MissingAuthDetector** flags tools with privileged names (admin, delete, shutdown, reset, grant) that lack any token/credential check in the tool body.

## Authoritative References

| Authority | Resource |
|-----------|----------|
| OWASP | [A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| OWASP | [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) |
| CISA | [Secure by Design Principles](https://www.cisa.gov/secure-by-design) |
| MITRE | [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html) |
| NIST | [SP 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html) |
