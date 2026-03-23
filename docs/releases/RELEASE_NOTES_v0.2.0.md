# MCP Sentinel v0.2.0 — MCP-Native Attack Pattern Detectors

**Released:** 2026-03-23
**Tests:** 334 passed, 4 xfailed, 0 failed
**Coverage:** 86.47%

---

## Summary

v0.2.0 closes the gap between generic static analysis and MCP-specific threats. Three new detectors grounded in real CVE data and 2025–2026 MCP security research, plus full-schema poisoning coverage in `ToolPoisoningDetector`.

---

## New Detectors

### SSRFDetector

**Vulnerability type:** `SSRF` (new)
**CWE:** CWE-918 (primary), CWE-601 (redirect params)

Real-world data: 30% of MCP servers were SSRF-vulnerable in independent scans of 2,614 implementations. An SSRF-vulnerable MCP tool that accepts URL inputs enables:
- AWS EC2 IMDSv1 credential theft (`169.254.169.254/latest/meta-data/iam/security-credentials/`)
- GCP service account token theft (`metadata.google.internal`)
- Internal network pivoting through the server
- Open redirect for OAuth authorization code theft

**Pattern categories:**

| Category | Languages | Severity |
|---|---|---|
| Variable URL to `requests`/`httpx`/`aiohttp`/`urllib` | Python | HIGH (CVSS 8.6) |
| Variable URL to `fetch()`/`axios` | JavaScript/TypeScript | HIGH (CVSS 8.6) |
| Hardcoded cloud metadata endpoints | Any | CRITICAL (CVSS 9.8) |
| Redirect/callback URL parameters | Any | MEDIUM (CVSS 6.1) |
| Variable URL to `http.Get`/`http.NewRequest` | Go | HIGH (CVSS 8.6) |
| Variable URL to `new URL(var).openConnection()` | Java | HIGH (CVSS 8.6) |

**False positive handling:** Word-boundary keyword filter (suppresses `"latest"` matching `"test"`). Literal string URLs (e.g. `requests.get("https://api.example.com")`) do not trigger.

---

### NetworkBindingDetector

**Vulnerability type:** `NETWORK_BINDING` (new)
**CWE:** CWE-284

8,000+ MCP servers are publicly reachable because they bind to `0.0.0.0` instead of `127.0.0.1`. MCP servers are designed for local use (STDIO or localhost HTTP). Binding to all interfaces exposes every registered tool — including file system, shell, and API tools — to any reachable client.

**Pattern categories:**

| Category | Examples |
|---|---|
| Python Flask/uvicorn | `app.run(host="0.0.0.0")`, `uvicorn.run(..., host="0.0.0.0")` |
| Python raw socket | `socket.bind(("0.0.0.0", port))` |
| JavaScript/TypeScript | `server.listen(port, "0.0.0.0")`, `hostname: "0.0.0.0"` |
| Go explicit | `net.Listen("tcp", "0.0.0.0:8080")`, `ListenAndServe("0.0.0.0:8080", ...)` |
| Go shorthand | `net.Listen("tcp", ":8080")`, `ListenAndServe(":8080", ...)` — equivalent to 0.0.0.0 |
| Java | `new ServerSocket(port)`, `InetAddress.getByName("0.0.0.0")` |
| Config files | `BIND_HOST=0.0.0.0`, `HOST=0.0.0.0`, `bind-address: 0.0.0.0` |

All findings: MEDIUM severity (CVSS 6.5), HIGH confidence. Remediation points to `host='127.0.0.1'` and reverse proxy patterns.

---

### MissingAuthDetector

**Vulnerability type:** `MISSING_AUTH` (new)
**CWE:** CWE-306

MCP servers that expose management, admin, or system-operation endpoints without authentication are immediately exploitable by any reachable client (especially combined with NetworkBinding findings).

**Detection strategy:** Multi-line lookback (±5 lines before, ±3 lines after route definition) for authentication patterns. Confidence is MEDIUM throughout — global middleware at the app level cannot be detected statically.

**Pattern categories:**

| Category | Severity | CVSS |
|---|---|---|
| Flask/FastAPI route without `@login_required` / `Depends(get_current_user)` | MEDIUM | 6.5 |
| Route with sensitive path (`/admin`, `/debug`, `/internal`, `/management`) | HIGH | 8.2 |
| Express route without auth middleware | MEDIUM | 6.5 |
| MCP tool definition exposing system ops (`exec`, `shell`, `run_command`) | HIGH | 8.6 |

**Auth patterns detected (suppresses findings):** `@login_required`, `@auth_required`, `@jwt_required`, `Depends(get_current_user)`, `Security(...)`, `authMiddleware`, `verifyToken`, `passport.authenticate`.

---

## ToolPoisoningDetector Enhancements

The detector now covers all MCP schema fields, not just `description`.

### Pattern 7: Suspicious Tool Names

Full-schema poisoning embeds directives in tool *names*. Tool names are processed by the model during tool selection. Patterns: `always_run_first`, `override_*`, `hijack`, `intercept_all`, `__*__` naming conventions.

### Pattern 8: Suspicious Parameter Names

Parameter names are injection surfaces. Patterns: `__instruction__`, `system_prompt`, `hidden_prompt`, `ai_directive`, `model_instruction`.

### Pattern 9: Cross-Tool Manipulation (Tool Shadowing)

A malicious MCP server can intercept all agent tool calls by embedding cross-tool directives. Patterns: "before calling", "always call this tool first", "global rule", "applies to all tools", "this tool takes precedence", "override all other tools".

This is the documented *tool shadowing* / *cross-server escalation* attack vector from 2025 MCP security research.

### Pattern 10: Sensitive Path Targeting — CRITICAL

The exact technique used in the GitHub MCP prompt injection data heist. Tool descriptions or schemas reference credential file paths to instruct the model to read and exfiltrate those files.

Patterns (all → CRITICAL, CVSS 9.5, CWE-200):
- `.env` (with false positive suppression for `dotenv` library usage)
- `.ssh/`
- `~/.aws/credentials`
- `~/.config/`
- `/etc/passwd`, `/etc/shadow`
- `~/.npmrc`, `~/.pypirc`
- `authorized_keys`
- `id_rsa`, `id_ed25519`
- `~/.gitconfig`, `~/.docker/config.json`

### Anomalous Description Length

Tool descriptions longer than 500 characters are flagged at MEDIUM/LOW confidence. Attackers embed payloads after legitimate-looking content — the AI processes the full description but human reviewers rarely read past the first sentence.

---

## VulnerabilityType Additions

```python
SSRF = "ssrf"
NETWORK_BINDING = "network_binding"
MISSING_AUTH = "missing_auth"
```

---

## Statistics

| Metric | v0.1.0 | v0.2.0 |
|---|---|---|
| Detectors | 6 | 9 |
| Tests passing | 248 | 334 |
| Tests xfail | 4 | 4 |
| Coverage | ~82% | 86.47% |
| New test files | — | 4 |
| New detector files | — | 3 |

---

## Breaking Changes

None. Existing `VulnerabilityType` values unchanged. New detectors are additive.

---

## Upgrading

```bash
git pull
pip install -e .
```

No configuration changes required. New detectors are enabled by default.
