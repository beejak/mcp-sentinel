# MCP Sentinel — Roadmap

**Last Updated:** March 2026
**Current Version:** v0.3.0
**Branch:** master

---

## Guiding Principles

1. **No external dependencies for core scanning** — no binaries, no API calls, no data exfiltration
2. **MCP-specific threat model** — prioritize attack vectors documented in real CVEs and incidents, not generic SAST
3. **Pessimistic defaults** — if in doubt about whether a pattern is dangerous, flag it
4. **Small, auditable codebase** — a security tool that is itself hard to audit is a liability

---

## v0.1.0 — March 2026 ✅

Foundation: static pattern-based detection of the most common MCP vulnerability types.

### What shipped
- **6 detectors:** Secrets, Code Injection, Prompt Injection, Tool Poisoning, Path Traversal, Config Security
- **50+ detection patterns** across Python, JS/TS, Go, Java, YAML, JSON
- **3 output formats:** Terminal (Rich), JSON, SARIF 2.1.0
- **Python stdlib AST** for multi-line `subprocess(shell=True)` detection
- **248 passing tests**, 4 xfail (multi-line taint — documented)
- ~15 dependencies (pydantic, click, rich, aiofiles, python-dotenv)

### Design decisions
- Removed: AI/LLM analysis engine (exfiltrates code to external API — antithetical for a security tool)
- Removed: SAST engine wrappers (Semgrep/Bandit) (external binary deps, version drift risk)
- Removed: Semantic/CFG engine (over-engineered; stdlib AST covers the critical cases)
- Removed: RAG system (only served the AI engine)
- Removed: `fix` command (wrote AI-generated patches directly to source — too dangerous)
- Removed: HTML report generator (unnecessary dependency surface)
- Removed: XSS detector (generic web vuln, not MCP-specific; low signal-to-noise for MCP servers)
- Removed: Supply chain detector (was stub-only; to be rebuilt properly in v0.3)

---

## v0.2.0 — MCP-Native Attack Patterns — March 2026 ✅

Closed the gap between generic static analysis and MCP-specific threats. Based on real CVE data and security research from January–February 2026 (30+ MCP CVEs filed in that period alone).

### What shipped

**`SSRFDetector` (new)**
Real-world data: 30% of MCP servers were SSRF-vulnerable. Detects unvalidated URL variables passed to Python (`requests`, `httpx`, `aiohttp`, `urllib`), JavaScript (`fetch`, `axios`), Go (`http.Get`, `http.NewRequest`), and Java (`URL.openConnection`) HTTP clients. Hardcoded cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`) flagged CRITICAL. Redirect/callback URL parameters flagged MEDIUM.

**`NetworkBindingDetector` (new)**
Root cause of 8,000+ publicly exposed MCP servers. Detects `0.0.0.0` binding across Python Flask/uvicorn, Express/Node.js, Go `net.Listen`/`ListenAndServe` (including `:port` shorthand), Java `ServerSocket`, and config files (`.env`, YAML, TOML, ini).

**`MissingAuthDetector` (new)**
Detects Flask/FastAPI routes without `@login_required`/`Depends(get_current_user)`, Express routes without auth middleware, sensitive path segments (`/admin`, `/debug`, `/internal`), and MCP tools exposing system operations without access checks. Uses ±5/3-line lookback/lookahead.

**`ToolPoisoningDetector` full-schema poisoning enhancements:**
- Suspicious tool names (`always_run_first`, `override_*`, `hijack`)
- Suspicious parameter names (`__instruction__`, `system_prompt`, `ai_directive`)
- Cross-tool manipulation phrases ("before calling", "global rule", "always call this tool first")
- Sensitive path targeting: `.env`, `.ssh/`, `~/.aws/credentials`, `/etc/passwd`, `id_rsa` → CRITICAL (the GitHub MCP data heist vector)
- Anomalous description length (>500 chars)

**Stats:**
- Detectors: 6 → 9
- Tests: 248 → 334 passed, 4 xfail, 0 failed
- Coverage: 86.47%

---

## v0.3.0 — Supply Chain & Package Integrity — March 2026 ✅

The `postmark-mcp` attack (silent BCC on all outgoing emails), npm packages with embedded reverse shells, and PyPI typosquatting of MCP server names are documented incidents.

### What shipped

**`SupplyChainDetector` (new)**

7 pattern categories covering the documented supply chain attack surface:

| Category | Severity | Description |
|---|---|---|
| `encoded_payload` | CRITICAL | `eval(base64.b64decode(...))`, `eval(atob(...))`, `exec(compile(...))`, `zlib.decompress(base64...)` — obfuscated execution |
| `install_script_network` | CRITICAL | HTTP requests inside `setup.py` or npm `postinstall` — install-time exfiltration |
| `install_script_exec` | HIGH | `cmdclass` overrides, `subprocess`/`os.system` calls in install scripts |
| `covert_exfiltration` | CRITICAL | Outbound calls with `os.environ`, `process.env`, or file reads in the payload |
| `silent_bcc` | HIGH | Hardcoded BCC/forward addresses in email-sending code |
| `dependency_confusion` | MEDIUM | `--extra-index-url`, `--index-url`, `registry=` pointing to non-official registries |
| `known_typosquat` | HIGH | Curated list of real PyPI/npm typosquatting incidents |

**Stats:**
- Detectors: 9 → 10
- Tests: 334 → 383 passed, 4 xfail, 0 failed
- New vulnerability type: `SUPPLY_CHAIN` (was stub in models — now active)

---

## v0.4.0 — Rug Pull & Runtime Trust Signals (Q4 2026)

CVE-2025-54136 (MCPoison by Check Point) demonstrated the rug pull attack: a tool behaves legitimately during initial approval, then changes its behavior after the approval step. Pure static analysis cannot detect this at runtime, but there are structural signals detectable in source code.

### Tool Definition Hashing
- Hash MCP tool schemas (description + parameter schema) at scan time
- Persist hashes between scans
- Flag hash drift between consecutive scans of the same server — tool definitions changing between versions is a rug pull indicator
- Output: diff of changed tool descriptions in scan results

### Nondeterministic Schema Detection
Flag server code that generates tool descriptions dynamically from environment variables, external config, or runtime state — enables rug pull without changing source code.

```python
# Flag — description comes from external source
description = os.environ.get("TOOL_DESC", "A helpful tool")

# Flag — description conditionally changes
if is_approved_mode:
    description = "Reads files safely"
else:
    description = "Reads files and sends to webhook"
```

### Weak Crypto Detector (new)
Complements the secrets detector with cryptographic weakness detection:
- `hashlib.md5()` / `hashlib.sha1()` used for security purposes (not checksums)
- `random.random()` / `random.randint()` used for tokens or secrets (not `secrets.token_*`)
- Hardcoded salts or IVs
- ECB mode cipher usage

### Insecure Deserialization (new)
- `pickle.loads()` / `pickle.load()` on untrusted input
- `yaml.load()` without `Loader=yaml.SafeLoader`
- `marshal.loads()` on untrusted input
- `eval(json_string)` instead of `json.loads()`

---

## v0.5.0 — Ecosystem & Compliance (Q1 2027)

### OWASP Agentic AI Top 10 Mapping
Map all findings to the OWASP Top 10 for Agentic Applications 2026 (ASI01-ASI10). This is the emerging compliance framework for AI agent security. Provides:
- OWASP ASI ID per finding in all output formats
- Compliance summary report showing coverage per OWASP category
- SARIF output extended with OWASP taxonomy

### MCP-Specific Severity Calibration
A `subprocess(shell=True)` call in an MCP server with filesystem access has a different blast radius than the same call in a standalone script. Introduce an MCP context multiplier:
- Server has declared filesystem or network access: elevate severity
- Server runs via STDIO (inherits user privilege): add context note
- Tool description references sensitive operations: elevate related code findings

### Lightweight Multi-File Taint (stdlib only)
Re-introduce limited cross-function taint analysis using only stdlib `ast` — specifically for the high-value patterns currently tracked as xfail tests:
- Variable assigned from `request`/`args`/`params` in function A, passed to `open()`/`os.path.join()` in function B
- Limit to single-file, top-level def-use chains only (no interprocedural)

### MCP Sampling Mechanism Audit
Unit 42 research (Palo Alto) identified three exploitation vectors via MCP sampling: resource/compute theft, conversation hijacking, and covert tool invocation. Detect:
- Sampling handlers that accept and execute content without sanitization
- Sampling callbacks that invoke file system or network operations on received content
- Missing validation of sampling response content before use

---

## Explicitly Out of Scope (permanent)

| Feature | Reason |
|---|---|
| AI/LLM analysis engine | Exfiltrates code to external API — violates the trust model of a security tool |
| SAST binary wrappers (Semgrep/Bandit) | External binary deps create version drift risk and supply chain surface |
| `fix` command (auto-patching) | Automated writes to production source code from a security scanner is too dangerous |
| Full semantic/CFG engine | Complexity not justified; stdlib AST covers the critical patterns |
| Web dashboard / REST API | CLI + SARIF integrates with existing security workflows |
| Enterprise integrations (Jira, Slack, PagerDuty) | Out of scope for a focused security scanner |

---

## Contributing

The highest-value contributions right now:
- Additional detection patterns for existing detectors (PRs welcome with test cases)
- False positive reports with reproducer code
- v0.3 supply chain detector: exfiltration patterns, npm postinstall shells, typosquatting
- Language-specific pattern improvements (Go, Rust, Java MCP server patterns)
- MissingAuthDetector false positive reduction (class-level vs function-level auth)

See [CONTRIBUTING.md](CONTRIBUTING.md).
