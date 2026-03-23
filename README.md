# MCP Sentinel

<div align="center">

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Tests](https://img.shields.io/badge/tests-334%20passing-brightgreen.svg)](https://github.com/beejak/mcp-sentinel)
[![Version](https://img.shields.io/badge/version-v0.2.0-blue.svg)](https://github.com/beejak/mcp-sentinel/releases)

</div>

<div align="center">

# Static Security Scanner for MCP Servers

### Pattern-based vulnerability detection built specifically for the MCP ecosystem

**[Quick Start](#quick-start)** • **[Detectors](#detectors)** • **[Output Formats](#output-formats)** • **[Roadmap](ROADMAP.md)** • **[Contributing](CONTRIBUTING.md)**

</div>

---

## What's New in v0.2.0

| | v0.1.0 | v0.2.0 |
|---|---|---|
| **Detectors** | 6 | 9 (+3) |
| **Tests passing** | 248 | 334 (+86) |
| **Coverage** | ~82% | 86.47% |
| **VulnerabilityTypes** | 10 | 13 (+SSRF, NETWORK_BINDING, MISSING_AUTH) |

### New detectors

| Detector | What it catches | Key finding |
|---|---|---|
| `SSRFDetector` | Variable URLs passed to HTTP clients; cloud metadata IPs; redirect params | `169.254.169.254` → CRITICAL |
| `NetworkBindingDetector` | `0.0.0.0` binding in code and config files across all languages | Root cause of 8,000+ exposed MCP servers |
| `MissingAuthDetector` | Routes and endpoints without auth decorators or middleware | `/admin` without `@login_required` → HIGH |

### ToolPoisoningDetector: full-schema poisoning (v0.2 additions)

v0.1 only scanned `description` fields. v0.2 scans all schema fields:

| Added in v0.2 | Coverage |
|---|---|
| Suspicious tool names | `always_run_first`, `override_*`, `hijack` |
| Suspicious param names | `__instruction__`, `system_prompt`, `ai_directive` |
| Cross-tool manipulation | "before calling", "global rule", "always call this tool first" |
| Sensitive path targeting | `.env`, `.ssh/`, `~/.aws/credentials`, `/etc/passwd`, `id_rsa` → **CRITICAL** |
| Anomalous description length | >500 chars flagged as potential payload embedding |

### Threat model expanded in v0.2

| Vulnerability class | v0.1 | v0.2 |
|---|---|---|
| Hardcoded secrets | ✅ | ✅ |
| Code/command injection | ✅ | ✅ |
| Prompt injection | ✅ | ✅ |
| Tool poisoning (description field) | ✅ | ✅ |
| Tool poisoning (all schema fields) | — | ✅ |
| Path traversal | ✅ | ✅ |
| Insecure configuration | ✅ | ✅ |
| SSRF | — | ✅ |
| Server exposed on all interfaces | — | ✅ |
| Missing authentication on routes | — | ✅ |

---



MCP Sentinel scans MCP server source code for security vulnerabilities using pattern-based static analysis. No external binaries, no API calls, no data leaves your machine.

Real-world context: scanning of 2,614 MCP implementations found that **82% had path traversal exposure**, **67% had code injection surface**, **30% were vulnerable to SSRF**, and **8,000+ servers were publicly accessible due to 0.0.0.0 binding**. 30+ CVEs were filed against MCP server packages in January–February 2026 alone, including vulnerabilities in Anthropic's own reference implementations.

MCP Sentinel catches the patterns behind these vulnerabilities before they ship.

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/beejak/mcp-sentinel.git
cd mcp-sentinel
pip install -e .

# Scan a directory
mcp-sentinel scan /path/to/your/mcp-server

# Scan with severity filter
mcp-sentinel scan . --severity critical --severity high

# Export SARIF for GitHub Code Scanning
mcp-sentinel scan . --output sarif --json-file results.sarif

# Export JSON
mcp-sentinel scan . --output json --json-file results.json
```

---

## Detectors

Nine detectors covering the attack surface most relevant to MCP servers, based on real CVE data and incident reports.

### SecretsDetector
Catches hardcoded credentials before they reach version control.

| Pattern | Examples |
|---|---|
| AWS access keys | `AKIA...`, `ASIA...` |
| AI provider keys | `sk-` (OpenAI), Anthropic, Google AI |
| Source control tokens | `ghp_`, `gho_`, `glpat-` (GitLab) |
| JWT tokens | `eyJ...` bearer tokens |
| Private keys | RSA, EC, OpenSSH PEM blocks |
| Database URLs | `postgresql://user:pass@...` |
| Generic secrets | `api_key = "..."`, `password = "..."` |

### CodeInjectionDetector
Catches command and code execution sinks. Uses both regex and Python stdlib AST for multi-line `subprocess(shell=True)` patterns.

| Pattern | Risk |
|---|---|
| `os.system(user_input)` | CRITICAL — direct shell execution |
| `subprocess.run(..., shell=True)` | CRITICAL — shell injection via args |
| `eval(...)` / `exec(...)` | CRITICAL — arbitrary code execution |
| `child_process.exec(...)` (Node.js) | CRITICAL — shell injection |
| `cursor.execute(f"... {var}")` | HIGH — SQL injection |

### PromptInjectionDetector
Catches embedded instructions in tool descriptions or outputs that manipulate agent behavior. Based on patterns observed in published MCP prompt injection exploits.

| Pattern family | Examples |
|---|---|
| Role manipulation | `you are now`, `act as`, `pretend you are` |
| System prompt exposure | `ignore previous instructions`, `reveal your system prompt` |
| Jailbreak attempts | `DAN mode`, `developer mode`, `god mode` |
| Override directives | `disregard all prior`, `your new instructions are` |

### ToolPoisoningDetector
Catches malicious content embedded in tool schemas that targets AI agents rather than human users. Covers both the well-documented description-field attacks and full-schema poisoning across all schema fields.

| Pattern | Notes |
|---|---|
| Invisible Unicode characters | 17 character types (zero-width spaces, RTLO, Hangul filler, etc.) |
| Sensitive path targeting | `.env`, `.ssh/id_rsa`, `~/.aws/credentials` in tool descriptions — the GitHub MCP data heist vector |
| Behavior override directives | `ignore previous`, `override instructions`, `[hidden]` |
| Cross-tool manipulation | `"before calling tool X, always call this tool first"` — tool shadowing attack |
| Suspicious tool/param names | `always_run_first`, `__instruction__`, `system_prompt` — full-schema poisoning |
| Anomalous description length | Descriptions >500 chars flagged as potential payload embedding |

### PathTraversalDetector
Catches directory traversal patterns. Path traversal is the single most common vulnerability in MCP servers (82% exposure rate in real-world scans).

| Pattern | Examples |
|---|---|
| Traversal sequences | `../`, `%2e%2e%2f`, `..\\` |
| Unsafe extraction | `zipfile.extractall()` without path validation (Zip Slip) |
| Unvalidated file opens | `open(request.args.get("filename"))` |
| Unsafe path construction | `os.path.join(base, user_input)` without validation |

### ConfigSecurityDetector
Catches insecure configuration values in source files and config files.

| Pattern | Examples |
|---|---|
| Debug mode | `DEBUG=True`, `debug: true` |
| Open CORS | `CORS_ORIGINS=*`, `allow_origins=["*"]` |
| TLS disabled | `SSL_VERIFY=False`, `verify=False` |
| Weak secrets | `SECRET_KEY="dev"`, `JWT_SECRET="test"` |
| Exposed endpoints | Admin/debug routes without auth decorators |

### SSRFDetector _(new in v0.2)_
Catches server-side request forgery patterns. 30% of real-world MCP servers were SSRF-vulnerable. Covers Python, JavaScript/TypeScript, Go, and Java HTTP clients.

| Pattern | Risk |
|---|---|
| `requests.get(url)` with variable URL | HIGH — unvalidated outbound request |
| `fetch(userUrl)` / `axios.get(endpoint)` | HIGH — JS/TS unvalidated URL |
| `169.254.169.254` / `metadata.google.internal` | CRITICAL — cloud metadata endpoint |
| `redirect_uri`, `callback_url`, `webhook_url` params | MEDIUM — open redirect / SSRF via redirect |
| Go `http.Get(url)` / `http.NewRequest(..., url, ...)` | HIGH — unvalidated Go HTTP |
| Java `new URL(var).openConnection()` | HIGH — unvalidated Java HTTP |

### NetworkBindingDetector _(new in v0.2)_
Catches servers bound to `0.0.0.0` (all interfaces) instead of `127.0.0.1`. This misconfiguration is the root cause of 8,000+ publicly exposed MCP servers.

| Pattern | Examples |
|---|---|
| Python Flask/FastAPI | `app.run(host="0.0.0.0")`, `uvicorn.run(..., host="0.0.0.0")` |
| Go net.Listen | `net.Listen("tcp", ":8080")` — shorthand binds to 0.0.0.0 |
| Go ListenAndServe | `http.ListenAndServe(":8080", ...)` |
| Express / Node.js | `server.listen(3000, "0.0.0.0")` |
| Config files | `BIND_HOST=0.0.0.0`, `HOST=0.0.0.0` in `.env`/YAML |

### MissingAuthDetector _(new in v0.2)_
Catches routes and endpoints defined without authentication decorators or middleware. Uses a multi-line lookback/lookahead to check for auth patterns in surrounding code.

| Pattern | Risk |
|---|---|
| Flask `@app.route` without `@login_required` | MEDIUM — unauthenticated route |
| FastAPI `@router.get` without `Depends(get_current_user)` | MEDIUM — unauthenticated route |
| Routes with `/admin`, `/debug`, `/internal` paths | HIGH — sensitive endpoint without auth |
| Express route without auth middleware | MEDIUM — unauthenticated Express route |
| MCP tool definitions exposing `exec`/`shell`/`system` | HIGH — system operation without access check |

---

## Output Formats

### Terminal (default)
Rich-formatted table output with colored severity levels, code snippets, and remediation guidance.

```
mcp-sentinel scan .
```

### JSON
Structured export of all findings including metadata, risk scores, and remediation steps.

```
mcp-sentinel scan . --output json --json-file results.json
```

### SARIF 2.1.0
Compatible with GitHub Code Scanning, Azure DevOps, and GitLab SAST. Upload directly to the GitHub Security tab.

```
mcp-sentinel scan . --output sarif --json-file results.sarif
```

**GitHub Actions integration:**
```yaml
- name: MCP Sentinel Scan
  run: mcp-sentinel scan . --output sarif --json-file results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## CLI Reference

```
mcp-sentinel scan [TARGET] [OPTIONS]

Arguments:
  TARGET    Path to scan (file or directory). Prompts if omitted.

Options:
  -o, --output [terminal|json|sarif]  Output format (default: terminal)
  --severity [critical|high|medium|low|info]  Filter by severity (repeatable)
  --json-file PATH                    Output file for json/sarif formats
  --no-progress                       Disable progress bar
  --log-level [DEBUG|INFO|WARN|ERROR|FATAL]
  --log-file PATH                     Log to file
  --version                           Show version
  --help
```

---

## Configuration

Environment variables (also loadable from `.env`):

| Variable | Default | Description |
|---|---|---|
| `ENABLE_STATIC_ANALYSIS` | `true` | Enable/disable the static analysis engine |
| `LOG_LEVEL` | `info` | Logging verbosity |
| `MAX_WORKERS` | `4` | Concurrent workers for file scanning |
| `CACHE_TTL` | `3600` | Cache TTL in seconds |
| `ENVIRONMENT` | `development` | Environment label |

---

## Supported Languages

Python, JavaScript, TypeScript, Go, Java, YAML, JSON, Shell

---

## Architecture

```
mcp-sentinel scan .
        │
        ▼
MultiEngineScanner
        │
        ▼
StaticAnalysisEngine
        │
        ├── SecretsDetector
        ├── CodeInjectionDetector   (regex + stdlib ast)
        ├── PromptInjectionDetector
        ├── ToolPoisoningDetector   (enhanced: full-schema poisoning, path targeting)
        ├── PathTraversalDetector
        ├── ConfigSecurityDetector
        ├── SSRFDetector            (new v0.2: Python/JS/Go/Java HTTP clients)
        ├── NetworkBindingDetector  (new v0.2: 0.0.0.0 binding across all languages)
        └── MissingAuthDetector     (new v0.2: routes without auth decorators)
        │
        ▼
Vulnerability Objects → Deduplication → Output Formatter
```

- **No external binaries** — pure Python stdlib + `pydantic`, `click`, `rich`
- **No network calls** — all analysis runs locally
- **Async scanning** — concurrent file processing with configurable worker pool
- **MD5-based caching** — skip unchanged files across successive scans
- **Python AST** — used for multi-line `subprocess(shell=True)` detection (stdlib only)

---

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
python -m pytest tests/ -v

# Lint
ruff check src/
black --check src/

# Type check
mypy src/
```

**Test suite:** 334 passing, 4 xfail (multi-line taint patterns that require semantic analysis — documented in `tests/unit/test_path_traversal.py`)

---

## Threat Model & Limitations

MCP Sentinel is a **static analysis tool**. It finds patterns in source code — it does not execute code or observe runtime behavior.

**What it catches:** Hardcoded secrets, dangerous function calls, known injection patterns, insecure configuration values, SSRF sinks, 0.0.0.0 binding, unauthenticated routes, tool poisoning in all schema fields.

**What it does not catch:**
- Multi-line taint flows (e.g., `x = request.args.get("f")` on line 1, `open(x)` on line 50) — requires semantic/dynamic analysis
- Rug pull attacks (tool definitions changing at runtime) — requires runtime monitoring; structural signals planned for v0.4
- Logic flaws, business logic vulnerabilities
- Vulnerabilities in dependencies — planned for v0.3 (Supply Chain rebuild)

**False positives:** Pattern-based detection produces false positives. Review findings in context. The `MissingAuthDetector` in particular uses a heuristic lookahead window — global middleware that applies auth to all routes will not be detected statically and will produce findings that can be suppressed.

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full roadmap.

- **v0.2** ✅ — SSRF, network binding, missing auth, full-schema tool poisoning
- **v0.3** — Supply chain & package integrity (postmark-style exfiltration, npm postinstall shells, typosquatting)
- **v0.4** — Rug pull detection, weak crypto, insecure deserialization

---

## Security

To report a vulnerability in MCP Sentinel itself, see [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
