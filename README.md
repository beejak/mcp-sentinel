# MCP Sentinel

<div align="center">

[![Version](https://img.shields.io/badge/version-v0.5.0-blue.svg)](https://github.com/beejak/mcp-sentinel/releases)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-3776AB?logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-619%20passing-brightgreen.svg)](https://github.com/beejak/mcp-sentinel)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-Agentic%20AI%20Top%2010-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**Static security scanner for Model Context Protocol (MCP) servers.**

Finds hardcoded secrets, injection flaws, tool poisoning, rug pulls, and 10 more vulnerability classes — before they reach production.

**[Quick Start](#quick-start)** · **[Detectors](#detection-coverage)** · **[Scan Report](#scan-report-beejak--vulnerable-mcp-server)** · **[CLI Reference](#cli-reference)** · **[OWASP Coverage](#owasp-agentic-ai-top-10-coverage)**

</div>

---

## See It In Action

```
$ mcp-sentinel scan ./my-mcp-server

╭─────────────────────────────────╮
│ MCP Sentinel v0.5.0             │
│ Scanning: ./my-mcp-server       │
│ Engine:   static                │
╰─────────────────────────────────╯

 Scan Summary
╭───────────────────────┬──────────────╮
│ Files Scanned         │ 57/57        │
│ Duration              │ 0.09s        │
│ Total Vulnerabilities │ 86           │
╰───────────────────────┴──────────────╯

 Vulnerabilities by Severity
╭──────────┬───────╮
│ CRITICAL │    32 │
│ HIGH     │    45 │
│ MEDIUM   │     9 │
╰──────────┴───────╯

 OWASP Agentic AI Top 10 Coverage
╭─────────┬──────────────────────────────────────────┬──────────┬──────────────╮
│ ASI ID  │ Category                                 │ Findings │ Max Severity │
├─────────┼──────────────────────────────────────────┼──────────┼──────────────┤
│ ASI01   │ Prompt Injection                         │       52 │   CRITICAL   │
│ ASI02   │ Sensitive Data Exposure                  │        3 │   CRITICAL   │
│ ASI03   │ Supply Chain Vulnerabilities             │        1 │     HIGH     │
│ ASI04   │ Insecure Direct Tool Invocation          │       15 │   CRITICAL   │
│ ASI05   │ Improper Output Handling / SSRF          │        5 │   CRITICAL   │
│ ASI06   │ Excessive Agency                         │        1 │    MEDIUM    │
│ ASI08   │ Insecure Deserialization                 │        1 │   CRITICAL   │
│ ASI09   │ Improper Error Handling / Path Traversal │        8 │     HIGH     │
╰─────────┴──────────────────────────────────────────┴──────────┴──────────────╯

 Risk Score: 82.4/100

 Found 86 vulnerabilities
```

---

## Why MCP Sentinel

The MCP ecosystem is growing fast. Security tooling is not keeping up.

A scan of 2,614 public MCP server implementations found:
- **82%** had path traversal exposure
- **67%** had code injection surface
- **30%** were SSRF-vulnerable
- **8,000+** were publicly accessible due to `0.0.0.0` binding
- **30+ CVEs** filed in January–February 2026 alone, including Anthropic's own reference implementations

MCP Sentinel catches the patterns behind these vulnerabilities — in seconds, with no external dependencies and no data leaving your machine.

---

## Quick Start

```bash
# Install
pip install mcp-sentinel

# Scan a directory
mcp-sentinel scan /path/to/your/mcp-server

# Scan and fail CI on critical/high only
mcp-sentinel scan . --severity critical --severity high --no-progress

# Export for GitHub Code Scanning
mcp-sentinel scan . --output sarif --json-file results.sarif

# Export OWASP compliance report
mcp-sentinel scan . --compliance-file compliance.json
```

---

## Detection Coverage

14 detectors. Every finding maps to an OWASP Agentic AI Top 10 category and a CWE.

| Detector | What It Catches | OWASP | Severity |
|---|---|---|---|
| **SecretsDetector** | AWS keys, OpenAI/Anthropic tokens, JWT, private keys, DB connection strings | ASI02 | CRITICAL |
| **CodeInjectionDetector** | `os.system()`, `subprocess(shell=True)`, `eval()`, `exec()`, SQL f-strings | ASI04 | CRITICAL |
| **PromptInjectionDetector** | Role manipulation, system prompt exposure, jailbreak patterns, override directives | ASI01 | HIGH |
| **ToolPoisoningDetector** | Invisible Unicode, sensitive path targeting, behavior overrides, cross-tool manipulation | ASI01 | CRITICAL |
| **PathTraversalDetector** | `../` sequences, zip slip, unvalidated file opens, unsafe `os.path.join()` | ASI09 | HIGH |
| **SSRFDetector** | Unvalidated URLs, cloud metadata endpoints (`169.254.169.254`), open redirects | ASI05 | CRITICAL |
| **MissingAuthDetector** | Routes without auth decorators, sensitive paths, unauthenticated system tools | ASI04 | HIGH |
| **NetworkBindingDetector** | `0.0.0.0` binding across Python, JS, Go, Java, and config files | ASI06 | MEDIUM |
| **ConfigSecurityDetector** | Debug mode, open CORS, TLS disabled, weak secrets, exposed admin endpoints | ASI02 | HIGH |
| **WeakCryptoDetector** | MD5/SHA-1, ECB mode, insecure random, static IV, deprecated ciphers | ASI04 | HIGH |
| **InsecureDeserializationDetector** | `pickle.loads()`, `yaml.load()`, `marshal`, `eval()` as parser, PHP `unserialize()` | ASI08 | CRITICAL |
| **SupplyChainDetector** | Encoded payloads, install-time exfiltration, silent BCC, typosquatted packages | ASI03 | CRITICAL |
| **MCPSamplingDetector** | Sampling misuse, sensitive data in LLM calls, prompt injection via sampling | ASI01 | HIGH |
| **RugPullDetector** | Global state mutation, first-call sentinel, time-based behavior evasion | ASI01 | CRITICAL |

---

## Scan Report: [beejak / Vulnerable-MCP-Server](https://github.com/beejak/Vulnerable-MCP-Server)

> Tested against the world's first deliberately vulnerable MCP server — 18 intentional vulnerabilities across 5 attack categories, based on real CVEs and novel MCP-specific attack patterns.

### Summary

| Metric | Value |
|---|---|
| Files scanned | 57 |
| Scan duration | 0.09s |
| Total findings | **86** |
| Critical | 32 |
| High | 45 |
| Medium | 9 |
| OWASP ASI categories covered | **8 / 10** |

### OWASP Agentic AI Top 10 Coverage

| ASI | Category | Findings | Severity |
|---|---|---|---|
| **ASI01** | Prompt Injection | 52 | 🔴 CRITICAL |
| **ASI02** | Sensitive Data Exposure | 3 | 🔴 CRITICAL |
| **ASI03** | Supply Chain Vulnerabilities | 1 | 🟠 HIGH |
| **ASI04** | Insecure Direct Tool Invocation | 15 | 🔴 CRITICAL |
| **ASI05** | Improper Output Handling / SSRF | 5 | 🔴 CRITICAL |
| **ASI06** | Excessive Agency | 1 | 🟡 MEDIUM |
| **ASI08** | Insecure Deserialization | 1 | 🔴 CRITICAL |
| **ASI09** | Improper Error Handling / Path Traversal | 8 | 🟠 HIGH |

### Selected Findings

**Secrets (ASI02)**
```
[CRITICAL] Hardcoded AWS Access Key
  config.py:47  ·  SecretsDetector  ·  CWE-798
  fake_aws_key: str = "AKIAFAKE1234567890AB"

[CRITICAL] Hardcoded AWS Secret Key
  config.py:48  ·  SecretsDetector  ·  CWE-798
  fake_aws_secret: str = "fakesecret/FAKE/abc123def456ghi789jkl012"
```

**Code Injection (ASI04)**
```
[CRITICAL] Command Injection via os.system()
  injection.py:135  ·  CodeInjectionDetector  ·  CWE-78
  Hint(2, "Create a malicious pickle object with os.system() in __reduce__")

[CRITICAL] Insecure Deserialization: pickle.loads() on Untrusted Data
  injection.py:295  ·  InsecureDeserializationDetector  ·  CWE-502
  obj = pickle.loads(decoded)  # noqa: S301 — intentionally vulnerable
```

**Tool Poisoning (ASI01)**
```
[HIGH] Prompt Injection: System Prompt Exposure
  orchestrator.py:221  ·  PromptInjectionDetector  ·  CWE-94
  planning_task = f"""Break this task into sub-tasks for the agent system...

[HIGH] Path Traversal: Unsafe Path Joining
  orchestrator.py:103  ·  PathTraversalDetector  ·  CWE-22
  path = os.path.join(self.work_dir, tool_input["path"])
```

**Rug Pull — detected for the first time (ASI01)**
```
[CRITICAL] Rug Pull: Time-Based Behavior Mutation
  rug_pull.py:153  ·  RugPullDetector  ·  CWE-913
  elapsed = now - _compliance_first_call
  → Tool returns safe response during scanner window, exfiltrates after delay

[HIGH] Rug Pull: Global State Mutation
  rug_pull.py:112  ·  RugPullDetector  ·  CWE-913
  global _analyse_call_count
  → Call #1 returns clean result; call #2+ exfiltrates to attacker-controlled server

[MEDIUM] Rug Pull: First-Call Sentinel Pattern
  rug_pull.py:150  ·  RugPullDetector  ·  CWE-913
  if _compliance_first_call is None:
```

**Infrastructure (ASI06)**
```
[MEDIUM] Network Binding: Server Exposed on All Interfaces (0.0.0.0)
  docker-compose.yml:20  ·  NetworkBindingDetector  ·  CWE-605
  MCP_HOST: "0.0.0.0"
```

> Full JSON report, SARIF file, and OWASP compliance report are available in [`reports/`](reports/).
> The Vulnerable-MCP-Server README includes a full breakdown with remediation guidance: [beejak/Vulnerable-MCP-Server](https://github.com/beejak/Vulnerable-MCP-Server)

---

## Output Formats

### Terminal (default)

Colour-coded table with severity levels, file locations, code snippets, and remediation steps. Best for interactive review.

```bash
mcp-sentinel scan /path/to/server
```

### JSON

Structured output with all findings, metadata, CVSS scores, MITRE ATT&CK IDs, and OWASP mappings. Pipe into any downstream tool.

```bash
mcp-sentinel scan . --output json --json-file results.json
```

<details>
<summary>Example JSON finding</summary>

```json
{
  "type": "secret_exposure",
  "title": "Hardcoded AWS Access Key",
  "severity": "critical",
  "confidence": "high",
  "file_path": "config.py",
  "line_number": 47,
  "code_snippet": "aws_key: str = \"AKIA...\"",
  "cwe_id": "CWE-798",
  "cvss_score": 9.1,
  "owasp_asi_id": "ASI02",
  "owasp_asi_name": "Sensitive Data Exposure",
  "remediation": "Revoke this key immediately. Use environment variables or a secrets manager.",
  "fixed_code": "aws_key: str = os.getenv(\"AWS_ACCESS_KEY_ID\")",
  "mitre_attack_ids": ["T1552.001"],
  "detector": "SecretsDetector",
  "engine": "static"
}
```
</details>

### SARIF 2.1.0

Compatible with GitHub Code Scanning, GitLab SAST, and Azure DevOps. Upload directly to the GitHub Security tab.

```bash
mcp-sentinel scan . --output sarif --json-file results.sarif
```

**GitHub Actions:**
```yaml
- name: MCP Sentinel Scan
  run: |
    pip install mcp-sentinel
    mcp-sentinel scan . --output sarif --json-file results.sarif

- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### OWASP Compliance Report

Exports a structured JSON report mapping every finding to its ASI01–ASI10 category, with severity breakdown and coverage gaps.

```bash
mcp-sentinel scan . --compliance-file compliance.json
```

<details>
<summary>Example compliance output</summary>

```json
{
  "framework": "OWASP Agentic AI Top 10 2026",
  "total_findings": 86,
  "categories": {
    "ASI01": {
      "name": "Prompt Injection",
      "finding_count": 52,
      "max_severity": "critical",
      "severity_breakdown": { "critical": 25, "high": 23, "medium": 4 }
    },
    "ASI02": {
      "name": "Sensitive Data Exposure",
      "finding_count": 3,
      "max_severity": "critical"
    }
  }
}
```
</details>

---

## CLI Reference

```
Usage: mcp-sentinel [OPTIONS] COMMAND [ARGS]...

Options:
  --log-level [DEBUG|INFO|WARN|ERROR|FATAL]
                        Logging verbosity. Use DEBUG to trace pattern matches.
                        [default: INFO]
  --log-file PATH       Write logs to a file in addition to stderr.
  --version             Show version and exit.
  --help                Show this message and exit.

Commands:
  scan    Scan a directory or file for security vulnerabilities.
```

### `mcp-sentinel scan`

```
Usage: mcp-sentinel scan [TARGET] [OPTIONS]

  Scan a directory or file for security vulnerabilities.

  TARGET is the path to scan — a directory or a single file.
  If omitted, mcp-sentinel will prompt you interactively.

  Runs 14 pattern-based detectors covering: hardcoded secrets, code
  injection, prompt injection, tool poisoning, path traversal, config
  security, SSRF, network binding, missing auth, supply chain attacks,
  weak cryptography, insecure deserialization, MCP sampling misuse,
  and rug pull / timed evasion attacks.

Arguments:
  TARGET    Path to scan (file or directory). Prompts if omitted.

Options:
  -o, --output [terminal|json|sarif]
                        Output format.
                          terminal  Colour-coded table — best for interactive use.
                          json      Structured findings — use for scripting.
                          sarif     SARIF 2.1.0 — use for GitHub Code Scanning.
                        [default: terminal]

  --severity [critical|high|medium|low|info]
                        Only show findings at or matching the given severity.
                        Repeatable: --severity critical --severity high
                        Omit to show all severities.

  --json-file PATH      Output file for json or sarif formats.
                        Required when --output sarif (for GitHub upload).
                        If omitted with --output json, prints to stdout.

  --no-progress         Suppress the animated progress bar.
                        Use in CI environments to keep logs clean.

  --compliance-file PATH
                        Write an OWASP Agentic AI Top 10 compliance report
                        (JSON) to this file. Lists all ASI01–ASI10 categories
                        with finding counts, severity breakdown, and gaps.

  --help                Show this message and exit.
```

### Common workflows

```bash
# Interactive review — default terminal output
mcp-sentinel scan /path/to/mcp-server

# CI — fail on critical/high, suppress noise
mcp-sentinel scan . --severity critical --severity high --no-progress

# GitHub Code Scanning integration
mcp-sentinel scan . --output sarif --json-file results.sarif

# Export all findings as JSON
mcp-sentinel scan . --output json --json-file results.json

# Scan a single file with debug logging
mcp-sentinel --log-level debug scan server.py

# Keep audit log while reviewing interactively
mcp-sentinel --log-file audit.log scan .

# OWASP Agentic AI Top 10 compliance report
mcp-sentinel scan . --compliance-file compliance.json

# All outputs at once
mcp-sentinel scan . \
  --output json --json-file results.json \
  --compliance-file compliance.json \
  --no-progress
```

---

## OWASP Agentic AI Top 10 Coverage

Every finding is annotated with its ASI category. The table below shows which detectors map to which categories.

| ASI | Category | Detectors |
|---|---|---|
| **ASI01** | Prompt Injection | PromptInjectionDetector, ToolPoisoningDetector, RugPullDetector, MCPSamplingDetector |
| **ASI02** | Sensitive Data Exposure | SecretsDetector, ConfigSecurityDetector |
| **ASI03** | Supply Chain Vulnerabilities | SupplyChainDetector |
| **ASI04** | Insecure Direct Tool Invocation | CodeInjectionDetector, MissingAuthDetector, WeakCryptoDetector |
| **ASI05** | Improper Output Handling / SSRF | SSRFDetector |
| **ASI06** | Excessive Agency | NetworkBindingDetector |
| **ASI07** | Insecure Plugin Design | ToolPoisoningDetector, ConfigSecurityDetector |
| **ASI08** | Insecure Deserialization | InsecureDeserializationDetector |
| **ASI09** | Improper Error Handling / Path Traversal | PathTraversalDetector |

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
        ├── SecretsDetector              AWS/OpenAI/GitHub keys, JWTs, PEM blocks
        ├── CodeInjectionDetector        os.system, subprocess(shell=True), eval, exec, SQL
        ├── PromptInjectionDetector      role manipulation, system prompt exposure, jailbreaks
        ├── ToolPoisoningDetector        invisible Unicode, path targeting, cross-tool manipulation
        ├── PathTraversalDetector        ../ sequences, zip slip, unsafe joins — with taint analysis
        ├── SSRFDetector                 unvalidated URLs, cloud metadata endpoints
        ├── MissingAuthDetector          routes without auth decorators, sensitive paths
        ├── NetworkBindingDetector       0.0.0.0 binding across Python / JS / Go / Java / config
        ├── ConfigSecurityDetector       debug mode, open CORS, TLS off, weak secrets
        ├── WeakCryptoDetector           MD5/SHA-1, ECB, insecure random, static IV
        ├── InsecureDeserializationDetector  pickle, yaml.load, marshal, eval-as-parser
        ├── SupplyChainDetector          encoded payloads, install-time exec, BCC injection
        ├── MCPSamplingDetector          sampling misuse, LLM call injection
        └── RugPullDetector              global state mutation, first-call sentinel, timed evasion
        │
        ▼
SeverityCalibrator          elevates severity based on MCP server context
        │
        ▼
Findings → Deduplication → OWASP annotation → Output formatter
```

**Design principles:**
- No external binaries — pure Python stdlib + `pydantic`, `click`, `rich`
- No network calls — all analysis runs locally, nothing leaves your machine
- Async scanning — concurrent file I/O with configurable worker pool
- MD5-based file cache — unchanged files skipped on successive scans
- Test-file awareness — `tests/`, `fixtures/`, `spec/` directories auto-suppressed to eliminate assertion false positives
- Python AST — multi-line `subprocess(shell=True)` detected via stdlib AST, not just regex

---

## Supported Languages

| Language | Extensions |
|---|---|
| Python | `.py` |
| JavaScript / TypeScript | `.js`, `.jsx`, `.ts`, `.tsx` |
| Go | `.go` |
| Java | `.java` |
| Configuration | `.yaml`, `.yml`, `.json`, `.env`, `.toml` |
| Shell | `.sh`, `.bash` |

---

## Development

```bash
# Clone and install with dev dependencies
git clone https://github.com/beejak/mcp-sentinel.git
cd mcp-sentinel
pip install -e ".[dev]"

# Run the full test suite (619 tests, ~8s)
python -m pytest tests/ -v

# Run a specific detector's tests
python -m pytest tests/unit/test_tool_poisoning.py -v

# Lint
ruff check src/
black --check src/

# Type check
mypy src/

# Run against the deliberately vulnerable MCP server
git clone https://github.com/beejak/Vulnerable-MCP-Server ../Vulnerable-MCP-Server
mcp-sentinel scan ../Vulnerable-MCP-Server
```

**Test suite:** 619 passing, 4 xfail (multi-line taint flows that require semantic analysis — tracked in `tests/unit/test_path_traversal.py`)

### Adding a detector

```
1. Create  src/mcp_sentinel/detectors/your_detector.py   — extend BaseDetector
2. Add     src/mcp_sentinel/detectors/__init__.py         — import + __all__
3. Register src/mcp_sentinel/engines/static/static_engine.py  — add to _get_default_detectors()
4. Write   tests/unit/test_your_detector.py               — at least 5 assertions
```

---

## Threat Model & Limitations

MCP Sentinel is a **static analysis tool**. It finds patterns in source code — it does not execute code or observe runtime behavior.

**What it catches:**

| Class | Detector |
|---|---|
| Hardcoded secrets | SecretsDetector |
| Code / command injection | CodeInjectionDetector |
| Prompt injection | PromptInjectionDetector |
| Tool poisoning (all schema fields) | ToolPoisoningDetector |
| Path traversal | PathTraversalDetector |
| SSRF | SSRFDetector |
| Missing authentication | MissingAuthDetector |
| 0.0.0.0 network binding | NetworkBindingDetector |
| Insecure configuration | ConfigSecurityDetector |
| Weak / broken cryptography | WeakCryptoDetector |
| Insecure deserialization | InsecureDeserializationDetector |
| Supply chain attacks | SupplyChainDetector |
| MCP sampling misuse | MCPSamplingDetector |
| Rug pull / timed evasion | RugPullDetector |

**What it does not catch:**

- Multi-line taint flows (`x = request.args.get("f")` on line 1, `open(x)` on line 50) — requires semantic analysis
- Runtime rug pulls using external state (database, remote config) rather than module-level variables
- Logic flaws and business logic vulnerabilities
- Deep transitive dependency analysis (direct manifest files and code patterns only)

---

## What's New

| | v0.1 | v0.2 | v0.3 | v0.4 | v0.5 |
|---|---|---|---|---|---|
| **Detectors** | 6 | 9 | 10 | 12 | **14** |
| **Tests** | 248 | 334 | 409 | 525 | **619** |
| **OWASP ASI mapping** | — | — | — | — | ✅ |
| **Rug pull detection** | — | — | — | — | ✅ |
| **Test-file FP suppression** | — | — | — | — | ✅ |

**v0.5.0** — `RugPullDetector` (global state mutation, first-call sentinel, time-based evasion), OWASP Agentic AI Top 10 mapping on all findings, 21% false positive reduction via test-file awareness, MCP sampling audit.

**v0.4.0** — `WeakCryptoDetector` (MD5/SHA-1, ECB, insecure random, deprecated ciphers), `InsecureDeserializationDetector` (pickle, yaml.load, marshal, PHP unserialize, Node.js VM escape).

**v0.3.0** — `SupplyChainDetector` (encoded payloads, install-time exfiltration, BCC injection, typosquatted packages).

**v0.2.0** — `SSRFDetector`, `NetworkBindingDetector`, `MissingAuthDetector`, full-schema tool poisoning.

---

## References

- [OWASP Agentic AI Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Tool Poisoning Attacks — Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [CVE-2025-6514 — mcp-remote OAuth RCE (JFrog)](https://research.jfrog.com/vulnerabilities/mcp-remote-command-injection-rce-jfsa-2025-001290844/)
- [MCP Attack Vectors — Palo Alto Unit 42](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)
- [Enhanced Tool Definition Interface — arXiv](https://arxiv.org/abs/2506.01333v1)
- [Systematic MCP Security Analysis — arXiv](https://arxiv.org/html/2508.12538v1)
- [VulnerableMCP Vulnerability Database](https://vulnerablemcp.info/)
- [beejak/Vulnerable-MCP-Server](https://github.com/beejak/Vulnerable-MCP-Server) — deliberately vulnerable MCP server used for scanner validation

---

## Security

To report a vulnerability in MCP Sentinel itself, see [SECURITY.md](SECURITY.md).

### Docker Deployment Hardening (2026-04-20)

`docker-compose.yml` no longer ships with hardcoded default credentials. All sensitive values now use Docker's `:?` syntax — compose will **exit with an error** rather than silently falling back to a weak default if any required variable is unset:

```
DB_PASSWORD:?DB_PASSWORD is required
REDIS_PASSWORD:?REDIS_PASSWORD is required
SECRET_KEY:?SECRET_KEY is required
MINIO_ROOT_USER:?MINIO_ROOT_USER is required
MINIO_ROOT_PASSWORD:?MINIO_ROOT_PASSWORD is required
```

A `.env.example` file has been added to the repo root. Before running the stack:

```bash
cp .env.example .env
# Fill in every required value in .env, then:
docker-compose up -d
```

The `.env` file is gitignored and must never be committed.

---

## License

MIT — see [LICENSE](LICENSE).
