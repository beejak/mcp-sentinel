# CLI Guide

This guide explains every command and option in MCP Sentinel with practical context — what each flag does, when to use it, and real-world examples for common workflows.

---

## Commands at a glance

```
mcp-sentinel [GLOBAL OPTIONS] COMMAND
```

There are two commands: **`scan`** and **`baseline`**. Global options apply to all commands and must come *before* the command name.

---

## Global options

### `--version`

Print the installed version and exit.

```bash
mcp-sentinel --version
# mcp-sentinel, version 0.4.1
```

---

### `--log-level [debug|info|warn|error|fatal]`

**Default:** `info`

Controls how much detail is written to stderr during a scan.

| Level | When to use |
|---|---|
| `debug` | Trace exactly which files are opened and which patterns fire — useful for understanding a false positive or verifying a new codebase is scanned |
| `info` | Default; shows scan progress and summary |
| `warn` | Suppress informational messages — useful in scripts where you only care about findings |
| `error` / `fatal` | Maximum silence — only show unrecoverable errors |

```bash
# Trace pattern matches on a single file
mcp-sentinel --log-level debug scan server.py

# Silent in a script — only exit code matters
mcp-sentinel --log-level error scan . --no-progress
```

---

### `--log-file PATH`

Write log output to a file *in addition to* stderr. The terminal still shows the normal output; the file gets the structured log.

Use this when you want a persistent audit trail of what was scanned and when, without losing the interactive terminal view.

```bash
mcp-sentinel --log-file scan-audit.log scan .
```

Log files use JSON-structured format (timestamp, level, message) and rotate at 10 MB with 5 backups.

---

## `scan` command

```
mcp-sentinel scan [TARGET] [OPTIONS]
```

Scans a directory or file for security vulnerabilities using all 20 detectors.

### `TARGET`

The path to scan — a directory or a single file. **Optional**: if omitted, mcp-sentinel prompts you interactively to enter a path.

```bash
# Scan a directory
mcp-sentinel scan /path/to/mcp-server

# Scan a single file
mcp-sentinel scan src/server.py

# Omit target — interactive prompt appears
mcp-sentinel scan
```

---

### `-o / --output [terminal|json|sarif]`

**Default:** `terminal`

Controls the output format. Choose based on what you're doing with the results:

#### `terminal` — human review

Colour-coded table with severity badges, file locations, code snippets, and remediation steps. Best for interactive use.

```bash
mcp-sentinel scan .
```

#### `json` — scripting and tooling

Structured JSON with every finding's full metadata (title, description, severity, file, line, code snippet, remediation, CVSS score). Write to a file or pipe to `jq`.

```bash
# Write to file
mcp-sentinel scan . --output json --json-file results.json

# Pipe to jq — print just critical finding titles
mcp-sentinel scan . --output json | jq '[.vulnerabilities[] | select(.severity=="critical") | .title]'
```

#### `sarif` — GitHub / GitLab / Azure code scanning

Writes a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) file. Upload to GitHub Security tab to see findings inline on pull requests.

```bash
mcp-sentinel scan . --output sarif --json-file results.sarif
```

GitHub Actions integration:
```yaml
- name: MCP Sentinel Scan
  run: mcp-sentinel scan . --output sarif --json-file results.sarif --no-progress

- name: Upload to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

---

### `--severity [critical|high|medium|low|info]`

**Default:** show all severities

Filter findings to only the specified severity levels. Repeatable — pass the flag multiple times to include more than one level.

```bash
# Show only critical findings
mcp-sentinel scan . --severity critical

# Show critical and high
mcp-sentinel scan . --severity critical --severity high
```

**When to use this:**

- **CI/CD pipeline gate** — fail the build only on critical/high. Review medium/low in a separate triage job.
- **Triage** — start with critical, fix those, then widen to high.
- **Noise reduction** — suppress info/low when onboarding a legacy codebase with many low-signal findings.

Note: filtering is applied *after* the scan completes — all detectors always run regardless of this flag.

---

### `--json-file PATH`

The file path to write `json` or `sarif` output to.

- **Required** when `--output sarif` (GitHub upload needs a file path).
- **Optional** with `--output json` — if omitted, JSON is printed to stdout.
- Has no effect with `--output terminal`.

```bash
# SARIF to file (required)
mcp-sentinel scan . --output sarif --json-file results.sarif

# JSON to file
mcp-sentinel scan . --output json --json-file results.json

# JSON to stdout (pipe-friendly)
mcp-sentinel scan . --output json | jq .vulnerabilities
```

---

### `--compliance-file PATH`

Write an [OWASP Agentic AI Top 10 2026](https://owasp.org/www-project-top-10-for-large-language-model-applications/) compliance report to this file as JSON.

The report covers all ASI01–ASI10 categories with finding counts, severity breakdowns, and notes on categories with no findings. It is independent of `--output` — you can combine it with any output format.

```bash
# Compliance report only
mcp-sentinel scan . --compliance-file compliance.json

# Compliance + SARIF for GitHub upload
mcp-sentinel scan . --output sarif --json-file results.sarif --compliance-file compliance.json

# Compliance + JSON findings in one command
mcp-sentinel scan . --output json --json-file findings.json --compliance-file compliance.json
```

Example compliance report structure:
```json
{
  "framework": "OWASP Agentic AI Top 10 2026",
  "total_findings": 7,
  "categories": {
    "ASI01": {"name": "Prompt Injection", "finding_count": 3, "max_severity": "high"},
    "ASI02": {"name": "Sensitive Data Exposure", "finding_count": 0, ...},
    ...
  },
  "summary": {"categories_with_findings": 4, "risk_distribution": {...}}
}
```

---

### `--no-progress`

Suppress the animated progress bar.

**Always use this in CI** — animated spinners and progress bars produce garbled output in non-TTY log streams.

```bash
mcp-sentinel scan . --no-progress
```

In CI the scan still runs at full speed; only the live progress display is suppressed. A static status message is shown instead.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed, no critical findings |
| `1` | Scan completed with **critical** findings — use this to fail a pipeline |
| `2` | Scan aborted (bad arguments, path not found, etc.) |

```bash
mcp-sentinel scan . --severity critical --no-progress
if [ $? -eq 1 ]; then
  echo "Critical findings — blocking deploy"
  exit 1
fi
```

---

## Worked examples

### Local interactive review

```bash
mcp-sentinel scan /path/to/mcp-server
```

Runs all 20 detectors, shows colour-coded findings grouped by severity, an OWASP ASI01–ASI10 category breakdown, and a risk score.

---

### Hard gate in CI — fail on critical/high

```bash
mcp-sentinel scan . --severity critical --severity high --no-progress
```

Exits `1` if any critical finding is found. Add `--output sarif --json-file results.sarif` to also upload to GitHub Security.

---

### Full GitHub Actions workflow

```yaml
name: MCP Sentinel Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Install MCP Sentinel
        run: pip install mcp-sentinel

      - name: Scan
        run: |
          mcp-sentinel scan . \
            --output sarif \
            --json-file results.sarif \
            --no-progress

      - name: Upload to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

---

### Debug a false positive

You suspect a finding is a false positive. Use debug logging to see exactly which pattern fired:

```bash
mcp-sentinel --log-level debug --log-file debug.log scan src/utils.py 2>&1 | grep -i "pattern\|match\|detect"
```

---

### Export findings for a security review spreadsheet

```bash
mcp-sentinel scan . --output json --json-file findings.json --no-progress

# Extract columns useful for a spreadsheet
jq -r '.vulnerabilities[] | [.severity, .title, .file_path, .line_number, .remediation] | @csv' findings.json
```

---

## Detector reference

All 20 detectors run on every scan. They cannot be individually disabled (by design — a scanner that lets you silence detectors is easier to misuse). Every finding is annotated with its OWASP Agentic AI Top 10 (ASI01–ASI10) category.

| Detector | Severity range | ASI | What it catches |
|---|---|---|---|
| `SecretsDetector` | CRITICAL | ASI02 | AWS keys, API tokens, private keys, DB URLs, 15+ patterns |
| `CodeInjectionDetector` | CRITICAL/HIGH | ASI04 | `os.system`, `subprocess(shell=True)`, `eval`, `exec`, SQL f-strings, `promisify(exec)` patterns |
| `PromptInjectionDetector` | HIGH/MEDIUM | ASI01 | Role manipulation, jailbreaks, system prompt exposure |
| `ToolPoisoningDetector` | CRITICAL/MEDIUM | ASI01 | Invisible Unicode, sensitive path targeting, override directives, cross-tool manipulation |
| `PathTraversalDetector` | HIGH | ASI09 | `../` sequences, zip slip, taint-tracked `open()` and `os.path.join()`, `readFileSync(userInput)` |
| `ConfigSecurityDetector` | HIGH/MEDIUM | ASI02 | `DEBUG=True`, open CORS, `SSL_VERIFY=False`, weak secrets |
| `SSRFDetector` | CRITICAL/HIGH | ASI05 | Unvalidated URLs in HTTP clients, cloud metadata endpoints (`169.254.169.254`) |
| `NetworkBindingDetector` | MEDIUM | ASI06 | `0.0.0.0` binding in Python, JS, Go, Java, config files |
| `MissingAuthDetector` | HIGH/MEDIUM | ASI04 | Routes without `@login_required`, `Depends(get_current_user)`, or auth middleware |
| `SupplyChainDetector` | CRITICAL/HIGH | ASI03 | Encoded payloads, install-time exec/network, env var exfiltration, typosquatting |
| `WeakCryptoDetector` | HIGH/MEDIUM | ASI07 | MD5/SHA-1, ECB mode, insecure random, deprecated ciphers, static IV, weak KDF |
| `InsecureDeserializationDetector` | CRITICAL | ASI08 | `pickle.loads`, `yaml.load`, `marshal`, `ObjectInputStream`, PHP `unserialize`, Node.js `vm.runInContext` |
| `MCPSamplingDetector` | CRITICAL/HIGH/MEDIUM | ASI10 | Sampling call audit, prompt injection via `create_message`, sensitive data in LLM calls, unconstrained token limits |
| `RugPullDetector` | CRITICAL/HIGH | ASI01 | Global state mutation, first-call sentinel checks, time-based behavior evasion |
| `OAuthFlowDetector` | CRITICAL/HIGH/MEDIUM | ASI04 | CVE-2025-6514 endpoint injection, open redirect via `redirect_uri`, token credential exposure, missing PKCE, implicit grant flow, disabled JWT verification |
| `ContextFloodingDetector` | HIGH/MEDIUM/LOW | ASI06 | Unbounded `read()`, uncapped `os.walk()`, SQL without `LIMIT`, list tools missing pagination parameters |
| `MCPResourcePoisoningDetector` | CRITICAL/HIGH/MEDIUM | ASI01 | Path traversal URIs, sensitive host paths (`.ssh`, `.aws`, `/etc/passwd`), wildcard subscriptions, prompt injection in resource metadata, invisible Unicode, env var exposure, MIME type confusion |
| `PrototypePollutionDetector` | HIGH | ASI08 | `__proto__` key injection, recursive merge without key guard, `JSON.parse` to unrestricted assign |
| `XXEDetector` | HIGH | ASI05 | `<!ENTITY SYSTEM` declarations, unsafe XML parsers, `DOMParser`/`xml2js` without `noent: false` |
| `ReDoSDetector` | HIGH | ASI06 | Nested quantifier patterns `(a+)+`, `(\w+)*`, `(a|b)+$` on user-controlled input |

### Severity calibration

After all detectors run, findings are adjusted based on server context signals detected
from `mcp.json`, `package.json`, or similar config files:

- **Filesystem/network access declared** → `CODE_INJECTION`, `PATH_TRAVERSAL`, `SSRF`, `MCP_SAMPLING` elevated one step
- **Sensitive tools** (`rm`, `delete`, `shell`, `sudo`) → `PATH_TRAVERSAL`, `CODE_INJECTION` elevated one step
- **STDIO transport** → all findings annotated with a privilege-level context note

---

---

## `baseline` command

The `baseline` command fingerprints every MCP tool definition in a directory so you can detect **rug-pull attacks** — silent changes to tool names, descriptions, or input schemas after initial deployment.

```
mcp-sentinel baseline [TARGET] [OPTIONS]
```

Each tool is identified by `(name, source_file)` and hashed with SHA-256 over its canonical `{name, description, inputSchema}` JSON. Baselines are stored as `.sentinel/baseline.json` inside the target directory.

### Create a baseline

```bash
# First run — creates .sentinel/baseline.json
mcp-sentinel baseline /path/to/mcp-server
```

### Detect drift

```bash
# Subsequent runs — compares current tool definitions against the saved baseline
mcp-sentinel baseline /path/to/mcp-server
```

Output shows:
- **ADDED** — tools present now but not in the baseline
- **REMOVED** — tools in the baseline that no longer exist (exit code 1)
- **MODIFIED** — tools whose description or schema changed since baseline (exit code 1)

Exit code 1 on `REMOVED` or `MODIFIED` tools makes it easy to fail CI on unexpected changes.

### Accept changes

```bash
# Update the baseline to reflect intentional changes (exit code always 0)
mcp-sentinel baseline /path/to/mcp-server --update
```

### Options

| Option | Description |
|---|---|
| `--update` | Accept current tool definitions as the new baseline (no drift alert) |
| `--baseline-file PATH` | Override the default `.sentinel/baseline.json` path |

### CI integration

```yaml
- name: Detect rug-pull
  run: mcp-sentinel baseline . --baseline-file .sentinel/baseline.json
```

Commit `.sentinel/baseline.json` to your repository. The `baseline diff` step in CI will exit 1 if any tool definition changes without an explicit `--update` commit.

---

## See also

- [QUICKSTART.md](../QUICKSTART.md) — install and first scan in 2 minutes
- [README.md](../README.md) — full detector documentation with pattern tables
- [ARCHITECTURE.md](ARCHITECTURE.md) — module structure, scan pipeline, detector reference
