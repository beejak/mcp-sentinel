# Quick Start

## Install

```bash
git clone https://github.com/beejak/mcp-sentinel.git
cd mcp-sentinel
pip install -e .
```

Verify:
```bash
mcp-sentinel --version
```

## Scan

```bash
# Scan current directory
mcp-sentinel scan .

# Scan a specific path
mcp-sentinel scan /path/to/your/mcp-server

# Filter to critical and high only
mcp-sentinel scan . --severity critical --severity high

# Suppress progress bar (good for CI)
mcp-sentinel scan . --no-progress
```

## Export Results

**JSON:**
```bash
mcp-sentinel scan . --output json --json-file results.json
```

**SARIF (GitHub Code Scanning):**
```bash
mcp-sentinel scan . --output sarif --json-file results.sarif
```

**GitHub Actions:**
```yaml
- name: MCP Sentinel Scan
  run: mcp-sentinel scan . --output sarif --json-file results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## What Gets Detected

| Detector | What it catches |
|---|---|
| `SecretsDetector` | Hardcoded AWS keys, API keys, tokens, private keys, DB URLs |
| `CodeInjectionDetector` | `os.system`, `subprocess(shell=True)`, `eval`, `exec`, SQL f-strings |
| `PromptInjectionDetector` | Role manipulation, jailbreaks, system prompt exposure |
| `ToolPoisoningDetector` | Invisible Unicode, override directives, sensitive path targeting |
| `PathTraversalDetector` | `../` sequences, zip slip, unsafe `open()` |
| `ConfigSecurityDetector` | `DEBUG=True`, open CORS, `SSL_VERIFY=False`, weak secrets |
| `SSRFDetector` | Unvalidated URL vars in HTTP clients, cloud metadata endpoints |
| `NetworkBindingDetector` | Servers bound to `0.0.0.0` instead of `127.0.0.1` |
| `MissingAuthDetector` | Routes and endpoints without authentication |
| `SupplyChainDetector` | Encoded payloads, install-time exec/network, covert exfiltration |
| `WeakCryptoDetector` | MD5/SHA-1, insecure random, ECB mode, deprecated ciphers |
| `InsecureDeserializationDetector` | `pickle.loads`, `yaml.load`, `ObjectInputStream`, PHP `unserialize` |

## Troubleshooting

**`No module named 'mcp_sentinel'`** — run `pip install -e .` from the repo root.

**Scan is slow** — use `--no-progress` in CI; scan runs async but progress display adds overhead on large repos.

## Full CLI Reference

```
mcp-sentinel [--log-level LEVEL] [--log-file PATH] [--version] COMMAND

Commands:
  scan    Scan a directory or file for security vulnerabilities

mcp-sentinel scan [TARGET] [OPTIONS]

  TARGET                Path to scan (prompts if omitted)

  -o, --output          terminal | json | sarif  (default: terminal)
  --severity            critical | high | medium | low | info (repeatable)
  --json-file PATH      Output file for json/sarif
  --no-progress         Disable progress bar
  --log-level           DEBUG | INFO | WARN | ERROR | FATAL
  --log-file PATH       Write logs to file
  --version
  --help
```
