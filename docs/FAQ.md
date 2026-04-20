# MCP Sentinel — FAQ

**Version**: v0.3.0

---

## General

**Q: What is MCP Sentinel?**

A: MCP Sentinel is a static security scanner for MCP (Model Context Protocol) servers. It uses pattern-matching across 10 specialized detectors to find vulnerabilities in Python, JavaScript, TypeScript, Go, Java, PHP, and config files. It runs entirely locally — no network calls, no API keys required.

**Q: How does it differ from Bandit or Semgrep?**

A: Bandit is Python-only. Semgrep is general-purpose. MCP Sentinel is purpose-built for the MCP ecosystem — it knows about MCP tool schemas, tool poisoning patterns, prompt injection in tool descriptions, missing authentication on MCP endpoints, and other attack vectors specific to MCP servers. It also supports multiple languages in a single scan.

**Q: Does it use AI?**

A: No. v0.2.0 is purely static pattern-matching — no LLM calls, no API keys, no network access. This makes it fast, free to run, and suitable for air-gapped environments.

**Q: What languages does it support?**

A: Python, JavaScript, TypeScript, Go, Java, PHP, and configuration files (YAML, JSON, `.env`, Dockerfile, nginx.conf).

---

## Usage

**Q: Can I scan a single file?**

A: Yes:
```bash
mcp-sentinel scan /path/to/file.py
```

**Q: How do I scan a directory?**

A: Pass the directory path:
```bash
mcp-sentinel scan /path/to/my-mcp-server
```

**Q: How do I get JSON output?**

A: Use `--output json` with `--json-file`:
```bash
mcp-sentinel scan . --output json --json-file results.json
```

**Q: How do I integrate with GitHub Code Scanning?**

A: Use SARIF output:
```bash
mcp-sentinel scan . --output sarif --json-file results.sarif
```
Then upload via `github/codeql-action/upload-sarif@v3`. See `docs/CI_CD_INTEGRATION.md` for the full workflow.

**Q: How do I filter by severity?**

A: Use `--severity`:
```bash
mcp-sentinel scan . --severity critical    # only critical
mcp-sentinel scan . --severity high        # high and above
```

**Q: Why is the scan slow?**

A: A few common reasons:
- Scanning `node_modules`, `.venv`, or `__pycache__` — add them to `.sentinelignore`
- Very large files — these are processed fully
- `MAX_WORKERS` is low — try `MAX_WORKERS=8 mcp-sentinel scan .`
- Caching is disabled — check `CACHE_TTL` (default 3600s)

**Q: What is `.sentinelignore`?**

A: A `.gitignore`-style file at the root of your project. Any paths listed are skipped during scanning. Useful for excluding vendored code, generated files, and test fixtures.

---

## Detectors

**Q: What detectors are included in v0.3.0?**

A: Ten detectors:

| Detector | What It Finds |
|---|---|
| `SecretsDetector` | API keys, tokens, private keys, database URLs |
| `CodeInjectionDetector` | `eval`, `exec`, `os.system`, `subprocess` with `shell=True` |
| `PromptInjectionDetector` | Role manipulation, jailbreak patterns, system prompt injection |
| `ToolPoisoningDetector` | Invisible unicode, cross-tool instructions, hidden file references in MCP tool schemas |
| `PathTraversalDetector` | `../` sequences, unsafe archive extraction, unvalidated file paths |
| `ConfigSecurityDetector` | Debug mode, wildcard CORS, weak TLS, insecure cookies, rate limiting disabled |
| `SSRFDetector` | HTTP calls with user-controlled URLs, cloud metadata endpoint access |
| `NetworkBindingDetector` | Services binding to `0.0.0.0` instead of `127.0.0.1` |
| `MissingAuthDetector` | Sensitive routes/tools exposed without authentication middleware |
| `SupplyChainDetector` | Encoded payloads, install-time shell/network exec, env var exfiltration, silent BCC, dependency confusion, typosquatted packages |

**Q: Can I disable a specific detector?**

A: Not via CLI flags in v0.3.0. All 10 detectors run on every scan. Per-detector configuration is on the roadmap for a future release.

---

## Troubleshooting

**Q: "Command not found: mcp-sentinel"**

A: The package isn't installed or isn't on your PATH. Fix:
```bash
pip install -e .
# or
pip install mcp-sentinel
```
If using a virtualenv, make sure it's activated.

**Q: "No such file or directory"**

A: The scan target doesn't exist. Check the path:
```bash
mcp-sentinel scan /correct/path/to/server
```

**Q: The scan finds no issues but I know there are secrets in the code**

A: Check that:
1. The file extension is supported (`.py`, `.js`, `.ts`, `.go`, `.java`, `.env`, `.json`, `.yaml`)
2. The file isn't excluded by `.sentinelignore`
3. The secret pattern matches — run with `LOG_LEVEL=debug` to see which files are being scanned

**Q: I'm getting false positives**

A: Use `--severity` to filter noise, or add the specific file to `.sentinelignore`. False positive reports are welcome as GitHub issues.

**Q: How do I report a bug?**

A: Open an issue on GitHub with:
- The command you ran
- The output with `LOG_LEVEL=debug`
- A minimal reproducing example (redact any real secrets)
