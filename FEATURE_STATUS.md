# Feature Status

**Version:** v0.5.0
**Date:** March 2026
**Tests:** 571 passed, 0 xfailed, 0 failed

---

## Active Detectors

| Detector | Status | Patterns | Languages | OWASP ASI |
|---|---|---|---|---|
| `SecretsDetector` | Production | 15+ secret types | All | ASI02 |
| `CodeInjectionDetector` | Production | 9 patterns + stdlib AST | Python, JS/TS, Go, Java | ASI04 |
| `PromptInjectionDetector` | Production | 30+ patterns across 4 families | All | ASI01 |
| `ToolPoisoningDetector` | Production | 10 patterns + 17 Unicode types | All | ASI01 |
| `PathTraversalDetector` | Production | 5 patterns + lightweight taint | All | ASI09 |
| `ConfigSecurityDetector` | Production | 8 patterns | Python, JS, YAML, JSON | ASI02 |
| `SSRFDetector` | Production | 6 patterns | Python, JS/TS, Go, Java | ASI05 |
| `NetworkBindingDetector` | Production | 5 patterns | Python, JS, Go, Java, Config | ASI06 |
| `MissingAuthDetector` | Production | 5 patterns + lookback/lookahead | Python, JS | ASI04 |
| `SupplyChainDetector` | Production | 7 pattern categories | Python, JS | ASI03 |
| `WeakCryptoDetector` | Production | 6 pattern categories | Python, JS, Java | ASI07 |
| `InsecureDeserializationDetector` | Production | 9 patterns | Python, Java, PHP, Node.js | ASI08 |
| `MCPSamplingDetector` | Production | 4 pattern categories | Python, JS/TS | ASI10 |

## Output Formats

| Format | Status | Use case |
|---|---|---|
| Terminal | Production | Human review |
| JSON | Production | Structured export, tooling |
| SARIF 2.1.0 | Production | GitHub/GitLab/Azure Code Scanning |

## New in v0.5.0

| Feature | Details |
|---|---|
| OWASP ASI annotations | All findings carry `owasp_asi_id`/`owasp_asi_name` (ASI01–ASI10); SARIF includes compliance summary |
| `MCPSamplingDetector` | Detects prompt injection, sensitive data, and unconstrained limits in MCP sampling calls |
| Lightweight taint analysis | `PathTraversalDetector` tracks `request.args` → `open()` / `path.join()` across lines in Python, JS, Java |

## Known Limitations

| Limitation | Reason | Planned fix |
|---|---|---|
| Multi-hop taint (> 1 derived variable) | Complex def-use chains across function boundaries | v0.6 inter-procedural analysis |
| Rug pull detection | Runtime behavior — not static | v0.6 structural signals |

## Removed Features

See `UNUSED_CODE.md` for the full list with rationale. Summary:

| Removed | Reason |
|---|---|
| AI engine (Claude/GPT-4/Gemini) | Exfiltrates source code to external APIs |
| SAST engine (Semgrep/Bandit) | External binary dependencies |
| Semantic/CFG engine | Over-engineered; stdlib AST covers critical cases |
| RAG system (ChromaDB) | Only served the removed AI engine |
| `fix` command | Automated source code modification is too dangerous |
| HTML reports | Unnecessary dependency surface |
| XSS detector | Generic web vuln; low signal for MCP servers |
| API server | Out of scope for a CLI tool |
| Enterprise integrations | Out of scope |
