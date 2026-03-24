# Feature Status

**Version:** v0.4.1
**Date:** March 2026
**Tests:** 525 passed, 4 xfailed, 0 failed

---

## Active Detectors

| Detector | Status | Patterns | Languages |
|---|---|---|---|
| `SecretsDetector` | Production | 15+ secret types | All |
| `CodeInjectionDetector` | Production | 9 patterns + stdlib AST | Python, JS/TS, Go, Java |
| `PromptInjectionDetector` | Production | 30+ patterns across 4 families | All |
| `ToolPoisoningDetector` | Production | 10 patterns + 17 Unicode types | All |
| `PathTraversalDetector` | Production | 5 patterns | All |
| `ConfigSecurityDetector` | Production | 8 patterns | Python, JS, YAML, JSON |
| `SSRFDetector` | Production | 6 patterns | Python, JS/TS, Go, Java |
| `NetworkBindingDetector` | Production | 5 patterns | Python, JS, Go, Java, Config |
| `MissingAuthDetector` | Production | 5 patterns + lookback/lookahead | Python, JS |
| `SupplyChainDetector` | Production | 7 pattern categories | Python, JS |
| `WeakCryptoDetector` | Production | 6 pattern categories | Python, JS, Java |
| `InsecureDeserializationDetector` | Production | 9 patterns | Python, Java, PHP, Node.js |

## Output Formats

| Format | Status | Use case |
|---|---|---|
| Terminal | Production | Human review |
| JSON | Production | Structured export, tooling |
| SARIF 2.1.0 | Production | GitHub/GitLab/Azure Code Scanning |

## Known Limitations

| Limitation | Reason | Planned fix |
|---|---|---|
| Multi-line taint (variable-to-sink across lines) | Requires semantic analysis | v0.5 lightweight taint |
| Rug pull detection | Runtime behavior — not static | v0.5 structural signals |

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
