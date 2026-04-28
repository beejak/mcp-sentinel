# External scan: `modelcontextprotocol/servers` → **`src/filesystem`** only

**Date:** 2026-04-28  
**Scanner:** MCP Sentinel v3.0.0  
**Upstream catalog:** Official reference servers listed in [`modelcontextprotocol/servers` README](https://github.com/modelcontextprotocol/servers/blob/main/README.md) (repository ~84k★ on GitHub; stars apply to the **whole** repo, not an individual folder).  

**Selection:** **`src/filesystem`** — MCP server that exposes constrained file operations (path validation and sandboxing are the interesting security surface). Only this directory was cloned and scanned, not the entire monorepo.

## What “subfolder scan” means

Scanning **`servers/src/filesystem`** instead of all of **`servers`** means:

- You **reuse the official catalog** to pick a concrete server (from the README’s “Reference Servers” table).
- You **avoid** pulling thousands of files across unrelated packages (`everything`, `fetch`, `git`, …).
- Reports stay **focused** on one threat model (here: filesystem access from tools).

Technically this run used a **sparse Git checkout** so only `src/filesystem` exists on disk under a shallow clone of `modelcontextprotocol/servers`.

## Published artifact (full JSON)

https://gist.github.com/beejak/235d9793985eef4870d4d4fe221cc6fe

## Engines requested vs what ran

CLI flags requested **`static,sast,semantic`**.

In the current MCP Sentinel codebase, **`MultiEngineScanner` only wires `StaticAnalysisEngine` and `SASTEngine`**. Semantic and AI engines are noted as future phases and are **not** attached when you pass `--engines semantic` or `--engines ai`, so those names do not add analyzers yet.

**Effective engines:** **static** (pattern detectors) plus **SAST** where Semgrep/Bandit succeed.

On this host, Semgrep integration printed **`Failed to parse Semgrep output`** (empty or non-JSON stdout), so **no Semgrep findings** were merged; Bandit targets Python only, so it contributed nothing under this TypeScript tree.

Net: **static-only signal** for this TypeScript snapshot.

## Summary statistics (from JSON)

| Metric | Value |
|--------|------:|
| Files scanned | 15 |
| Total findings | 21 |
| Critical | 9 |
| High | 10 |
| Medium | 1 |
| Low | 1 |

### By type

| Type | Count | Notes |
|------|------:|-------|
| `path_traversal` | 16 | Almost all in **`__tests__`** — intentional `../` and manipulation strings used to **test** validation. |
| `tool_poisoning` | 2 | Matched Zod `.describe("… replace with …")` and prose in `index.ts` — **documentation strings**, not runtime overrides. |
| `supply_chain` | 2 | Manifest / dependency advisories (review with your upgrade policy). |
| `prompt_injection` | 1 | Hit in **`path-validation.test.ts`** test content — not production MCP behavior. |

## Reproduce

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/modelcontextprotocol/servers.git
cd servers
git sparse-checkout set src/filesystem
cd src/filesystem
mcp-sentinel scan . --engines static,sast --output json --json-file scan.json --no-fail-on-critical
```

Prefer **`static,sast`** until semantic analysis is wired in the scanner.

## Next steps for a genuinely “multi-layer” scrub

1. **Fix Semgrep** on the runner (ensure `semgrep` prints JSON and MCP Sentinel parses it) so **SAST** contributes TypeScript/JavaScript rules.  
2. **Implement or wire `SemanticAnalysisEngine`** when Phase 4.2 lands — then `--engines semantic` will mean something in results.  
3. Optional: **`--engines ai`** only when LLM/API configuration is intended for your environment.
