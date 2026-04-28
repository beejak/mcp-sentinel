# External scan: `github/github-mcp-server`

**Date:** 2026-04-28  
**Scanner:** MCP Sentinel v3.0.0  
**Target revision:** `main` (shallow clone, depth 1)  
**Engines:** `static`, `sast` (Semgrep reported a parse error during this run; static results are complete in the artifact below.)

## Published artifact (full JSON)

Full structured output (all findings, snippets, statistics):

https://gist.github.com/beejak/c190bcb8f8b76e8b2200faef11e807d6

## Summary statistics

| Metric | Value |
|--------|------:|
| Files scanned | 191 |
| Total findings | 588 |
| Critical | 1 |
| High | 11 |
| Medium | 575 |
| Low | 1 |

### By detector type (top)

| Type | Count | Notes |
|------|------:|-------|
| `supply_chain` | 576 | Dependency / manifest advisories (review in context of your lockfiles and upgrade policy). |
| `xss` | 6 | Mostly JSX `onClick` / `onError` patterns; manual review did not show user-controlled handler injection. |
| `path_traversal` | 5 | Includes `../` in **markdown doc generator** and **Vite config** strings; not user-controlled path joins. |
| `tool_poisoning` | 1 | Matched workflow prose in `.github/workflows/go.yml` (“replace with …”); not runtime MCP tool poisoning. |

## Manual triage (non–supply-chain)

The single **critical** `path_traversal` hit is a **false positive**: it matched `ResolveResourcePath(r *http.Request, …)` in `pkg/http/oauth/oauth.go` because the heuristic treats `Path` in the signature as filesystem path manipulation; the function only normalizes **URL paths** for OAuth metadata routing.

No credible, minimal security patch was identified for an upstream pull request. **`go test ./...`** on the same tree completed successfully (all packages green).

## Reproduce locally

```bash
git clone --depth 1 https://github.com/github/github-mcp-server.git
cd github-mcp-server
mcp-sentinel scan . --engines static,sast --output json --json-file scan.json --no-fail-on-critical
```

Use `--no-fail-on-critical` only when you intentionally want exit code 0 while reviewing reports locally or in a sandbox.

## Upstream pull request

**None opened.** Opening a PR would require a concrete, reproducible defect or a clearly scoped hardening change; this pass did not surface one after triage and tests.
