# MCP Sentinel — Configuration Guide

**Version**: v0.2.0

MCP Sentinel is configured entirely through environment variables. There is no config file required — sane defaults work out of the box.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ENABLE_STATIC_ANALYSIS` | `true` | Enable the static pattern-matching engine |
| `LOG_LEVEL` | `info` | Logging verbosity: `debug`, `info`, `warning`, `error` |
| `MAX_WORKERS` | `4` | Number of concurrent file scanning workers |
| `CACHE_TTL` | `3600` | File result cache TTL in seconds (0 = disabled) |
| `ENVIRONMENT` | `development` | Runtime environment: `development`, `production`, `testing` |

That's it. MCP Sentinel v0.2.0 is a local CLI tool — no database, no API server, no external services, no AI provider keys required.

---

## Setting Variables

### Shell / `.env` file

```bash
export LOG_LEVEL=debug
export MAX_WORKERS=8
export CACHE_TTL=0  # disable caching during development
```

Or in a `.env` file in the project root (loaded automatically):

```bash
ENABLE_STATIC_ANALYSIS=true
LOG_LEVEL=info
MAX_WORKERS=4
CACHE_TTL=3600
ENVIRONMENT=production
```

### CI/CD pipelines

Set as pipeline environment variables. Example (GitHub Actions):

```yaml
env:
  LOG_LEVEL: warning
  MAX_WORKERS: 8
```

---

## CLI Flags

Environment variables set defaults. CLI flags override them per-run:

```
mcp-sentinel scan <target> [OPTIONS]

Options:
  --output [terminal|json|sarif]  Output format (default: terminal)
  --json-file <path>              Write JSON or SARIF output to this file
  --severity [critical|high|medium|low|info]
                                  Filter findings by minimum severity
  --no-progress                   Suppress progress bar (useful in CI)
  --log-level [debug|info|warning|error]
                                  Override LOG_LEVEL for this run
  --log-file <path>               Write logs to file in addition to stderr
```

---

## Variable Details

### `ENABLE_STATIC_ANALYSIS`

Controls whether the static analysis engine runs. Setting to `false` disables all scanning — useful for testing the CLI itself without running detectors.

```bash
ENABLE_STATIC_ANALYSIS=false mcp-sentinel scan .   # no findings, instant
```

### `LOG_LEVEL`

Controls verbosity of log output to stderr.

- `debug` — full internal trace, file-by-file processing
- `info` — scan progress and summary (default)
- `warning` — only warnings and errors
- `error` — only errors

### `MAX_WORKERS`

Number of files processed concurrently. Increasing this speeds up scans on large codebases but uses more memory.

Recommended values:
- Laptop/desktop: `4` (default)
- CI runner (2-core): `4`
- CI runner (8-core): `8–16`

### `CACHE_TTL`

MCP Sentinel caches scan results per file using an MD5 hash of file content. If a file hasn't changed since the last scan, its cached result is reused.

- `0` — disable cache entirely
- `3600` — cache results for 1 hour (default)
- `86400` — cache results for 24 hours

Cache is stored in `.sentinel/cache.json` relative to the working directory.

### `ENVIRONMENT`

Affects log formatting:

- `development` — human-readable log lines
- `production` — structured JSON log lines (better for log aggregators)
- `testing` — minimal output
