# MCP Sentinel

**Repository:** [github.com/beejak/mcp-sentinel](https://github.com/beejak/mcp-sentinel)

Security scanner for [Model Context Protocol (MCP)](https://modelcontextprotocol.io) **server source code**: static pattern analysis, optional SAST (Semgrep, Bandit), and reports (terminal, JSON, SARIF, HTML).

| | |
|---|---|
| **Implementation** | Python package in [`mcp-sentinel-python/`](mcp-sentinel-python/README.md) (primary) |
| **Version** | See `mcp_sentinel.__version__` in the Python package (e.g. 3.x) |
| **License** | See [LICENSE](LICENSE) in this repository |

## Quick start

```bash
cd mcp-sentinel-python
pip install -e .
mcp-sentinel scan /path/to/mcp-server-repo --engines static --output html --json-file report.html
```

- **Critical findings:** the CLI writes the report, then exits **1** for CI unless you pass **`--no-fail-on-critical`** (see Python README).
- **Rust/Cargo tree:** earlier Rust prototypes were removed; **this repo’s maintained scanner is the Python package**.

## Documentation

| Doc | Purpose |
|-----|---------|
| [`mcp-sentinel-python/README.md`](mcp-sentinel-python/README.md) | Install, CLI, detectors, roadmap, complementary tools |
| [`mcp-sentinel-python/docs/README.md`](mcp-sentinel-python/docs/README.md) | Doc index |
| [`LESSONS_LEARNED.md`](LESSONS_LEARNED.md) | Running log of engineering decisions and releases |

## Related (same maintainer)

Complementary scanners and samples are linked from the Python README (e.g. container image scanning, Rust second-opinion CLI, vulnerable MCP lab).

## Contributing

Use [`mcp-sentinel-python/docs/CONTRIBUTING.md`](mcp-sentinel-python/docs/CONTRIBUTING.md) if present, or open an issue/PR on **beejak/mcp-sentinel**.
