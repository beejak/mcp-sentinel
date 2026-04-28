# Reporting, architecture, and scan workflows

This document describes how MCP Sentinel turns a **codebase** into **actionable reports**, how that relates to **transport layers** (stdio vs network MCP), and where **optional lab-style dynamic probing** fits.

---

## System context

```mermaid
flowchart LR
  subgraph UsersAndAutomation["Users / CI"]
    Dev["Developer"]
    CI["CI pipeline"]
  end

  subgraph MCPSentinel["MCP Sentinel"]
    CLI["mcp-sentinel scan"]
    MES["MultiEngineScanner"]
    Static["StaticAnalysisEngine"]
    SAST["SASTEngine"]
    Reports["Report generators\n(JSON / SARIF / HTML / PDF / incident MD)"]
  end

  subgraph TargetRepo["Target MCP server repo"]
    Src["Source tree"]
    MCPConf["MCP JSON configs\n(mcp.json / Claude config snippets)"]
  end

  subgraph OptionalLab["Optional: runtime lab probes"]
    LabStdio["stdio MCP client probe"]
    LabHTTP["HTTP/SSE MCP client probe"]
  end

  Dev --> CLI
  CI --> CLI
  CLI --> MES
  MES --> Static
  MES --> SAST
  Static --> Reports
  SAST --> Reports
  Src --> MES
  MCPConf --> MES
  CLI -. "separate process, not part of core CLI today" .-> LabStdio
  CLI -. "separate process, not part of core CLI today" .-> LabHTTP
```

**Important:** The shipped **`mcp-sentinel scan`** command analyzes files on disk (static + SAST). **Runtime/dynamic** exercises (starting the real server and calling tools over MCP) are **optional lab workflows** that live outside the core scanner unless you explicitly wire them.

---

## Logical network: MCP transports (reference)

This is not “MCP Sentinel networking,” but the **target server’s** exposure model when you later probe it dynamically:

```mermaid
flowchart TB
  subgraph Local["Same machine"]
    ClientA["MCP client\n(IDE / inspector / script)"]
    ServerStdio["MCP server process\nstdio transport"]
    ClientA <-->|"stdin/stdout JSON-RPC"| ServerStdio
  end

  subgraph Loopback["Loopback HTTP"]
    ClientB["MCP client"]
    ServerHTTP["MCP server\nHTTP + SSE or streamable HTTP"]
    ClientB <-->|"http://127.0.0.1:<port>/..."| ServerHTTP
  end

  subgraph RiskNote["Threat-model note"]
    N["Binding to 127.0.0.1 reduces LAN exposure;\nallowlists / auth still matter for localhost attackers."]
  end
```

---

## Internal scan workflow (what `scan` does)

```mermaid
flowchart TD
  A["CLI: parse engines & options"] --> B["MultiEngineScanner.scan_directory"]
  B --> C["Static: detectors on files"]
  B --> D["SAST: Semgrep/Bandit when available"]
  C --> E["Merge + dedupe vulnerabilities"]
  D --> E
  E --> F["Optional: VulnerableMCP threat-intel enrich"]
  E --> G["Optional: MCP tool-definition baseline diff"]
  G --> H["Emit reports"]
  H --> I["Terminal / JSON / SARIF / HTML / PDF"]
  H --> J["Incident summary markdown\n(default: critical / code-injection / exploit-style heuristics)"]
```

### Incident summary (default-on)

After findings exist, the CLI can write **`\<primary-report-stem\>-incidents.md`** (when `--json-file` is used) or a path you choose via **`--incident-file`**.

---

## Reporting outputs (today)

| Output | Role |
|--------|------|
| JSON | Full machine-readable results; integrates with CI and dashboards |
| SARIF | GitHub Code Scanning and SARIF consumers |
| HTML | Interactive drill-down |
| PDF | Short executive table (truncated rows) |
| Incident MD | **Triage-focused** list for critical / code injection / exploit-style indicators |

---

## Relationship: “static scan” vs “dynamic test”

| Layer | What runs | In core CLI? |
|-------|-----------|----------------|
| Static analysis | Pattern detectors on source | Yes (`static` engine) |
| SAST | Semgrep / Bandit | Yes (`sast` engine) |
| Threat intel | Feed enrichment after scan | Yes (optional network) |
| Dynamic MCP probe | Launch server, `initialize`, `list_tools`, optional `call_tool` | **No** (lab scripts / inspector); not merged into `scan` yet |

---

## CLI flags referenced elsewhere

- **`--incident-summary` / `--no-incident-summary`** — turn the incident markdown on or off (default: **on**).
- **`--incident-file PATH`** — explicit output path for the incident summary.

These are **overrides**: they change default behavior without editing code.
