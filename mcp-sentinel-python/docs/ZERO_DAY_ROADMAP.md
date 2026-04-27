# Zero-day detection roadmap (public)

This document describes how **MCP Sentinel** intends to evolve **beyond signature-based scanning** toward **behavioral / anomaly signals** that can highlight *unknown* or *novel* risk—often grouped under “zero-day style” detection in product language. It is the **public, reader-friendly** companion to the deeper strategic notes in [`SECURITY_ANALYSIS_AND_ROADMAP.md`](../../SECURITY_ANALYSIS_AND_ROADMAP.md) at the repository root.

---

## What you get today

The maintained scanner is the **Python package** under `mcp-sentinel-python/`:

| Layer | Role |
|-------|------|
| **Static engine** | Pattern-based detectors (secrets, prompt/tool issues, path traversal, XSS, config problems, prototype pollution heuristics, etc.). |
| **SAST engine** | Semgrep + Bandit where available (multi-engine scans). |
| **Threat intel** | Optional enrichment against curated MCP vulnerability data (e.g. **VulnerableMCP** JSON feed—see main README). |

These layers excel at **known patterns**, **manifest and config mistakes**, and **correlation with public advisories**. They are **not** a substitute for runtime monitoring of live MCP sessions.

---

## What “zero-day detection” means here

In this project, **zero-day detection** does **not** mean “magic CVE prediction.” It means:

1. **Baseline + deviation** — Learn what “normal” looks like for a codebase or organization (complexity, dependency churn, tool surfaces), then surface **unusual** combinations that warrant review.
2. **Behavioral scoring** — Attach a **confidence / anomaly score** to findings or whole scans so teams can triage **novel** clusters without hiding them behind binary rules.
3. **Optional feedback loop** — With explicit opt-in, learn from labeled true/false positives to reduce noise over time (privacy-preserving design is a requirement, not an afterthought).

Runtime capture of MCP traffic (proxy, session recording) is a **separate** track (see **Phase 3.0** in the strategic doc): static “zero-day” scoring and runtime monitoring **complement** each other.

---

## Planned capabilities (Phase 2.6 target — subject to reprioritization)

Aligned with [`SECURITY_ANALYSIS_AND_ROADMAP.md` § Phase 2.6](../../SECURITY_ANALYSIS_AND_ROADMAP.md#phase-26-roadmap):

| Milestone | Intent | Notes |
|-----------|--------|--------|
| **Behavioral feature extraction** | Summarize scan outputs (complexity proxies, dependency deltas, sensitive API usage density, etc.). | Feed for anomaly models; must stay explainable. |
| **Anomaly scoring** | Unsupervised or semi-supervised scoring (e.g. isolation forest–class ideas in the roadmap). | Delivers a **score**, not only pass/fail. |
| **CLI integration** | A dedicated switch (roadmap name: `--enable-zero-day`) to opt into heavier analysis. | Off by default until quality bars are met. |
| **Report surfacing** | Zero-day / anomaly confidence in JSON, SARIF, or HTML where applicable. | Clear labeling so it is not confused with CVE-backed rules. |

**Dependencies:** lightweight ML or statistical stack (exact library TBD), evaluation harness, and **benchmark** datasets to avoid shipping a black box.

---

## Explicitly out of scope for this roadmap note

| Topic | Where it lives |
|-------|----------------|
| **Full inter-procedural taint / IFDS** for JS/TS merge sinks | **Parked** until semantic/dataflow milestones land—see **“Parked — inter-procedural taint”** in [`SECURITY_ANALYSIS_AND_ROADMAP.md`](../../SECURITY_ANALYSIS_AND_ROADMAP.md). |
| **Live MCP proxy / policy enforcement** | **Phase 3.0** vision in the same strategic doc. |
| **Guaranteed detection of unpublished CVEs** | Not promised; scoring is **risk prioritization**, not oracle behavior. |

---

## How we will ship responsibly

1. **Feature flag** — Experimental paths stay behind CLI/config flags until precision/recall targets are documented.
2. **Transparency** — Reports will distinguish **rule-based** findings from **behavioral / anomaly** signals.
3. **Telemetry** — Any learning loop is **opt-in** and documented (no silent exfiltration of customer code).

---

## Tracking progress

- **Strategic detail & history:** [`SECURITY_ANALYSIS_AND_ROADMAP.md`](../../SECURITY_ANALYSIS_AND_ROADMAP.md)
- **Implementation:** Watch milestones and issues on **[github.com/beejak/mcp-sentinel](https://github.com/beejak/mcp-sentinel)** (Python package path: `mcp-sentinel-python/`).

*Last reviewed with the “Quick wins” batch that shipped VulnerableMCP JSON enrichment; refresh this file when zero-day milestones close or scope changes.*
