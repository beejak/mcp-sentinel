# Phase 2.0 Technical Architecture
## MCP Sentinel Advanced Analysis Engine

**Version**: 2.0.0
**Status**: Implementation in Progress
**Created**: 2025-10-25

---

## System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLI Interface                             │
│  (scan, init, baseline, suppress, analyze commands)             │
└───────────────────┬─────────────────────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────────────────────┐
│                   Orchestration Layer                            │
│  - Configuration Management                                      │
│  - Baseline Comparison                                           │
│  - Suppression Filtering                                         │
│  - Result Aggregation                                            │
└───────────┬────────────────┬────────────────┬────────────────────┘
            │                │                │
    ┌───────▼──────┐  ┌─────▼──────┐  ┌──────▼────────┐
    │ Static       │  │ Semantic   │  │ AI Analysis   │
    │ Analysis     │  │ Analysis   │  │ Engine        │
    │ (Phase 1)    │  │ (Phase 2)  │  │ (Phase 2)     │
    └──────────────┘  └────────────┘  └───────────────┘
            │                │                │
    ┌───────▼──────┐  ┌─────▼──────┐  ┌──────▼────────┐
    │ Pattern      │  │Tree-sitter │  │  LLM          │
    │ Detectors    │  │ AST Parser │  │  Providers    │
    │ (5 types)    │  │            │  │  (Multi)      │
    └──────────────┘  └────────────┘  └───────────────┘
            │                │                │
            │         ┌──────▼──────┐         │
            │         │  Semgrep    │         │
            │         │  Integration│         │
            │         └─────────────┘         │
            │                                 │
    ┌───────▼─────────────────────────────────▼──────────┐
    │            Result Processing Layer                  │
    │  - Deduplication                                    │
    │  - Severity Scoring                                 │
    │  - CWE/OWASP Mapping                               │
    │  - Confidence Scoring                              │
    └─────────────────────┬───────────────────────────────┘
                          │
    ┌─────────────────────▼───────────────────────────────┐
    │              Output Generation                      │
    │  - Terminal (colored, tables)                       │
    │  - JSON (structured)                                │
    │  - SARIF (GitHub/GitLab)                           │
    │  - HTML (dashboard + charts)                        │
    └─────────────────────────────────────────────────────┘
```

---

## Module Structure

```
src/
├── engines/                    # Analysis engines
│   ├── mod.rs                 # Engine trait definition
│   ├── static_engine.rs       # Phase 1 pattern-based
│   ├── semgrep_engine.rs      # Semgrep integration
│   ├── treesitter_engine.rs   # AST-based analysis
│   └── ai_engine.rs           # LLM-powered analysis
│
├── providers/                  # LLM provider implementations
│   ├── mod.rs                 # Provider trait + factory
│   ├── openai.rs              # OpenAI GPT-3.5/4/4-turbo
│   ├── anthropic.rs           # Claude 3 (Opus/Sonnet/Haiku)
│   ├── ollama.rs              # Local Ollama models
│   ├── mistral.rs             # Mistral AI
│   ├── cohere.rs              # Cohere Command
│   ├── huggingface.rs         # HuggingFace Inference API
│   ├── google.rs              # Google Gemini
│   └── azure.rs               # Azure OpenAI
│
├── analysis/                   # Analysis utilities
│   ├── dataflow.rs            # Dataflow analysis
│   ├── taint.rs               # Taint tracking
│   ├── ast_walker.rs          # AST traversal
│   └── semantic_matcher.rs    # Semantic pattern matching
│
├── storage/                    # Persistence layer
│   ├── baseline.rs            # Baseline management
│   ├── cache.rs               # Result caching
│   └── db.rs                  # Sled database wrapper
│
├── suppression/                # False positive management
│   ├── mod.rs                 # Suppression engine
│   ├── parser.rs              # Parse .mcp-sentinel-ignore
│   ├── matcher.rs             # Match suppressions to findings
│   └── auditor.rs             # Suppression audit logs
│
├── output/                     # Report generators
│   ├── terminal.rs            # Enhanced terminal output
│   ├── json.rs                # JSON output
│   ├── sarif.rs               # SARIF 2.1.0
│   ├── html.rs                # HTML report generator
│   └── templates/             # Handlebars templates
│       ├── report.hbs
│       ├── dashboard.hbs
│       └── partials/
│
├── models/                     # Data models
│   ├── vulnerability.rs       # Enhanced with CWE/OWASP
│   ├── cwe.rs                 # CWE definitions
│   ├── owasp.rs               # OWASP mappings
│   ├── ai_finding.rs          # AI analysis results
│   ├── baseline_diff.rs       # Baseline comparison
│   └── suppression_rule.rs    # Suppression rules
│
├── utils/                      # Utilities
│   ├── git.rs                 # Git integration
│   ├── github.rs              # GitHub URL parsing
│   ├── doc_generator.rs       # Auto-documentation
│   └── logger.rs              # Enhanced logging
│
└── cli/                        # Commands
    ├── scan.rs                # Enhanced scan command
    ├── init.rs                # NEW: Setup wizard
    ├── baseline.rs            # NEW: Baseline management
    ├── suppress.rs            # NEW: Suppression management
    └── analyze.rs             # NEW: Deep AI analysis
```

---

## LLM Provider Architecture

... (content continues identical to original)