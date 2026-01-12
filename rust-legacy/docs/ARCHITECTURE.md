# MCP Sentinel - System Architecture
## Phase 2.0 - AI Intelligence & Workflow

**Version**: 2.0.0
**Date**: 2025-10-26
**Status**: Production Ready

---

## Table of Contents

1. [System Overview](#system-overview)
2. [High-Level Architecture](#high-level-architecture)
3. [Component Architecture](#component-architecture)
4. [Data Flow Diagrams](#data-flow-diagrams)
5. [Network Architecture](#network-architecture)
6. [Security Architecture](#security-architecture)
7. [Performance Architecture](#performance-architecture)
8. [Deployment Architecture](#deployment-architecture)

---

## System Overview

### Purpose

MCP Sentinel is a comprehensive security scanner for Model Context Protocol (MCP) servers that combines:
- **Static Analysis**: Pattern-based vulnerability detection
- **AI Analysis**: LLM-powered contextual security assessment
- **Performance Optimization**: Intelligent caching and diff-aware scanning
- **Compliance Tracking**: Baseline comparison and suppression management

### Key Design Principles

1. **Modularity**: Components are loosely coupled and independently testable
2. **Extensibility**: New providers and detectors can be added without core changes
3. **Performance**: Caching and incremental scanning for 10-100x speedups
4. **Privacy**: Local-first AI with optional cloud providers
5. **Cost Control**: Budget tracking and provider fallbacks prevent overspending

### Technology Stack

```
┌─────────────────────────────────────────────────┐
│               MCP Sentinel                      │
├─────────────────────────────────────────────────┤
│ Language: Rust 1.70+                            │
│ Runtime: Tokio (async)                          │
│ CLI: Clap 4.x                                   │
│ Database: Sled (embedded)                       │
│ Serialization: Serde (JSON/YAML/Bincode)       │
│ HTTP: Reqwest + async-openai                   │
│ Git: git2 (libgit2 bindings)                   │
│ Compression: flate2 (gzip)                     │
│ Logging: tracing + tracing-subscriber          │
└─────────────────────────────────────────────────┘
```

---

## High-Level Architecture

### System Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                         MCP SENTINEL SYSTEM                          │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │                    CLI Interface Layer                       │   │
│  │  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐        │   │
│  │  │ scan │  │ init │  │audit │  │proxy │  │monitor│        │   │
│  │  └──────┘  └──────┘  └──────┘  └──────┘  └──────┘        │   │
│  └────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │                  Core Engine Layer                          │   │
│  │                                                             │   │
│  │  ┌─────────────────┐  ┌─────────────────┐                │   │
│  │  │ Static Analysis │  │  AI Analysis    │                │   │
│  │  │     Engine      │  │     Engine      │                │   │
│  │  └─────────────────┘  └─────────────────┘                │   │
│  │           │                     │                          │   │
│  │  ┌────────▼─────────────────────▼──────────┐            │   │
│  │  │     Scanner Orchestrator                 │            │   │
│  │  │  - File Discovery                        │            │   │
│  │  │  - Detector Dispatch                     │            │   │
│  │  │  - Result Aggregation                    │            │   │
│  │  └──────────────────────────────────────────┘            │   │
│  └────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │                  Provider Layer                             │   │
│  │                                                             │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐     │   │
│  │  │ OpenAI  │  │Anthropic│  │ Gemini  │  │ Ollama  │     │   │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘     │   │
│  │       │             │             │             │          │   │
│  │       └─────────────┴─────────────┴─────────────┘          │   │
│  │                         │                                   │   │
│  │              ┌──────────▼──────────┐                       │   │
│  │              │  Provider Registry  │                       │   │
│  │              │  - Registration     │                       │   │
│  │              │  - Health Checks    │                       │   │
│  │              │  - Fallback Logic   │                       │   │
│  │              └─────────────────────┘                       │   │
│  └────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │                  Storage Layer                              │   │
│  │                                                             │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │   │
│  │  │Baseline  │  │  Cache   │  │  Audit   │  │  Config  │ │   │
│  │  │ Storage  │  │ (Sled)   │  │   Log    │  │  Files   │ │   │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘ │   │
│  └────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │               Integration Layer                             │   │
│  │                                                             │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐                │   │
│  │  │   Git    │  │   HTTP   │  │  File    │                │   │
│  │  │  (git2)  │  │(reqwest) │  │  System  │                │   │
│  │  └──────────┘  └──────────┘  └──────────┘                │   │
│  └────────────────────────────────────────────────────────────┘   │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### Why This Architecture?

1. **Layered Design**: Clear separation of concerns enables independent testing and evolution
2. **Plugin Architecture**: Providers and detectors can be added/removed without core changes
3. **Async Throughout**: Tokio enables efficient concurrent scanning and API calls
4. **Storage Abstraction**: Sled provides fast embedded database without external dependencies
5. **Integration Layer**: Isolated external dependencies for easier mocking and testing

---

## Component Architecture

### 1. CLI Interface Layer

**Purpose**: User interaction and command routing

```
┌─────────────────────────────────────────────────┐
│              CLI Commands                       │
├─────────────────────────────────────────────────┤
│                                                 │
│  scan     → Scanner Orchestrator                │
│  init     → Project Setup Wizard                │
│  audit    → Suppression Audit Report            │
│  proxy    → Runtime Proxy (Phase 3)             │
│  monitor  → Continuous Monitoring (Phase 3)     │
│                                                 │
│  Common Flags:                                  │
│  --config       Configuration file              │
│  --output       Output format (json/sarif/term) │
│  --verbose      Debug logging                   │
│  --ai           Enable AI analysis              │
│  --provider     LLM provider selection          │
│  --budget       Cost limit in USD               │
│  --diff         Git diff mode                   │
│  --baseline     Baseline comparison             │
│  --suppress     Suppression file                │
│                                                 │
└─────────────────────────────────────────────────┘
```

**Why Clap?**
- Declarative CLI definition with derive macros
- Automatic help generation
- Type-safe argument parsing
- Built-in validation
- Shell completion support

### 2. Static Analysis Engine

**Purpose**: Pattern-based vulnerability detection

```
┌─────────────────────────────────────────────────┐
│         Static Analysis Engine                  │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌────────────────────────────────────────┐   │
│  │         Detector Registry              │   │
│  │  - Secrets Leakage                     │   │
│  │  - Command Injection                   │   │
│  │  - Sensitive File Access               │   │
│  │  - Tool Poisoning                      │   │
│  │  - Prompt Injection                    │   │
│  │  - MCP Config Security                 │   │
│  └────────────────────────────────────────┘   │
│                │                                │
│  ┌─────────────▼────────────────────────┐     │
│  │      Pattern Matching Engine          │     │
│  │  - Regex patterns                     │     │
│  │  - Tree-sitter AST analysis           │     │
│  │  - Heuristic rules                    │     │
│  └───────────────────────────────────────┘     │
│                │                                │
│  ┌─────────────▼────────────────────────┐     │
│  │      Result Aggregation               │     │
│  │  - Deduplication                      │     │
│  │  - Confidence scoring                 │     │
│  │  - Location tracking                  │     │
│  └───────────────────────────────────────┘     │
│                                                 │
└─────────────────────────────────────────────────┘
```

**Why Tree-sitter?**
- Language-agnostic AST parsing
- Incremental parsing for performance
- Error-tolerant (works with incomplete code)
- Rich query language for pattern matching

### 3. AI Analysis Engine

**Purpose**: LLM-powered contextual vulnerability analysis

```
┌───────────────────────────────────────────────────────────┐
│              AI Analysis Engine                           │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  ┌─────────────────────────────────────────────────┐   │
│  │           Request Manager                        │   │
│  │  ┌────────────┐  ┌────────────┐  ┌───────────┐│   │
│  │  │  Budget    │  │   Rate     │  │  Request  ││   │
│  │  │  Tracker   │  │  Limiter   │  │   Queue   ││   │
│  │  └────────────┘  └────────────┘  └───────────┘│   │
│  └─────────────────────────────────────────────────┘   │
│                        │                                 │
│  ┌─────────────────────▼───────────────────────────┐   │
│  │          Provider Orchestrator                   │   │
│  │  - Primary provider selection                    │   │
│  │  - Automatic fallback on failure                 │   │
│  │  - Health checking                               │   │
│  │  - Cost tracking per provider                    │   │
│  └──────────────────────────────────────────────────┘   │
│                        │                                 │
│  ┌─────────────────────▼───────────────────────────┐   │
│  │          Provider Factory                        │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐     │   │
│  │  │ OpenAI   │  │Anthropic │  │ Gemini   │     │   │
│  │  └──────────┘  └──────────┘  └──────────┘     │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐     │   │
│  │  │  Ollama  │  │ Mistral  │  │ Cohere   │     │   │
│  │  └──────────┘  └──────────┘  └──────────┘     │   │
│  └──────────────────────────────────────────────────┘   │
│                        │                                 │
│  ┌─────────────────────▼───────────────────────────┐   │
│  │         Result Processing                        │   │
│  │  - JSON extraction                               │   │
│  │  - Confidence calibration                        │   │
│  │  - False positive estimation                     │   │
│  │  - Cost calculation                              │   │
│  └──────────────────────────────────────────────────┘   │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

**Why This Design?**

1. **Budget Tracker**: Uses atomic operations (u64 micro-dollars) for thread-safe cost tracking without locks
2. **Rate Limiter**: Semaphore-based concurrency control respects API limits per provider
3. **Provider Fallback**: Gracefully degrades to backup providers on failure, ensuring scan completion
4. **Health Checking**: Pre-scan validation prevents wasting time on unavailable providers
5. **Cost per Provider**: Enables cost optimization by provider selection

**Rate Limiting Strategy**:
```
Max Concurrent Requests = config.max_requests (default: 50)
│
├─ Semaphore with N permits
│  └─ Each API call acquires permit
│     └─ Automatically released after completion
│
└─ Prevents overwhelming provider APIs
   └─ Respects tier-based rate limits
```

### 4. Storage Layer

**Purpose**: Persistent data management

```
┌─────────────────────────────────────────────────────────┐
│                  Storage Architecture                    │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────────────────────────────────────────┐      │
│  │          Baseline Storage                     │      │
│  │  ~/.mcp-sentinel/baselines/                   │      │
│  │                                               │      │
│  │  {project_hash}_baseline.json.gz              │      │
│  │  ├─ Gzip compressed (70-90% reduction)       │      │
│  │  ├─ Vulnerability snapshots                   │      │
│  │  ├─ File hashes (SHA-256)                     │      │
│  │  └─ Metadata (timestamp, config)              │      │
│  │                                               │      │
│  │  Why Compressed?                              │      │
│  │  - Large scans generate 10+ MB data           │      │
│  │  - Compression reduces to 1-2 MB              │      │
│  │  - ~10ms compression overhead acceptable      │      │
│  └──────────────────────────────────────────────┘      │
│                                                          │
│  ┌──────────────────────────────────────────────┐      │
│  │            Cache Storage (Sled)               │      │
│  │  ~/.mcp-sentinel/cache/                       │      │
│  │                                               │      │
│  │  Key: "file:{path}"                           │      │
│  │  Value: Bincode(CacheEntry)                   │      │
│  │    ├─ Content hash (SHA-256)                  │      │
│  │    ├─ Scan results                            │      │
│  │    ├─ Timestamp                               │      │
│  │    └─ TTL (default: 24h)                      │      │
│  │                                               │      │
│  │  Why Sled?                                    │      │
│  │  - Embedded (no external DB)                  │      │
│  │  - Lock-free reads (high concurrency)         │      │
│  │  - Crash-safe (ACID guarantees)              │      │
│  │  - Fast (100K+ ops/sec)                       │      │
│  └──────────────────────────────────────────────┘      │
│                                                          │
│  ┌──────────────────────────────────────────────┐      │
│  │          Audit Log Storage                    │      │
│  │  ~/.mcp-sentinel/logs/suppressions.log        │      │
│  │                                               │      │
│  │  Format: JSON Lines (one entry per line)      │      │
│  │  {                                            │      │
│  │    "timestamp": "2025-10-26T...",            │      │
│  │    "suppression_id": "SUP-001",              │      │
│  │    "vuln_type": "secrets",                   │      │
│  │    "file_path": "config.py",                 │      │
│  │    "reason": "False positive"                │      │
│  │  }                                            │      │
│  │                                               │      │
│  │  Why JSON Lines?                              │      │
│  │  - Append-only (no file locking)             │      │
│  │  - Easy to parse line by line                │      │
│  │  - Standard format for log aggregation       │      │
│  └──────────────────────────────────────────────┘      │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

**Storage Size Estimates**:
- Baseline (compressed): 1-5 MB for 10,000 files
- Cache: ~100 KB per 1,000 files (with hits)
- Audit log: ~500 bytes per suppression
- Total: <10 MB for typical projects

---

## Data Flow Diagrams

### 1. Full Scan Flow (With AI Analysis)

```
┌─────────┐
│  User   │
│ Runs    │
│ Scan    │
└────┬────┘
     │
     ▼
┌─────────────────────────────────────────────────┐
│ 1. CLI Argument Parsing                          │
│    - Parse flags: --ai, --provider, --budget    │
│    - Load config file (if specified)            │
│    - Validate parameters                        │
└────┬────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────┐
│ 2. Git Integration (if --diff specified)        │
│    - Detect Git repository                      │
│    - Get changed files since reference          │
│    - Filter file list to changed only           │
└────┬────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────┐
│ 3. File Discovery                               │
│    - Walk directory tree                        │
│    - Apply exclude patterns                     │
│    - Filter by supported file types             │
│    Result: Vec<PathBuf>                         │
└────┬────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────┐
│ 4. Cache Check (for each file)                  │
│    - Hash file content (SHA-256)                │
│    - Query cache with hash                      │
│    - If hit: use cached results                 │
│    - If miss: proceed to scanning               │
└────┬────────────────────────────────────────────┘
     │
     ├─ Cache Hit ─────────────────────┐
     │                                 │
     │                                 ▼
     │                    ┌─────────────────────┐
     │                    │ Use Cached Results  │
     │                    └─────────────────────┘
     │                                 │
     ▼                                 │
┌─────────────────────────────────────┴───────────┐
│ 5. Static Analysis                              │
│    - Run all detectors concurrently             │
│    - Pattern matching (regex)                   │
│    - AST analysis (tree-sitter)                 │
│    - Heuristic rules                            │
│    Result: Vec<Vulnerability>                   │
└────┬────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────┐
│ 6. AI Analysis (if --ai enabled)                │
│    ┌─────────────────────────────────────────┐ │
│    │ For each suspicious code snippet:        │ │
│    │                                          │ │
│    │ 6.1. Check Budget                        │ │
│    │      - Current cost vs limit             │ │
│    │      - Abort if exceeded                 │ │
│    │                                          │ │
│    │ 6.2. Acquire Rate Limit Permit           │ │
│    │      - Wait for semaphore                │ │
│    │                                          │ │
│    │ 6.3. Call LLM Provider                   │ │
│    │      - Primary provider first            │ │
│    │      - Fallback on failure               │ │
│    │                                          │ │
│    │ 6.4. Parse Response                      │ │
│    │      - Extract JSON                      │ │
│    │      - Validate structure                │ │
│    │      - Calculate confidence              │ │
│    │                                          │ │
│    │ 6.5. Track Cost                          │ │
│    │      - Count tokens                      │ │
│    │      - Calculate USD cost                │ │
│    │      - Update atomic counter             │ │
│    └─────────────────────────────────────────┘ │
│    Result: Vec<AIFinding>                       │
└────┬────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────┐
│ 7. Result Aggregation                           │
│    - Merge static + AI findings                 │
│    - Deduplicate by location + type             │
│    - Sort by severity                           │
└────┬────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────┐
│ 8. Suppression Filtering                        │
│    - Load suppression config                    │
│    - Match each vulnerability                   │
│    - Filter suppressed items                    │
│    - Log suppressions to audit                  │
└────┬────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────┐
│ 9. Baseline Comparison (if enabled)             │
│    - Load previous baseline                     │
│    - Compare vulnerabilities                    │
│    - Classify: NEW/FIXED/CHANGED/UNCHANGED      │
│    - Generate comparison summary                │
└────┬────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────┐
│ 10. Cache Update                                │
│     - Store results for each file               │
│     - Set TTL (default: 24h)                    │
│     - Cleanup expired entries                   │
└────┬────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────┐
│ 11. Output Generation                           │
│     - Format: Terminal / JSON / SARIF           │
│     - Include cost summary (if AI used)         │
│     - Write to file or stdout                   │
└────┬────────────────────────────────────────────┘
     │
     ▼
┌─────────┐
│  User   │
│ Reviews │
│ Results │
└─────────┘
```

**Why This Flow?**

1. **Early Git Filtering**: Reduces file count before heavy processing
2. **Cache First**: Avoids redundant scanning of unchanged files
3. **Static Before AI**: Uses cheap detection first, reserves AI for suspicious code
4. **Budget Checks**: Prevents runaway costs from accidental large scans
5. **Suppression After Analysis**: Allows reviewing what would be suppressed
6. **Cache Last**: Only caches validated results

### 2. AI Provider Communication Flow

```
┌──────────────┐
│ AI Analysis  │
│   Engine     │
└──────┬───────┘
       │
       │ 1. Initialize Provider
       │
       ▼
┌─────────────────────────────────────────┐
│         Provider Factory                │
│                                         │
│  - Read API key from environment        │
│  - Validate key format                  │
│  - Create HTTP client                   │
│  - Perform health check                 │
│                                         │
│  Health Check:                          │
│  ┌────────────────────────────────┐   │
│  │ Send test request to API        │   │
│  │ ├─ Success: Provider ready      │   │
│  │ └─ Failure: Try fallback        │   │
│  └────────────────────────────────┘   │
└──────┬──────────────────────────────────┘
       │
       │ 2. Provider Ready
       │
       ▼
┌─────────────────────────────────────────┐
│      Analyze Code Request               │
│                                         │
│  Input:                                 │
│  - Code snippet (max ~50 lines)         │
│  - File path and language               │
│  - Line number (if known)               │
│  - Suspected vulnerability type         │
└──────┬──────────────────────────────────┘
       │
       │ 3. Build Prompt
       │
       ▼
┌─────────────────────────────────────────┐
│       Prompt Construction               │
│                                         │
│  System Prompt:                         │
│  "You are a security expert..."         │
│  "Respond with JSON format..."          │
│  "Focus on MCP-specific risks..."       │
│                                         │
│  User Prompt:                           │
│  File: {file_path}                      │
│  Language: {language}                   │
│  Code:                                  │
│  ```{language}                          │
│  {code_snippet}                         │
│  ```                                    │
└──────┬──────────────────────────────────┘
       │
       │ 4. HTTP Request
       │
       ▼
┌─────────────────────────────────────────┐
│      Provider API Call                  │
│                                         │
│  ┌─────────────────────────────────┐  │
│  │ OpenAI:                          │  │
│  │ POST https://api.openai.com/... │  │
│  │ Headers:                         │  │
│  │   Authorization: Bearer {key}    │  │
│  │   Content-Type: application/json │  │
│  │ Body:                            │  │
│  │   {                              │  │
│  │     "model": "gpt-4-turbo",     │  │
│  │     "messages": [...],          │  │
│  │     "temperature": 0.1          │  │
│  │   }                              │  │
│  └─────────────────────────────────┘  │
│                                         │
│  ┌─────────────────────────────────┐  │
│  │ Anthropic:                       │  │
│  │ POST https://api.anthropic.com/...│ │
│  │ Headers:                         │  │
│  │   x-api-key: {key}              │  │
│  │   anthropic-version: 2023-06-01 │  │
│  │ Body:                            │  │
│  │   {                              │  │
│  │     "model": "claude-3-sonnet", │  │
│  │     "max_tokens": 2000,         │  │
│  │     "system": "...",            │  │
│  │     "messages": [...]           │  │
│  │   }                              │  │
│  └─────────────────────────────────┘  │
│                                         │
│  ┌─────────────────────────────────┐  │
│  │ Google Gemini:                   │  │
│  │ POST https://generativelanguage.│  │
│  │      googleapis.com/.../generate│  │
│  │ Query Params:                    │  │
│  │   key={api_key}                 │  │
│  │ Body:                            │  │
│  │   {                              │  │
│  │     "contents": [{              │  │
│  │       "role": "user",           │  │
│  │       "parts": [{"text": "..."}]│  │
│  │     }],                          │  │
│  │     "generationConfig": {...}   │  │
│  │   }                              │  │
│  └─────────────────────────────────┘  │
└──────┬──────────────────────────────────┘
       │
       │ 5. Response
       │
       ▼
┌─────────────────────────────────────────┐
│      Response Processing                │
│                                         │
│  Step 1: HTTP Status Check              │
│  ├─ 200: Success → Parse body           │
│  ├─ 429: Rate limit → Retry w/ backoff  │
│  ├─ 401: Auth error → Fail w/ message   │
│  └─ 5xx: Server error → Try fallback    │
│                                         │
│  Step 2: Extract Response Text          │
│  - OpenAI: choices[0].message.content   │
│  - Anthropic: content[0].text           │
│  - Gemini: candidates[0].content.parts  │
│                                         │
│  Step 3: Extract JSON                   │
│  - Try direct parse                     │
│  - Try markdown code block (```json)    │
│  - Try finding { ... } in text          │
│                                         │
│  Step 4: Validate Structure             │
│  - Check required fields exist          │
│  - Validate enum values                 │
│  - Apply defaults for missing fields    │
│                                         │
│  Step 5: Calculate Costs                │
│  - Count input/output tokens            │
│  - Multiply by provider rates           │
│  - Convert to USD                       │
└──────┬──────────────────────────────────┘
       │
       │ 6. Return AIFinding
       │
       ▼
┌──────────────┐
│ AI Analysis  │
│   Engine     │
│ (with result)│
└──────────────┘
```

**Error Handling Strategy**:

```
API Call Error
│
├─ Network Error (timeout, DNS, etc.)
│  └─ Retry 3 times with exponential backoff
│     └─ If still fails: Try fallback provider
│
├─ Auth Error (401, 403)
│  └─ Return helpful error with setup instructions
│     └─ Do NOT retry (wastes time)
│
├─ Rate Limit (429)
│  └─ Extract Retry-After header
│     └─ Wait specified time
│        └─ Retry request
│
├─ Server Error (5xx)
│  └─ Try fallback provider immediately
│     └─ Log warning for primary provider
│
└─ Invalid Response (malformed JSON, missing fields)
   └─ Log warning
      └─ Try fallback provider
         └─ Return best-effort result
```

---

## Network Architecture

### Provider Communication Patterns

```
┌────────────────────────────────────────────────────────────┐
│                    MCP Sentinel                            │
│                  (Local Process)                           │
│                                                            │
│  ┌──────────────────────────────────────────────────┐    │
│  │         AI Analysis Engine                        │    │
│  │  - Budget: $1.00 limit                           │    │
│  │  - Rate: 50 concurrent requests max              │    │
│  │  - Timeout: 60 seconds per request               │    │
│  └──────────────────────────────────────────────────┘    │
│                         │                                  │
└─────────────────────────┼──────────────────────────────────┘
                          │
            ┌─────────────┼─────────────┐
            │             │             │
            ▼             ▼             ▼
┌────────────────┐ ┌────────────────┐ ┌────────────────┐
│   Provider 1   │ │   Provider 2   │ │   Provider 3   │
│   (Primary)    │ │  (Fallback 1)  │ │  (Fallback 2)  │
└────────┬───────┘ └────────┬───────┘ └────────┬───────┘
         │                  │                  │
         │                  │                  │
   ┌─────▼──────────┐ ┌────▼───────────┐ ┌───▼────────────┐
   │   OpenAI API   │ │ Anthropic API  │ │  Gemini API    │
   │                │ │                │ │                │
   │ api.openai.com │ │api.anthropic...│ │generativelang..│
   │                │ │                │ │                │
   │ TLS 1.3        │ │ TLS 1.3        │ │ TLS 1.3        │
   │ HTTPS (443)    │ │ HTTPS (443)    │ │ HTTPS (443)    │
   └────────────────┘ └────────────────┘ └────────────────┘
```

**Local Provider (Ollama)**:

```
┌────────────────────────────────────────────┐
│          MCP Sentinel                      │
│        (Local Process)                     │
└──────────────┬─────────────────────────────┘
               │
               │ HTTP (no TLS needed)
               │ localhost:11434
               │
      ┌────────▼───────────┐
      │  Ollama Server     │
      │  (Local Process)   │
      │                    │
      │  - No API key      │
      │  - Free            │
      │  - Private         │
      │  - Offline capable │
      └──────────┬─────────┘
                 │
                 │ Model inference
                 │
         ┌───────▼──────────┐
         │   LLM Models     │
         │  ~/.ollama/      │
         │                  │
         │  - codellama     │
         │  - llama3        │
         │  - mistral       │
         └──────────────────┘
```

**Why This Design?**

1. **Primary + Fallbacks**: Ensures scan completion even if primary provider fails
2. **Concurrent Requests**: Semaphore limits prevent overwhelming APIs
3. **TLS Everywhere**: All cloud providers use HTTPS for security
4. **Local Option**: Ollama provides zero-cost, private alternative
5. **Timeout Protection**: 60s timeout prevents hanging on slow responses

### Network Security

```
┌─────────────────────────────────────────────────────────┐
│              Security Measures                          │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. API Key Storage                                     │
│     ✓ Environment variables only                       │
│     ✓ Never stored in files                            │
│     ✓ Never logged                                      │
│     ✓ Not in error messages                            │
│                                                         │
│  2. TLS/HTTPS                                          │
│     ✓ All cloud APIs use HTTPS                         │
│     ✓ Certificate validation enabled                   │
│     ✓ TLS 1.2+ required                                │
│                                                         │
│  3. Code Privacy                                       │
│     ⚠ Code sent to cloud providers                     │
│     ⚠ Subject to provider's privacy policy             │
│     ✓ Option to use local Ollama (no external sends)  │
│     ✓ Snippets limited to ~50 lines                    │
│                                                         │
│  4. Rate Limiting                                      │
│     ✓ Respects provider tier limits                   │
│     ✓ Prevents abuse/overwhelming APIs                │
│     ✓ Automatic backoff on 429 responses              │
│                                                         │
│  5. Error Handling                                     │
│     ✓ No sensitive data in error messages             │
│     ✓ Generic errors to user                          │
│     ✓ Detailed errors in debug logs only              │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Performance Architecture

### Caching Strategy

**Why Cache?** Scanning 10,000 files takes ~8 minutes. Rescanning unchanged files is wasteful.

```
┌─────────────────────────────────────────────────────────┐
│              Caching Flow                               │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  File to Scan                                           │
│       │                                                 │
│       ▼                                                 │
│  ┌──────────────────────┐                              │
│  │ Hash Content (SHA256)│                              │
│  │ Time: ~0.1ms         │                              │
│  └─────────┬────────────┘                              │
│            │                                            │
│            ▼                                            │
│  ┌──────────────────────┐       ┌──────────────┐     │
│  │ Query Cache by Hash  │────→  │ Cache Hit?   │     │
│  │ Time: ~0.05ms       │       └──────┬───────┘     │
│  └──────────────────────┘              │             │
│                                         │             │
│                          ┌──────────────┴──────┐     │
│                          │                     │     │
│                      YES │                     │ NO  │
│                          │                     │     │
│                          ▼                     ▼     │
│              ┌────────────────┐    ┌──────────────┐ │
│              │ Return Cached  │    │ Full Scan    │ │
│              │ Results        │    │ Time: ~50ms  │ │
│              │ Time: ~0.2ms   │    └──────┬───────┘ │
│              └────────────────┘           │         │
│                                           │         │
│                                           ▼         │
│                              ┌────────────────────┐ │
│                              │ Store in Cache     │ │
│                              │ Time: ~0.5ms       │ │
│                              └────────────────────┘ │
│                                                     │
│  Performance Impact:                                │
│  - Cache Hit: 0.2ms vs 50ms = 250x faster         │
│  - 90% cache hit rate: 10,000 files in 1s vs 8min │
│                                                     │
└─────────────────────────────────────────────────────────┘
```

### Concurrent Scanning

```
┌─────────────────────────────────────────────────────────┐
│         Concurrent Scanning Architecture                │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  File List (10,000 files)                              │
│       │                                                 │
│       ▼                                                 │
│  ┌──────────────────────────────────────┐             │
│  │   Tokio Runtime (Thread Pool)        │             │
│  │   Threads: num_cpus (usually 8-16)   │             │
│  └──────────────┬───────────────────────┘             │
│                 │                                       │
│                 │ Spawn tasks                          │
│                 │                                       │
│      ┌──────────┼──────────┬──────────┬──────────┐   │
│      │          │          │          │          │   │
│      ▼          ▼          ▼          ▼          ▼   │
│  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐ │
│  │Task 1│  │Task 2│  │Task 3│  │Task 4│  │Task N│ │
│  │      │  │      │  │      │  │      │  │      │ │
│  │Scan  │  │Scan  │  │Scan  │  │Scan  │  │Scan  │ │
│  │File 1│  │File 2│  │File 3│  │File 4│  │File N│ │
│  └──────┘  └──────┘  └──────┘  └──────┘  └──────┘ │
│      │          │          │          │          │   │
│      └──────────┴──────────┴──────────┴──────────┘   │
│                 │                                       │
│                 ▼                                       │
│  ┌────────────────────────────────┐                   │
│  │   Collect Results (ordered)    │                   │
│  └────────────────────────────────┘                   │
│                                                         │
│  Why Tokio?                                            │
│  - Async I/O for file reading (no blocking)           │
│  - Work-stealing scheduler (optimal CPU usage)        │
│  - Supports millions of tasks (not threads)           │
│  - Excellent for mixed I/O and CPU-bound work         │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Memory Management

```
┌─────────────────────────────────────────────────────────┐
│         Memory Usage Profile                            │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Component               Memory           Why           │
│  ────────────────────────────────────────────────────   │
│  File Buffer            4 KB/file       Small reads     │
│  Tree-sitter AST        ~100 KB/file    Rich parsing    │
│  Scan Results           ~1 KB/vuln      Compact structs │
│  Cache (Sled)           ~10 MB          Embedded DB     │
│  HTTP Connections       ~50 KB/conn     TLS overhead    │
│  ────────────────────────────────────────────────────   │
│  Total (10K files):     ~1.2 GB                         │
│                                                         │
│  Optimization Strategies:                               │
│  1. Streaming file reads (not full load)               │
│  2. Drop AST after analysis                            │
│  3. Batch results to disk                              │
│  4. Limit concurrent tasks                             │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Security Architecture

### Threat Model

```
┌─────────────────────────────────────────────────────────┐
│              Threats & Mitigations                      │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Threat 1: API Key Exposure                            │
│  Risk: High                                            │
│  Impact: Unauthorized use, cost overruns               │
│  Mitigation:                                           │
│  ✓ Keys from environment only                          │
│  ✓ Never logged or stored                             │
│  ✓ Validation on startup                              │
│  ✓ Clear error messages (no key leaks)                │
│                                                         │
│  Threat 2: Code Exfiltration                           │
│  Risk: Medium                                          │
│  Impact: IP theft, competitive intelligence            │
│  Mitigation:                                           │
│  ✓ Option to use local Ollama (no external)           │
│  ✓ Snippet size limits (~50 lines)                    │
│  ✓ User awareness (docs explain data flow)            │
│  ⚠ Cannot prevent cloud provider access               │
│                                                         │
│  Threat 3: Cost Overruns                               │
│  Risk: Medium                                          │
│  Impact: Unexpected bills                              │
│  Mitigation:                                           │
│  ✓ Budget limits (enforced)                           │
│  ✓ Cost tracking (real-time)                          │
│  ✓ Warnings before expensive operations                │
│  ✓ Ollama as free alternative                         │
│                                                         │
│  Threat 4: Supply Chain (Dependencies)                 │
│  Risk: Low                                             │
│  Impact: Malicious code injection                      │
│  Mitigation:                                           │
│  ✓ Minimal dependencies                                │
│  ✓ Well-known crates only                             │
│  ✓ Cargo.lock committed                               │
│  ✓ Regular audits (cargo audit)                       │
│                                                         │
│  Threat 5: Configuration Injection                     │
│  Risk: Low                                             │
│  Impact: Arbitrary code execution                      │
│  Mitigation:                                           │
│  ✓ YAML parsing (safe, no eval)                       │
│  ✓ Input validation                                    │
│  ✓ No dynamic code loading                            │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Deployment Architecture

### Local Development

```
┌────────────────────────────────────┐
│     Developer Workstation          │
│                                    │
│  ┌──────────────────────────────┐ │
│  │  MCP Sentinel (Binary)       │ │
│  │  ~/.cargo/bin/mcp-sentinel   │ │
│  └──────────────────────────────┘ │
│               │                    │
│  ┌────────────▼──────────────────┐│
│  │  Local Storage                ││
│  │  ~/.mcp-sentinel/             ││
│  │    ├─ baselines/              ││
│  │    ├─ cache/                  ││
│  │    ├─ logs/                   ││
│  │    └─ config.yaml             ││
│  └───────────────────────────────┘│
│                                    │
│  Optional: Ollama for local AI    │
│  ┌──────────────────────────────┐ │
│  │  Ollama Server               │ │
│  │  http://localhost:11434      │ │
│  └──────────────────────────────┘ │
│                                    │
└────────────────────────────────────┘
```

### CI/CD Integration

```
┌─────────────────────────────────────────────────────────┐
│              GitHub Actions Workflow                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Trigger: Pull Request                                  │
│       │                                                 │
│       ▼                                                 │
│  ┌──────────────────────────────┐                      │
│  │  1. Checkout Code            │                      │
│  └──────────┬───────────────────┘                      │
│             │                                            │
│             ▼                                            │
│  ┌──────────────────────────────┐                      │
│  │  2. Install MCP Sentinel     │                      │
│  │     wget binary or cargo      │                      │
│  └──────────┬───────────────────┘                      │
│             │                                            │
│             ▼                                            │
│  ┌──────────────────────────────┐                      │
│  │  3. Run Scan                 │                      │
│  │     mcp-sentinel scan        │                      │
│  │       --diff origin/main     │                      │
│  │       --output sarif         │                      │
│  │       --fail-on high         │                      │
│  │       --ai                   │                      │
│  │       --provider gemini      │                      │
│  │       --budget 0.50          │                      │
│  └──────────┬───────────────────┘                      │
│             │                                            │
│             ▼                                            │
│  ┌──────────────────────────────┐                      │
│  │  4. Upload SARIF             │                      │
│  │     To GitHub Code Scanning  │                      │
│  └──────────┬───────────────────┘                      │
│             │                                            │
│             ▼                                            │
│  ┌──────────────────────────────┐                      │
│  │  5. Post PR Comment          │                      │
│  │     Summary of findings      │                      │
│  └──────────────────────────────┘                      │
│                                                         │
│  Environment Variables:                                 │
│  - GOOGLE_API_KEY (Gemini)                             │
│  - Budget: $0.50 per PR                                │
│  - Runtime: ~2-5 minutes                               │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**Why Gemini for CI/CD?**
- Cheapest option: $0.03 per 50 files
- Fast inference: 0.3-0.8s per snippet
- High availability: Google infrastructure
- Good enough quality for automated checks

---

## Appendix: Design Rationale

### Key Architectural Decisions

1. **Why Rust?**
   - Memory safety without garbage collection
   - Excellent concurrency (async/await)
   - Fast (C++ performance)
   - Strong type system (prevents bugs)
   - Great ecosystem (Cargo, crates.io)

2. **Why Tokio over threads?**
   - Async I/O is faster for file operations
   - Can handle 100K+ concurrent tasks
   - Work-stealing scheduler optimizes CPU usage
   - Better for mixed I/O + CPU work

3. **Why Sled over SQLite?**
   - Fully embedded (single dependency)
   - Lock-free reads (better concurrency)
   - Simpler API (KV store vs SQL)
   - Crash-safe by default
   - No schema migrations needed

4. **Why gzip for baselines?**
   - 70-90% compression ratio
   - Fast (10ms for 5MB)
   - Standard format (widely supported)
   - Streaming decompression

5. **Why trait-based providers?**
   - Type safety (compile-time checks)
   - Easy to mock for testing
   - Clear interface contracts
   - Supports dynamic dispatch

6. **Why atomic operations for costs?**
   - Thread-safe without locks
   - Faster than Mutex
   - No deadlock risk
   - Simple to reason about

7. **Why semaphore for rate limiting?**
   - Fair (FIFO) access
   - Async-aware (works with Tokio)
   - Automatic cleanup
   - Backpressure built-in

8. **Why JSON Lines for audit log?**
   - Append-only (no file locking)
   - Easy to parse (one entry per line)
   - Standard format (log aggregation tools)
   - Human-readable

---

**Document Version**: 1.0
**Last Updated**: 2025-10-26
**Authors**: Claude (Anthropic) for MCP Sentinel
**Review Status**: ✅ Complete
