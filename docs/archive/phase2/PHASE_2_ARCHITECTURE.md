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

### Unified Provider Interface

```rust
#[async_trait]
pub trait LLMProvider: Send + Sync {
    /// Analyze code snippet for vulnerabilities
    async fn analyze_code(
        &self,
        code: &str,
        context: &AnalysisContext,
    ) -> Result<AIFinding>;

    /// Explain a detected vulnerability
    async fn explain_vulnerability(
        &self,
        vuln: &Vulnerability,
        code: &str,
    ) -> Result<String>;

    /// Generate remediation guidance
    async fn generate_remediation(
        &self,
        vuln: &Vulnerability,
    ) -> Result<String>;

    /// Provider name
    fn name(&self) -> &str;

    /// Cost per request (in USD)
    fn cost_per_request(&self) -> f64;

    /// Check if provider is available
    async fn health_check(&self) -> Result<bool>;
}
```

### Supported Providers

**1. OpenAI**
- Models: GPT-4, GPT-4-turbo, GPT-3.5-turbo
- Cost: $0.03 per 1K tokens (GPT-4)
- Requires: OPENAI_API_KEY

**2. Anthropic**
- Models: Claude 3 Opus, Sonnet, Haiku
- Cost: $0.015 per 1K tokens (Claude 3 Sonnet)
- Requires: ANTHROPIC_API_KEY

**3. Ollama (Local)**
- Models: llama3, mistral, codellama, phi, etc.
- Cost: $0 (local)
- Requires: Ollama server running

**4. Mistral AI**
- Models: Mistral Large, Medium, Small
- Cost: $0.008 per 1K tokens
- Requires: MISTRAL_API_KEY

**5. Cohere**
- Models: Command, Command-Light
- Cost: $0.002 per 1K tokens
- Requires: COHERE_API_KEY

**6. HuggingFace**
- Models: Any inference API model
- Cost: Varies by model
- Requires: HUGGINGFACE_API_KEY

**7. Google Gemini**
- Models: Gemini Pro, Gemini Ultra
- Cost: $0.00025 per 1K tokens (Pro)
- Requires: GOOGLE_API_KEY

**8. Azure OpenAI**
- Models: GPT-4, GPT-3.5 (Azure-hosted)
- Cost: Varies by region
- Requires: AZURE_OPENAI_KEY + endpoint

### Provider Selection Strategy

```rust
pub struct ProviderConfig {
    /// Primary provider
    pub primary: String,

    /// Fallback providers (in order)
    pub fallbacks: Vec<String>,

    /// Budget limit (USD per scan)
    pub budget_limit: f64,

    /// Max requests per provider
    pub max_requests: usize,

    /// Prefer local providers
    pub prefer_local: bool,
}
```

**Default Strategy**:
1. Try Ollama (local) if available - $0 cost
2. Fall back to OpenAI GPT-3.5-turbo - lowest commercial cost
3. Final fallback to Anthropic Claude Haiku - fast and cheap

---

## Data Flow

### Scan Flow with All Features

```
1. Parse CLI Arguments
   ├─> Load configuration file
   ├─> Load suppression rules
   └─> Initialize LLM providers

2. Target Discovery
   ├─> GitHub URL? → Clone to temp
   ├─> Local path? → Validate
   └─> Get file list

3. Diff-Aware Filtering (if --diff)
   ├─> Query Git for changed files
   └─> Filter file list

4. Cache Check (if --cached)
   ├─> Hash unchanged files
   └─> Load cached results

5. Multi-Engine Analysis
   ├─> Static Pattern Analysis (Phase 1)
   │   └─> 5 detectors + MCP config
   │
   ├─> Semgrep Analysis (Phase 2)
   │   └─> Run Semgrep with rules
   │
   ├─> Tree-sitter Analysis (Phase 2)
   │   ├─> Parse AST
   │   ├─> Dataflow analysis
   │   └─> Taint tracking
   │
   └─> AI Analysis (Phase 2, optional)
       ├─> Send to LLM provider
       ├─> Parse AI findings
       └─> Add confidence scores

6. Result Processing
   ├─> Merge all findings
   ├─> Deduplicate by location + type
   ├─> Apply suppression rules
   ├─> Add CWE/OWASP mappings
   └─> Calculate confidence scores

7. Baseline Comparison (if enabled)
   ├─> Load previous baseline
   ├─> Compare: NEW, FIXED, CHANGED
   └─> Update baseline

8. Output Generation
   ├─> Terminal (colored table)
   ├─> JSON (structured)
   ├─> SARIF (GitHub integration)
   └─> HTML (dashboard with charts)

9. Exit Code Determination
   └─> 0=clean, 1=vulns, 2=error, 3=usage
```

---

## Error Handling Strategy

### Error Categories

**1. User Errors (Exit Code 3)**
- Invalid arguments
- Invalid configuration
- Missing required files

**2. System Errors (Exit Code 2)**
- File I/O failures
- Git failures
- Network timeouts

**3. Analysis Errors (Logged, Continue)**
- Detector failures
- AST parse errors
- LLM API errors

**4. Critical Errors (Exit Code 2)**
- Out of memory
- Corrupted database
- Missing dependencies

### Error Types

```rust
#[derive(Debug, thiserror::Error)]
pub enum SentinelError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Git error: {0}")]
    Git(String),

    #[error("LLM provider error: {0}")]
    LLMProvider(String),

    #[error("AST parsing error: {0}")]
    ASTParser(String),

    #[error("Semgrep error: {0}")]
    Semgrep(String),

    #[error("Cache error: {0}")]
    Cache(String),

    #[error("Baseline error: {0}")]
    Baseline(String),

    #[error("Suppression error: {0}")]
    Suppression(String),
}
```

### Error Handling Pattern

```rust
// Graceful degradation for detectors
match detector.detect(code) {
    Ok(findings) => results.extend(findings),
    Err(e) => {
        warn!("Detector {} failed: {}", detector.name(), e);
        metrics.record_detector_failure(detector.name());
        // Continue with other detectors
    }
}

// Critical errors should fail fast
let config = load_config().context("Failed to load configuration")?;

// User errors should show helpful messages
if !target.exists() {
    return Err(SentinelError::Config(
        format!("Target path does not exist: {}", target.display())
    ));
}
```

---

## Logging Architecture

### Log Levels

**ERROR**: Critical failures that stop execution
- Configuration load failures
- Database corruption
- Out of memory

**WARN**: Non-critical issues that may affect results
- Detector failures
- API timeouts
- Cache misses

**INFO**: Important progress updates
- Scan started/completed
- Files scanned count
- Findings summary

**DEBUG**: Detailed execution info
- Individual file scans
- Detector execution times
- API request/response

**TRACE**: Very detailed debugging
- AST node traversal
- Regex pattern matches
- Cache hit/miss details

### Logging Configuration

```yaml
# config.yaml logging section
logging:
  level: info              # error, warn, info, debug, trace
  format: pretty           # pretty, json, compact
  output: stderr           # stderr, stdout, file
  file: ~/.mcp-sentinel/logs/sentinel.log
  rotation:
    enabled: true
    max_size: 10MB
    max_files: 5
```

### Structured Logging

```rust
// Use tracing for structured logs
use tracing::{info, warn, error, debug, trace, instrument};

#[instrument(skip(code))]
async fn analyze_with_ai(code: &str, provider: &dyn LLMProvider) -> Result<AIFinding> {
    debug!(
        provider = provider.name(),
        code_length = code.len(),
        "Starting AI analysis"
    );

    let start = Instant::now();
    let result = provider.analyze_code(code, &context).await;
    let duration = start.elapsed();

    match &result {
        Ok(finding) => {
            info!(
                provider = provider.name(),
                confidence = finding.confidence,
                duration_ms = duration.as_millis(),
                "AI analysis completed"
            );
        }
        Err(e) => {
            warn!(
                provider = provider.name(),
                error = %e,
                "AI analysis failed"
            );
        }
    }

    result
}
```

---

## Documentation Auto-Generation

### Documentation Sources

**1. Code Documentation (rustdoc)**
- Inline doc comments (///)
- Module-level docs
- Example code
- Generated with `cargo doc`

**2. CLI Help (clap)**
- Command descriptions
- Argument help text
- Usage examples
- Auto-generated from code

**3. Feature Documentation (markdown)**
- Auto-generated from feature flags
- Examples from tests
- Configuration options

**4. API Documentation (OpenAPI)**
- For future API server
- Generated from route handlers

### Auto-Generated Docs

**src/utils/doc_generator.rs**:
- Scan codebase for doc comments
- Extract examples from tests
- Generate feature matrix
- Create configuration reference
- Build CLI command reference

**Generated Files**:
- `docs/CLI_REFERENCE.md` - All commands with examples
- `docs/CONFIGURATION.md` - Complete config options
- `docs/LLM_PROVIDERS.md` - Provider setup guides
- `docs/DETECTORS.md` - All detection rules
- `docs/OUTPUT_FORMATS.md` - Output format specs

---

## Performance Considerations

### Optimization Strategies

**1. Parallel Execution**
- Scan files concurrently (tokio::spawn)
- Run detectors in parallel per file
- Batch LLM requests

**2. Caching**
- File content hashes → Skip unchanged files
- AST parsing results → Reuse across detectors
- LLM responses → Cache similar code patterns

**3. Incremental Analysis**
- Git diff-aware: Only scan changed files
- Baseline comparison: Focus on delta
- Smart file filtering: Skip obvious non-vulnerable files

**4. Resource Management**
- Limit concurrent LLM requests (rate limiting)
- Stream large reports (don't hold in memory)
- Clean up temp files eagerly

### Performance Targets

- **Small repos (<100 files)**: <10s total
- **Medium repos (100-1000 files)**: <60s total
- **Large repos (>1000 files)**: <5 minutes with caching
- **Incremental scans**: <5s (only changed files)
- **LLM analysis**: <2s per finding (with caching)

---

## Security & Privacy

### Data Handling

**1. LLM Privacy**
- Code snippets only (max 50 lines)
- Strip PII, secrets, credentials before sending
- Sanitize file paths (no personal info)
- Local Ollama as privacy-first option

**2. Cache Security**
- Encrypt sensitive data in cache
- Store in user home directory
- Configurable retention
- Clear command for cleanup

**3. Baseline Storage**
- Compressed JSON format
- Optional encryption
- No credentials in baseline
- Gitignore by default

### Compliance

**Data Residency**:
- Local-only mode (no network calls)
- EU-region LLM providers available
- Audit logs for all API calls

**Certifications Ready**:
- SOC 2 compliance patterns
- GDPR-friendly defaults
- HIPAA-compatible (local mode)

---

## Testing Strategy

### Unit Tests
- Each detector module
- LLM provider mocks
- AST parsing edge cases
- Suppression rule matching

### Integration Tests
- End-to-end scan flows
- Multi-engine coordination
- Baseline comparison
- Report generation

### Performance Tests
- Large repository scanning
- Concurrent detector execution
- Cache effectiveness
- Memory usage profiling

### AI Tests
- Mock LLM responses
- Error handling (timeouts, rate limits)
- Cost tracking accuracy
- Provider fallback logic

---

## Monitoring & Metrics

### Collected Metrics

**Performance**:
- Scan duration (total, per detector)
- Files scanned per second
- Cache hit rate
- AST parsing time

**Quality**:
- Findings by severity
- False positive rate (via suppressions)
- Confidence score distribution
- AI vs. static detection comparison

**Usage**:
- LLM API calls count
- Cost per scan
- Popular detectors
- Output format preferences

**Errors**:
- Detector failure rate
- LLM timeout rate
- Git operation failures
- Cache corruption events

### Metrics Output

```bash
# After scan completion
✅ Scan Complete

Performance:
  Duration: 45.2s
  Files scanned: 247
  Speed: 5.5 files/sec
  Cache hit rate: 78%

Findings:
  Critical: 2
  High: 5
  Medium: 12
  Low: 8
  Total: 27

Analysis:
  Static detectors: 18 findings
  Semgrep: 6 findings
  Tree-sitter: 3 findings
  AI analysis: 5 findings (2 new insights)

Cost:
  LLM API calls: 15
  Total cost: $0.12
```

---

## Configuration Management

### Configuration Priority

1. **CLI flags** (highest priority)
2. **Environment variables**
3. **Project config** (./.mcp-sentinel.yaml)
4. **User config** (~/.mcp-sentinel/config.yaml)
5. **Built-in defaults** (lowest priority)

### Full Configuration Schema

```yaml
version: "2.0"

# Scan settings
scan:
  mode: deep                    # quick, deep, comprehensive
  parallel_workers: 8
  max_file_size: 10485760      # 10MB
  timeout: 300                  # 5 minutes

  engines:
    static: true
    semgrep: true
    treesitter: true
    ai: false                   # Opt-in

  exclude_patterns:
    - "node_modules/**"
    - ".git/**"
    - "target/**"
    - "dist/**"

# AI analysis settings
ai:
  enabled: false
  primary_provider: ollama
  fallback_providers:
    - openai
    - anthropic
  budget_limit: 1.00           # USD per scan
  max_requests_per_scan: 50
  prefer_local: true

  providers:
    openai:
      model: gpt-3.5-turbo
      api_key_env: OPENAI_API_KEY
      temperature: 0.1

    anthropic:
      model: claude-3-haiku
      api_key_env: ANTHROPIC_API_KEY

    ollama:
      url: http://localhost:11434
      model: codellama

    mistral:
      model: mistral-small
      api_key_env: MISTRAL_API_KEY

# Baseline settings
baseline:
  enabled: false
  path: .mcp-sentinel/baseline.json
  auto_update: false

# Cache settings
cache:
  enabled: true
  directory: ~/.mcp-sentinel/cache
  ttl: 86400                   # 24 hours
  max_size: 1073741824         # 1GB

# Suppression settings
suppression:
  file: .mcp-sentinel-ignore
  audit_log: ~/.mcp-sentinel/suppressions.log
  warn_on_expired: true

# Output settings
output:
  format: terminal             # terminal, json, sarif, html
  file: null                   # Or path to output file
  terminal:
    color: auto                # auto, always, never
    verbose: false
  html:
    theme: dark                # dark, light
    include_charts: true

# Severity thresholds
severity:
  min_report: low              # Minimum to report
  fail_on: high                # Minimum to fail CI

# Logging
logging:
  level: info
  format: pretty
  output: stderr
  file: ~/.mcp-sentinel/logs/sentinel.log

# Git integration
git:
  enabled: true
  diff_mode: auto              # auto, HEAD, main, <ref>
  include_untracked: true
```

---

## Deployment Options

### Local Installation
```bash
cargo install mcp-sentinel --version 2.0.0
mcp-sentinel init --full
```

### Docker
```dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/mcp-sentinel /usr/local/bin/
RUN apt-get update && apt-get install -y git ca-certificates
ENTRYPOINT ["mcp-sentinel"]
```

### CI/CD Integration
```yaml
# .github/workflows/security-scan.yml
- name: MCP Sentinel Scan
  uses: docker://ghcr.io/beejak/mcp-sentinel:2.0
  with:
    args: scan . --output sarif --fail-on high
```

---

**This architecture provides a solid foundation for Phase 2.0 implementation. All components are designed for extensibility, testability, and production use.**
