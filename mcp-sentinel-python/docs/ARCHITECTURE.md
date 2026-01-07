# Python Edition Architecture Documentation

**Version**: 2.0.0
**Date**: 2026-01-06
**Repository**: mcp-sentinel-python
**Status**: Phase 2 Complete (~75% Detector Parity)

This document outlines the architecture and technical design decisions for the Python edition of MCP Sentinel, focusing on the async-first approach, modular design, and production-ready implementation.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Core Design Principles](#core-design-principles)
3. [Module Structure](#module-structure)
4. [Async Architecture](#async-architecture)
5. [Configuration Management](#configuration-management)
6. [Error Handling Strategy](#error-handling-strategy)
7. [Testing Architecture](#testing-architecture)
8. [CLI Design](#cli-design)
9. [API Design](#api-design)
10. [Security Architecture](#security-architecture)
11. [Performance Considerations](#performance-considerations)
12. [Future Architecture Plans](#future-architecture-plans)

---

## Architecture Overview

### High-Level Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    CLI Layer (Rich Terminal)                 │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                    CLI Commands                         │ │
│  │  scan, server, config, validate                      │ │
│  └─────────────────────┬──────────────────────────────────┘ │
│                        │                                   │
│  ┌─────────────────────▼──────────────────────────────────┐ │
│  │              Core Scanner Orchestrator                  │ │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐      │ │
│  │  │   Config    │ │   Scanner   │ │   Results   │      │ │
│  │  │  Manager    │ │  Engine     │ │  Processor  │      │ │
│  │  └─────────────┘ └─────────────┘ └─────────────┘      │ │
│  └─────────────────────┬──────────────────────────────────┘ │
│                        │                                   │
│  ┌─────────────────────▼──────────────────────────────────┐ │
│  │              Detector Modules (Async)                   │ │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐      │ │
│  │  │   Secrets   │ │   Code      │ │   File      │      │ │
│  │  │  Detector   │ │ Injection   │ │ Access      │      │ │
│  │  └─────────────┘ └─────────────┘ └─────────────┘      │ │
│  └─────────────────────┬──────────────────────────────────┘ │
│                        │                                   │
│  ┌─────────────────────▼──────────────────────────────────┐ │
│  │              Output Formatters                          │ │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐      │ │
│  │  │    JSON     │ │    SARIF    │ │    HTML     │      │ │
│  │  │  Formatter  │ │ Formatter   │ │ Formatter   │      │ │
│  │  └─────────────┘ └─────────────┘ └─────────────┘      │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────┐
│                    File System Layer                         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│  │   Async     │ │   Path      │ │   Content   │            │
│  │   File      │ │   Resolver  │ │   Cache     │            │
│  │   I/O       │ │             │ │             │            │
│  └─────────────┘ └─────────────┘ └─────────────┘            │
└──────────────────────────────────────────────────────────────┘
```

### Key Architectural Decisions

1. **Async-First Design**: All I/O operations are asynchronous for maximum performance
2. **Modular Detector System**: Pluggable detector modules for different vulnerability types
3. **Pydantic Configuration**: Type-safe configuration with validation and defaults
4. **Rich Terminal Interface**: Beautiful, informative CLI using Rich library
5. **Multiple Output Formats**: JSON, SARIF, and HTML output support

---

## Core Design Principles

### 1. Async-First Architecture

**Why Async**: Python's asyncio provides excellent I/O performance for file scanning operations.

**Implementation**:
- All file I/O operations use `aiofiles`
- Detector modules are async-compatible
- CLI commands are async functions
- Results processing is async

**Benefits**:
- Concurrent file processing
- Better resource utilization
- Scalable to large codebases
- Non-blocking I/O operations

### 2. Type Safety

**Tools Used**:
- **Pydantic**: Configuration and data models
- **mypy**: Static type checking
- **Type hints**: Throughout codebase

**Benefits**:
- Compile-time error detection
- Better IDE support
- Self-documenting code
- Reduced runtime errors

### 3. Modular Design

**Detector Modules**:
```python
class BaseDetector(ABC):
    """Base class for all vulnerability detectors."""
    
    @abstractmethod
    async def detect(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Detect vulnerabilities in file content."""
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Detector name for identification."""
        pass
```

**Benefits**:
- Easy to add new detectors
- Isolated testing
- Clear separation of concerns
- Plugin architecture ready

---

## Module Structure

### Core Package Structure

```
src/mcp_sentinel/
├── __init__.py              # Package initialization
├── __main__.py              # Module entry point
├── cli/                     # CLI framework
│   ├── __init__.py
│   ├── main.py             # Rich terminal UI (450 lines)
│   └── commands.py         # Command implementations
├── core/                    # Core business logic
│   ├── __init__.py
│   ├── config.py           # Settings management (150 lines)
│   ├── exceptions.py       # Custom exceptions (50 lines)
│   ├── scanner.py          # Scan orchestrator (200 lines)
│   └── results.py          # Result processing
├── detectors/               # Vulnerability detectors (5 implemented)
│   ├── __init__.py
│   ├── base.py             # Base detector class
│   ├── secrets.py          # Secrets detection (350 lines) ✅
│   ├── code_injection.py   # Code injection (300 lines) ✅
│   ├── prompt_injection.py # Prompt injection (280 lines) ✅
│   ├── tool_poisoning.py   # Tool poisoning (310 lines) ✅
│   └── supply_chain.py     # Supply chain (660 lines) ✅
├── formatters/              # Output formatters
│   ├── __init__.py
│   ├── json.py             # JSON output
│   ├── sarif.py            # SARIF format (Phase 2)
│   └── html.py             # HTML report (Phase 2)
├── utils/                   # Utility functions
│   ├── __init__.py
│   ├── file_io.py          # Async file operations
│   └── logger.py           # Logging configuration
└── api/                     # REST API (Phase 2)
    ├── __init__.py
    ├── server.py           # FastAPI server
    └── routes.py           # API endpoints
```

### Module Responsibilities

**CLI Module (450 lines)**:
- Rich terminal interface
- Command parsing and validation
- Progress indication
- Error handling and user feedback

**Config Module (150 lines)**:
- Pydantic settings management
- Environment variable support
- Configuration validation
- Default value management

**Scanner Module (200 lines)**:
- File discovery and filtering
- Async orchestration
- Result aggregation
- Error handling

**Implemented Detectors (2,400+ lines)**:

1. **SecretsDetector** (350 lines):
   - 15+ secret patterns (AWS, OpenAI, GitHub, etc.)
   - Regex optimization
   - Context-aware detection
   - Test coverage: 97.91%

2. **CodeInjectionDetector** (300 lines):
   - 8 injection patterns (SQL, command, eval)
   - Python and JavaScript support
   - Dangerous function detection
   - Test coverage: 96.15%

3. **PromptInjectionDetector** (280 lines):
   - 7 attack patterns
   - System prompt override detection
   - Encoding bypass detection
   - Test coverage: 95.83%

4. **ToolPoisoningDetector** (310 lines):
   - 6 pattern categories
   - 16 invisible Unicode character types
   - Hidden instruction detection
   - Test coverage: 97.96%

5. **SupplyChainDetector** (660 lines):
   - 11 vulnerability patterns
   - Multi-format support (npm, pip, poetry)
   - Typosquatting detection
   - Test coverage: 83.46%

**Overall Statistics**:
- 47 total vulnerability patterns
- 151 comprehensive tests
- 94.26% average test coverage
- 96.5% test pass rate

---

## Async Architecture

### Async Flow Design

```python
async def scan_directory(path: Path, config: Config) -> ScanResults:
    """Async directory scanning orchestration."""
    
    # Discover files asynchronously
    files = await discover_files(path, config.include_patterns, config.exclude_patterns)
    
    # Process files concurrently
    semaphore = asyncio.Semaphore(config.max_concurrent_files)
    
    async def process_file(file_path: Path) -> List[Vulnerability]:
        async with semaphore:
            return await scan_file(file_path, config)
    
    # Run all scans concurrently
    results = await asyncio.gather(*[process_file(f) for f in files])
    
    return aggregate_results(results)
```

### Concurrency Control

**Semaphore Pattern**:
- Limits concurrent file operations
- Prevents resource exhaustion
- Configurable based on system resources

**Benefits**:
- Scales with system capability
- Prevents memory issues
- Maintains performance under load

---

## Configuration Management

### Pydantic Settings Architecture

```python
class Config(BaseSettings):
    """Application configuration with validation."""
    
    # Core settings
    max_concurrent_files: int = Field(default=10, ge=1, le=100)
    include_patterns: List[str] = Field(default=["*.py", "*.js", "*.ts"])
    exclude_patterns: List[str] = Field(default=["*.pyc", "__pycache__/*"])
    
    # Output settings
    output_format: str = Field(default="json", pattern="^(json|sarif|html)$")
    output_file: Optional[Path] = None
    
    # Detection settings
    min_confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    max_file_size: int = Field(default=1024*1024, ge=1024)  # 1MB default
    
    # Logging settings
    log_level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR)$")
    
    model_config = SettingsConfigDict(
        env_prefix="MCP_SENTINEL_",
        env_file=".env",
        case_sensitive=False
    )
```

### Configuration Features

**Validation**:
- Type validation at startup
- Range checking for numeric values
- Pattern matching for string values
- Custom validators for complex logic

**Environment Support**:
- Environment variable prefix
- .env file support
- Case-insensitive matching
- Type coercion

**Documentation**:
- Self-documenting through field descriptions
- Type hints for IDE support
- Validation error messages

---

## Error Handling Strategy

### Error Classification

```python
class MCPSentinelError(Exception):
    """Base exception for MCP Sentinel."""
    pass

class ConfigurationError(MCPSentinelError):
    """Configuration-related errors."""
    pass

class FileAccessError(MCPSentinelError):
    """File system access errors."""
    pass

class DetectionError(MCPSentinelError):
    """Vulnerability detection errors."""
    pass
```

### Error Handling Patterns

**Graceful Degradation**:
- Continue scanning on individual file errors
- Log errors but don't crash
- Report partial results

**User-Friendly Messages**:
- Clear error descriptions
- Suggested solutions
- Context information

**Logging Strategy**:
- Structured logging with contexts
- Appropriate log levels
- Error aggregation

---

## Testing Architecture

### Test Structure

```
tests/
├── unit/                    # Unit tests
│   ├── test_config.py      # Configuration tests
│   ├── test_scanner.py     # Scanner tests
│   ├── test_detectors/     # Detector tests
│   └── test_formatters/    # Formatter tests
├── integration/             # Integration tests
│   ├── test_cli.py         # CLI integration
│   ├── test_api.py         # API integration
│   └── test_formatters.py  # Output format tests
├── e2e/                     # End-to-end tests
│   ├── test_scan_flow.py   # Complete scan flow
│   └── test_api_server.py  # API server tests
└── fixtures/                # Test data
    ├── sample_projects/    # Test projects
    ├── vulnerabilities/    # Known vulnerabilities
    └── secrets/           # Test secrets
```

### Testing Strategy

**Unit Tests**:
- Fast execution (< 1 second per test)
- Isolated dependencies
- High coverage (90%+ for critical modules)

**Integration Tests**:
- Real file system operations
- CLI command testing
- Configuration validation

**E2E Tests**:
- Full scan workflows
- Performance benchmarks
- Real-world scenarios

---

## CLI Design

### Rich Terminal Interface

**Features**:
- Progress bars for long operations
- Syntax highlighting for code snippets
- Table formatting for results
- Color-coded severity levels
- Interactive confirmation prompts

**Design Principles**:
- Clear command structure
- Consistent option naming
- Helpful error messages
- Progress indication

### Command Structure

```
mcp-sentinel
├── scan          # Scan directory for vulnerabilities
├── server        # Start API server
├── config        # Configuration management
├── validate      # Validate configuration
└── version       # Show version information
```

---

## API Design

### FastAPI Architecture

**Phase 2 Implementation**:
- RESTful API design
- Async endpoint handlers
- Pydantic request/response models
- OpenAPI documentation
- Authentication support

### API Endpoints

```python
@app.post("/api/v1/scan")
async def scan_directory(request: ScanRequest) -> ScanResponse:
    """Scan directory for vulnerabilities."""
    pass

@app.get("/api/v1/health")
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    pass

@app.get("/api/v1/config")
async def get_config() -> ConfigResponse:
    """Get current configuration."""
    pass
```

---

## Security Architecture

### Security Principles

**Input Validation**:
- Path traversal protection
- File size limits
- Content type validation
- Regex safety checks

**Secure Defaults**:
- Conservative file patterns
- Limited concurrent operations
- Safe regex patterns
- Minimal permissions

**Error Handling**:
- No sensitive information in errors
- Safe error messages
- Logging without secrets
- Graceful failure modes

---

## Performance Considerations

### Optimization Strategies

**Async I/O**:
- Concurrent file processing
- Non-blocking operations
- Efficient memory usage
- Scalable architecture

**Regex Optimization**:
- Compiled patterns
- Efficient matching
- Context-aware detection
- Early termination

**Memory Management**:
- Streaming file processing
- Result batching
- Garbage collection optimization
- Resource cleanup

### Performance Targets

**Scanning Performance**:
- 1000 files in < 5 seconds
- Memory usage < 100MB for typical projects
- Concurrent file processing (10-20 files)
- Efficient regex matching

---

## Future Architecture Plans

### Phase 3: Complete Detector Parity (2 weeks)

**3 Remaining Detectors**:
1. **XSSDetector**: DOM-based, stored, reflected XSS
2. **ConfigSecurityDetector**: Insecure MCP configs, weak crypto
3. **PathTraversalDetector**: Directory traversal, zip slip

**Outcome**: 8/8 detectors → 100% parity with Rust

---

### Phase 4: Analysis Engines (6 weeks)

**Critical for 10x Detection Accuracy**:

1. **Semantic Analysis Engine** (2 weeks):
   - Tree-sitter integration (Python, JS, TS, Go)
   - Dataflow analysis (taint tracking)
   - Control flow analysis
   - Call graph construction

2. **SAST Integration** (1 week):
   - Semgrep community rules
   - Bandit Python security
   - Result normalization

3. **Static Analysis Engine** (1 week):
   - Centralized pattern registry
   - Pattern compilation and caching
   - Performance optimization

4. **AI Analysis Engine** (2 weeks):
   - LangChain integration
   - Multiple LLM providers (OpenAI, Anthropic, Google, Ollama)
   - RAG security knowledge base
   - Token management and cost tracking

**Outcome**: Context-aware, highly accurate detection

---

### Phase 5: Enterprise Platform (8 weeks)

**Production Infrastructure**:

1. **FastAPI Server** (2 weeks):
   - REST API (OpenAPI 3.1)
   - JWT authentication
   - Rate limiting
   - WebSocket support

2. **Database Layer** (2 weeks):
   - PostgreSQL + SQLAlchemy
   - Alembic migrations
   - Repository pattern
   - Redis caching

3. **Task Queue** (1 week):
   - Celery async processing
   - Background scans
   - Report generation
   - Scheduled jobs

4. **Reporting & Analytics** (2 weeks):
   - HTML reports (interactive)
   - PDF generation
   - SARIF 2.1.0 complete
   - Metrics and trends

5. **Key Integrations** (1 week):
   - Jira (issue tracking)
   - Slack (notifications)
   - HashiCorp Vault (secrets)

**Outcome**: Enterprise-ready deployment

---

### Phase 6: Threat Intelligence (2 weeks)

**Security Data Integration**:
1. VulnerableMCP API
2. MITRE ATT&CK framework
3. NVD CVE feed
4. Vulnerability enrichment

**Outcome**: Enhanced context for findings

---

### Phase 7: Advanced Integrations (3 weeks)

**15+ Enterprise Systems**:
- Additional ticketing (ServiceNow, Linear)
- Additional notifications (Teams, PagerDuty, Email)
- Cloud secrets (AWS Secrets Manager, Azure Key Vault)
- Logging (Splunk, Datadog, Elasticsearch)
- VCS (GitHub, GitLab, Bitbucket - complete)
- CI/CD (GitHub Actions, GitLab CI, Jenkins, CircleCI)

**Outcome**: Seamless enterprise integration

---

### Phase 8: Monitoring & Observability (2 weeks)

**Production Monitoring**:
1. Prometheus metrics
2. OpenTelemetry tracing
3. Structured logging
4. Sentry error tracking
5. Grafana dashboards

**Outcome**: Production-grade observability

---

## Architecture Benefits

### Current Benefits (Phase 1 + Phase 2)

1. **Async Performance**: Fast, concurrent file processing
2. **Type Safety**: 97%+ type hints, Pydantic models
3. **Modular Design**: Easy to extend and maintain
4. **Rich UX**: Beautiful terminal interface
5. **Comprehensive Detection**: 5 detectors, 47 patterns
6. **High Test Coverage**: 94.26% average, 151 tests
7. **Production Quality**: Enterprise-grade code
8. **Docker Ready**: Full stack containerization

### Future Benefits (Phase 3+)

1. **Complete Detection**: 100% Rust parity (8 detectors)
2. **AI-Powered**: Context-aware analysis
3. **API Integration**: RESTful + GraphQL APIs
4. **Enterprise Ready**: Multi-tenant, authentication
5. **Threat Intelligence**: Enriched findings
6. **Advanced Analytics**: Compliance scoring
7. **15+ Integrations**: Seamless enterprise workflows
8. **Production Monitoring**: Full observability

---

## Current Implementation Status

### ✅ Completed (Phase 1 + Phase 2)

**Infrastructure**:
- Modern Python project structure
- Poetry dependency management
- Docker + docker-compose
- GitHub Actions CI/CD
- Pre-commit hooks

**Core Framework**:
- Async scanner orchestrator
- Pydantic configuration
- Type-safe models
- Exception hierarchy
- Rich CLI output

**Detectors** (5/8 = 63%):
- SecretsDetector (15 patterns)
- CodeInjectionDetector (8 patterns)
- PromptInjectionDetector (7 patterns)
- ToolPoisoningDetector (6 patterns)
- SupplyChainDetector (11 patterns)

**Quality**:
- 94.26% test coverage
- 96.5% test pass rate
- 97%+ type hints
- Clean linting
- Comprehensive documentation

### 🚧 In Progress

**Next Phase**: Phase 3 - Complete Detector Parity
- XSSDetector
- ConfigSecurityDetector
- PathTraversalDetector

### 📋 Planned

See Future Architecture Plans above for detailed roadmap.

---

This architecture provides a solid foundation for the Python edition while maintaining flexibility for future enhancements. The async-first design ensures excellent performance, while the modular structure enables easy extension and maintenance.

**Version**: 2.0.0
**Last Updated**: 2026-01-06
**Status**: Production-Ready Foundation with 5 Detectors Operational