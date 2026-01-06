# Python Edition Architecture Documentation

**Version**: 1.0.0
**Date**: 2026-01-06
**Repository**: mcp-sentinel-python
**Status**: Production Ready (Phase 1 Complete)

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
├── detectors/               # Vulnerability detectors
│   ├── __init__.py
│   ├── base.py             # Base detector class
│   ├── secrets.py          # Secrets detection (300 lines)
│   ├── injection.py        # Code injection detection
│   └── file_access.py      # Sensitive file access
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

**Secrets Detector (300 lines)**:
- 15+ secret patterns
- Regex optimization
- Context-aware detection
- Confidence scoring

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

### Phase 2 (Q1 2026)

**API Server**:
- FastAPI implementation
- Authentication support
- Rate limiting
- Background job processing

**Advanced Output Formats**:
- SARIF format support
- HTML report generation
- PDF export capability
- Custom format plugins

**Enhanced Detection**:
- Machine learning integration
- Semantic analysis
- Context-aware detection
- False positive reduction

### Phase 3 (Q2 2026)

**Plugin Architecture**:
- Custom detector plugins
- Output format plugins
- Integration plugins
- Community marketplace

**Enterprise Features**:
- Multi-tenant support
- Advanced authentication
- Audit logging
- Compliance reporting

**Performance Enhancements**:
- Distributed scanning
- Caching layer
- Database persistence
- Advanced optimization

---

## Architecture Benefits

### Current Benefits (Phase 1)

1. **Async Performance**: Fast, concurrent file processing
2. **Type Safety**: Reduced runtime errors with mypy
3. **Modular Design**: Easy to extend and maintain
4. **Rich UX**: Beautiful terminal interface
5. **Configuration**: Flexible, validated settings
6. **Testing**: Comprehensive test coverage

### Future Benefits (Phase 2+)

1. **API Integration**: RESTful API for integration
2. **Plugin System**: Extensible architecture
3. **Enterprise Ready**: Multi-tenant, authentication
4. **Advanced Detection**: ML-powered analysis
5. **Performance**: Distributed scanning capabilities

---

This architecture provides a solid foundation for the Python edition while maintaining flexibility for future enhancements. The async-first design ensures excellent performance, while the modular structure enables easy extension and maintenance.