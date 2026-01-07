# API Design Specification

## Overview

This document defines the API design for the MCP Sentinel Python project, including the public CLI interface, programmatic API, plugin interfaces, and configuration schemas. The API is designed to be intuitive, consistent, and extensible while maintaining backward compatibility.

## Table of Contents

1. [API Design Principles](#api-design-principles)
2. [CLI Interface Design](#cli-interface-design)
3. [Programmatic API](#programmatic-api)
4. [Plugin API](#plugin-api)
5. [Configuration API](#configuration-api)
6. [Error Handling API](#error-handling-api)
7. [Versioning Strategy](#versioning-strategy)
8. [API Examples](#api-examples)

---

## API Design Principles

### Core Principles

1. **Consistency**: Uniform naming conventions and patterns across all APIs
2. **Intuitive**: Self-documenting interfaces that follow Python conventions
3. **Extensible**: Plugin architecture that allows easy extension
4. **Type Safe**: Comprehensive type hints and validation
5. **Async First**: Async/await patterns for I/O operations
6. **Backward Compatible**: Semantic versioning with deprecation warnings

### Naming Conventions

```python
# Function naming
scan_directory(path: Path) -> ScanResults  # Verb + Noun
get_detector(name: str) -> BaseDetector     # get_ + Noun
is_valid_file(path: Path) -> bool          # is_ + Adjective

# Class naming
class ScanResults:                          # PascalCase, Noun
class BaseDetector:                         # PascalCase, Descriptive
class FileProcessingError:                  # PascalCase, Exception

# Constant naming
MAX_FILE_SIZE = 100 * 1024 * 1024        # UPPER_SNAKE_CASE
DEFAULT_TIMEOUT = 30                     # UPPER_SNAKE_CASE
```

---

## CLI Interface Design

### Command Structure

```bash
mcp-sentinel [OPTIONS] COMMAND [ARGS]...
```

### Core Commands

```python
@click.group()
@click.option('--config', '-c', type=click.Path(), help='Configuration file path')
@click.option('--verbose', '-v', count=True, help='Increase verbosity')
@click.option('--quiet', '-q', is_flag=True, help='Suppress output')
@click.pass_context
def cli(ctx, config, verbose, quiet):
    """MCP Sentinel - Security vulnerability scanner."""
    ctx.ensure_object(dict)
    ctx.obj['config'] = load_config(config)
    ctx.obj['verbose'] = verbose
    ctx.obj['quiet'] = quiet

@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Choice(['json', 'csv', 'xml']), default='json')
@click.option('--output-file', '-f', type=click.Path(), help='Output file path')
@click.option('--detectors', '-d', multiple=True, help='Specific detectors to run')
@click.option('--exclude', '-e', multiple=True, help='Patterns to exclude')
@click.option('--severity', '-s', type=click.Choice(['low', 'medium', 'high', 'critical']), help='Minimum severity')
@click.option('--max-depth', type=int, help='Maximum directory depth')
@click.option('--concurrent', type=int, default=20, help='Maximum concurrent files')
@click.pass_context
def scan(ctx, path, output, output_file, detectors, exclude, severity, max_depth, concurrent):
    """Scan directory for security vulnerabilities."""
    # Implementation

@cli.command()
@click.option('--list', '-l', 'list_detectors', is_flag=True, help='List available detectors')
@click.option('--info', '-i', help='Show detailed info about a detector')
@click.pass_context
def detectors(ctx, list_detectors, info):
    """Manage vulnerability detectors."""
    # Implementation

@cli.command()
@click.pass_context
def config(ctx):
    """Manage configuration settings."""
    # Implementation
```

### CLI Options Reference

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--config` | `-c` | Path | None | Configuration file path |
| `--output` | `-o` | Choice | json | Output format |
| `--output-file` | `-f` | Path | None | Output file path |
| `--detectors` | `-d` | Multiple | All | Specific detectors to run |
| `--exclude` | `-e` | Multiple | None | Exclude patterns |
| `--severity` | `-s` | Choice | low | Minimum severity level |
| `--max-depth` | None | Int | None | Maximum directory depth |
| `--concurrent` | None | Int | 20 | Max concurrent files |
| `--verbose` | `-v` | Count | 0 | Verbosity level |
| `--quiet` | `-q` | Flag | False | Suppress output |

---

## Programmatic API

### Main Scanner API

```python
from pathlib import Path
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
import asyncio

class ScanResults(BaseModel):
    """Scan results data model."""
    total_files: int
    scanned_files: int
    vulnerabilities: List[Vulnerability]
    scan_duration: float
    errors: List[str]
    summary: Dict[str, Any]

class Vulnerability(BaseModel):
    """Vulnerability data model."""
    file_path: Path
    line_number: int
    severity: str  # 'low', 'medium', 'high', 'critical'
    detector_name: str
    description: str
    recommendation: str
    context: str
    rule_id: str
    confidence: float  # 0.0 to 1.0

class Config(BaseModel):
    """Configuration data model."""
    max_concurrent_files: int = 20
    timeout_seconds: int = 30
    severity_threshold: str = "low"
    exclude_patterns: List[str] = []
    include_patterns: List[str] = ["*"]
    max_file_size: int = 100 * 1024 * 1024  # 100MB
    output_format: str = "json"
    detectors: List[str] = []  # Empty means all
    
class MCPSentinel:
    """Main scanner class."""
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize scanner with configuration."""
        self.config = config or Config()
        self.detector_manager = DetectorManager()
        self.orchestrator = ScannerOrchestrator(self.config)
    
    async def scan_directory(self, path: Path) -> ScanResults:
        """Scan directory for vulnerabilities."""
        return await self.orchestrator.scan_directory(path)
    
    async def scan_file(self, file_path: Path) -> List[Vulnerability]:
        """Scan single file for vulnerabilities."""
        return await self.orchestrator.scan_file(file_path)
    
    async def scan_files(self, files: List[Path]) -> ScanResults:
        """Scan multiple files for vulnerabilities."""
        return await self.orchestrator.scan_files(files)
    
    def get_available_detectors(self) -> List[str]:
        """Get list of available detectors."""
        return self.detector_manager.list_detectors()
    
    def get_detector_info(self, detector_name: str) -> Dict[str, Any]:
        """Get detailed information about a detector."""
        return self.detector_manager.get_detector_info(detector_name)
```

### Async Context Manager API

```python
class ScannerSession:
    """Context manager for scanner sessions."""
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.scanner = None
    
    async def __aenter__(self):
        """Enter async context."""
        self.scanner = MCPSentinel(self.config)
        await self.scanner.initialize()
        return self.scanner
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit async context."""
        if self.scanner:
            await self.scanner.cleanup()

# Usage example
async with ScannerSession() as scanner:
    results = await scanner.scan_directory(Path("/path/to/scan"))
    print(f"Found {len(results.vulnerabilities)} vulnerabilities")
```

---

## Plugin API

### Base Detector Interface

```python
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from pathlib import Path

class BaseDetector(ABC):
    """Base class for all vulnerability detectors."""
    
    @abstractmethod
    async def detect(self, file_path: Path, content: str) -> List[Vulnerability]:
        """
        Detect vulnerabilities in file content.
        
        Args:
            file_path: Path to the file being scanned
            content: File content as string
            
        Returns:
            List of detected vulnerabilities
        """
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Detector name."""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Detector description."""
        pass
    
    @property
    @abstractmethod
    def severity_level(self) -> str:
        """Default severity level ('low', 'medium', 'high', 'critical')."""
        pass
    
    @property
    def supported_file_types(self) -> List[str]:
        """List of supported file extensions. Empty list means all types."""
        return []
    
    @property
    def max_file_size(self) -> int:
        """Maximum file size in bytes. 0 means no limit."""
        return 0
    
    async def initialize(self) -> None:
        """Initialize detector (optional)."""
        pass
    
    async def cleanup(self) -> None:
        """Cleanup detector resources (optional)."""
        pass
```

### Detector Registration

```python
class DetectorManager:
    """Manages detector registration and lifecycle."""
    
    def register_detector(self, detector_class: type) -> None:
        """Register a detector class."""
        if not issubclass(detector_class, BaseDetector):
            raise ValueError("Detector must inherit from BaseDetector")
        
        # Registration logic
    
    def unregister_detector(self, detector_name: str) -> None:
        """Unregister a detector."""
        # Unregistration logic
    
    def get_detector(self, name: str) -> BaseDetector:
        """Get detector instance by name."""
        # Retrieval logic
    
    def list_detectors(self) -> List[str]:
        """List all registered detector names."""
        # Listing logic

# Example detector implementation
class SecretDetector(BaseDetector):
    """Detector for hardcoded secrets."""
    
    def __init__(self):
        self.patterns = self._compile_patterns()
    
    @property
    def name(self) -> str:
        return "secrets"
    
    @property
    def description(self) -> str:
        return "Detects hardcoded secrets and credentials"
    
    @property
    def severity_level(self) -> str:
        return "critical"
    
    async def detect(self, file_path: Path, content: str) -> List[Vulnerability]:
        vulnerabilities = []
        
        for pattern_name, pattern in self.patterns.items():
            for match in pattern.finditer(content):
                vulnerability = Vulnerability(
                    file_path=file_path,
                    line_number=self._get_line_number(content, match.start()),
                    severity="critical",
                    detector_name=self.name,
                    description=f"Potential {pattern_name} detected",
                    recommendation="Use environment variables or secure vaults",
                    context=match.group(0),
                    rule_id=f"secret_{pattern_name}",
                    confidence=0.8
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
```

---

## Configuration API

### Configuration Schema

```python
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from pathlib import Path

class DetectorConfig(BaseModel):
    """Individual detector configuration."""
    enabled: bool = True
    severity: str = "medium"
    exclude_patterns: List[str] = []
    custom_rules: List[Dict[str, Any]] = []
    
    @validator('severity')
    def validate_severity(cls, v):
        if v not in ['low', 'medium', 'high', 'critical']:
            raise ValueError('Severity must be low, medium, high, or critical')
        return v

class OutputConfig(BaseModel):
    """Output configuration."""
    format: str = "json"
    file_path: Optional[Path] = None
    include_metadata: bool = True
    pretty_print: bool = True
    
    @validator('format')
    def validate_format(cls, v):
        if v not in ['json', 'csv', 'xml', 'sarif']:
            raise ValueError('Format must be json, csv, xml, or sarif')
        return v

class PerformanceConfig(BaseModel):
    """Performance tuning configuration."""
    max_concurrent_files: int = Field(default=20, ge=1, le=100)
    timeout_seconds: int = Field(default=30, ge=5, le=300)
    memory_limit_mb: int = Field(default=512, ge=128, le=4096)
    batch_size: int = Field(default=50, ge=10, le=200)
    
    @validator('max_concurrent_files')
    def validate_concurrency(cls, v):
        if v > 50:
            import warnings
            warnings.warn("High concurrency may impact performance")
        return v

class LoggingConfig(BaseModel):
    """Logging configuration."""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: Optional[Path] = None
    max_file_size_mb: int = 100
    backup_count: int = 5
    
    @validator('level')
    def validate_level(cls, v):
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v not in valid_levels:
            raise ValueError(f'Level must be one of {valid_levels}')
        return v

class SecurityConfig(BaseModel):
    """Security-related configuration."""
    max_file_size: int = Field(default=100*1024*1024, description="Max file size in bytes")
    exclude_hidden_files: bool = True
    follow_symlinks: bool = False
    validate_file_paths: bool = True
    
class Config(BaseModel):
    """Main configuration class."""
    # Core settings
    detectors: Dict[str, DetectorConfig] = {}
    output: OutputConfig = OutputConfig()
    performance: PerformanceConfig = PerformanceConfig()
    logging: LoggingConfig = LoggingConfig()
    security: SecurityConfig = SecurityConfig()
    
    # Global settings
    severity_threshold: str = "low"
    exclude_patterns: List[str] = []
    include_patterns: List[str] = ["*"]
    
    # Environment-specific overrides
    environment: str = "production"
    
    class Config:
        env_prefix = "MCP_SENTINEL_"
        case_sensitive = False
        validate_assignment = True
```

### Configuration Loading

```python
class ConfigManager:
    """Manages configuration loading and validation."""
    
    @staticmethod
    def load_from_file(config_path: Path) -> Config:
        """Load configuration from file."""
        import yaml
        
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f)
        
        return Config(**config_data)
    
    @staticmethod
    def load_from_env() -> Config:
        """Load configuration from environment variables."""
        return Config()  # Pydantic will auto-load from env
    
    @staticmethod
    def load_merged(config_path: Optional[Path] = None) -> Config:
        """Load configuration with file override."""
        config = Config()
        
        if config_path and config_path.exists():
            file_config = ConfigManager.load_from_file(config_path)
            # Merge configurations
            config = ConfigManager.merge_configs(config, file_config)
        
        return config
    
    @staticmethod
    def merge_configs(base: Config, override: Config) -> Config:
        """Merge two configuration objects."""
        # Deep merge logic
        base_dict = base.dict()
        override_dict = override.dict()
        
        merged = deep_merge(base_dict, override_dict)
        return Config(**merged)
```

---

## Error Handling API

### Exception Hierarchy

```python
class MCPSentinelError(Exception):
    """Base exception for all MCP Sentinel errors."""
    
    def __init__(self, message: str, error_code: str = None, details: Dict[str, Any] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or "UNKNOWN_ERROR"
        self.details = details or {}

class ConfigurationError(MCPSentinelError):
    """Configuration-related errors."""
    
    def __init__(self, message: str, config_key: str = None, details: Dict[str, Any] = None):
        super().__init__(message, "CONFIG_ERROR", details)
        self.config_key = config_key

class ScannerError(MCPSentinelError):
    """Scanner operation errors."""
    
    def __init__(self, message: str, file_path: Path = None, details: Dict[str, Any] = None):
        super().__init__(message, "SCANNER_ERROR", details)
        self.file_path = file_path

class DetectorError(MCPSentinelError):
    """Detector-specific errors."""
    
    def __init__(self, message: str, detector_name: str = None, details: Dict[str, Any] = None):
        super().__init__(message, "DETECTOR_ERROR", details)
        self.detector_name = detector_name

class ValidationError(MCPSentinelError):
    """Input validation errors."""
    
    def __init__(self, message: str, field: str = None, value: Any = None, details: Dict[str, Any] = None):
        super().__init__(message, "VALIDATION_ERROR", details)
        self.field = field
        self.value = value

class TimeoutError(MCPSentinelError):
    """Operation timeout errors."""
    
    def __init__(self, message: str, timeout_seconds: int = None, details: Dict[str, Any] = None):
        super().__init__(message, "TIMEOUT_ERROR", details)
        self.timeout_seconds = timeout_seconds
```

### Error Response Format

```python
class ErrorResponse(BaseModel):
    """Standard error response format."""
    
    error: str
    error_code: str
    message: str
    details: Dict[str, Any] = {}
    timestamp: datetime
    path: Optional[str] = None
    suggestion: Optional[str] = None
    
    @classmethod
    def from_exception(cls, exc: MCPSentinelError) -> 'ErrorResponse':
        """Create error response from exception."""
        return cls(
            error=exc.__class__.__name__,
            error_code=exc.error_code,
            message=exc.message,
            details=exc.details,
            timestamp=datetime.now(),
            suggestion=cls._get_suggestion(exc.error_code)
        )
    
    @staticmethod
    def _get_suggestion(error_code: str) -> Optional[str]:
        """Get helpful suggestion based on error code."""
        suggestions = {
            "CONFIG_ERROR": "Check your configuration file format and values",
            "SCANNER_ERROR": "Verify file permissions and path accessibility",
            "DETECTOR_ERROR": "Check detector logs for detailed error information",
            "VALIDATION_ERROR": "Ensure input values meet validation requirements",
            "TIMEOUT_ERROR": "Consider increasing timeout values for large files"
        }
        return suggestions.get(error_code)
```

---

## Versioning Strategy

### Semantic Versioning

```python
class Version:
    """Version management following semantic versioning."""
    
    def __init__(self, major: int, minor: int, patch: int, pre_release: Optional[str] = None):
        self.major = major
        self.minor = minor
        self.patch = patch
        self.pre_release = pre_release
    
    def __str__(self) -> str:
        version = f"{self.major}.{self.minor}.{self.patch}"
        if self.pre_release:
            version += f"-{self.pre_release}"
        return version
    
    def is_compatible(self, other: 'Version') -> bool:
        """Check if versions are compatible (same major version)."""
        return self.major == other.major
    
    def __lt__(self, other: 'Version') -> bool:
        """Compare versions for compatibility checks."""
        # Implementation

# Current version
CURRENT_VERSION = Version(1, 0, 0)
API_VERSION = "v1"
```

### API Versioning

```python
class APIVersion:
    """API version management."""
    
    SUPPORTED_VERSIONS = ["v1"]
    CURRENT_VERSION = "v1"
    DEPRECATED_VERSIONS = []
    
    @classmethod
    def validate_version(cls, version: str) -> bool:
        """Validate API version."""
        if version not in cls.SUPPORTED_VERSIONS:
            raise ValidationError(f"Unsupported API version: {version}")
        return True
    
    @classmethod
    def check_deprecation(cls, version: str) -> Optional[str]:
        """Check if version is deprecated."""
        if version in cls.DEPRECATED_VERSIONS:
            return f"API version {version} is deprecated and will be removed in a future release"
        return None
```

---

## API Examples

### Basic Scanning

```python
import asyncio
from pathlib import Path
from mcp_sentinel import MCPSentinel, Config

async def basic_scan():
    """Basic directory scanning example."""
    # Create scanner with default config
    scanner = MCPSentinel()
    
    # Scan directory
    results = await scanner.scan_directory(Path("/path/to/scan"))
    
    # Process results
    print(f"Scanned {results.scanned_files} files")
    print(f"Found {len(results.vulnerabilities)} vulnerabilities")
    
    for vuln in results.vulnerabilities:
        print(f"{vuln.severity}: {vuln.file_path}:{vuln.line_number} - {vuln.description}")

# Run the scan
asyncio.run(basic_scan())
```

### Advanced Configuration

```python
async def advanced_scan():
    """Advanced scanning with custom configuration."""
    
    # Create custom configuration
    config = Config(
        max_concurrent_files=50,
        severity_threshold="medium",
        exclude_patterns=["*.log", "node_modules/*", ".git/*"],
        detectors=["secrets", "sql_injection", "xss"]
    )
    
    # Create scanner with custom config
    scanner = MCPSentinel(config)
    
    # Scan specific files
    files = [Path("app.py"), Path("config.py"), Path("database.py")]
    results = await scanner.scan_files(files)
    
    # Export results
    if results.vulnerabilities:
        scanner.export_results(results, format="json", output_path="scan_results.json")

asyncio.run(advanced_scan())
```

### Custom Detector Implementation

```python
from mcp_sentinel import BaseDetector, Vulnerability
from pathlib import Path
import re

class CustomSQLDetector(BaseDetector):
    """Custom SQL injection detector."""
    
    def __init__(self):
        self.sql_patterns = [
            re.compile(r"SELECT.*FROM.*WHERE.*\+.*", re.IGNORECASE),
            re.compile(r"INSERT.*INTO.*VALUES.*\+.*", re.IGNORECASE),
            re.compile(r"UPDATE.*SET.*\+.*WHERE", re.IGNORECASE)
        ]
    
    @property
    def name(self) -> str:
        return "custom_sql_injection"
    
    @property
    def description(self) -> str:
        return "Custom SQL injection vulnerability detector"
    
    @property
    def severity_level(self) -> str:
        return "high"
    
    async def detect(self, file_path: Path, content: str) -> List[Vulnerability]:
        vulnerabilities = []
        
        for line_num, line in enumerate(content.split('\n'), 1):
            for pattern in self.sql_patterns:
                if pattern.search(line):
                    vulnerability = Vulnerability(
                        file_path=file_path,
                        line_number=line_num,
                        severity="high",
                        detector_name=self.name,
                        description="Potential SQL injection vulnerability",
                        recommendation="Use parameterized queries or prepared statements",
                        context=line.strip(),
                        rule_id="custom_sql_concat",
                        confidence=0.7
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities

# Register custom detector
async def scan_with_custom_detector():
    scanner = MCPSentinel()
    scanner.detector_manager.register_detector(CustomSQLDetector)
    
    results = await scanner.scan_directory(Path("/path/to/scan"))
    print(f"Custom detector found {len([v for v in results.vulnerabilities if v.detector_name == 'custom_sql_injection'])} SQL injection vulnerabilities")

asyncio.run(scan_with_custom_detector())
```

### Error Handling

```python
async def robust_scanning():
    """Example with comprehensive error handling."""
    
    try:
        scanner = MCPSentinel()
        results = await scanner.scan_directory(Path("/path/to/scan"))
        
    except ValidationError as e:
        print(f"Configuration error: {e.message}")
        print(f"Field: {e.field}, Value: {e.value}")
        
    except ScannerError as e:
        print(f"Scanning failed: {e.message}")
        if e.file_path:
            print(f"Problematic file: {e.file_path}")
            
    except TimeoutError as e:
        print(f"Operation timed out after {e.timeout_seconds} seconds")
        print("Consider increasing timeout for large files")
        
    except MCPSentinelError as e:
        print(f"Error: {e.message}")
        print(f"Error code: {e.error_code}")
        if e.details:
            print(f"Details: {e.details}")
        
    else:
        # Success case
        print(f"Scan completed successfully: {results.summary}")

asyncio.run(robust_scanning())
```

---

## API Testing

### Test Structure

```python
import pytest
from pathlib import Path
from mcp_sentinel import MCPSentinel, Config

class TestMCPSentinelAPI:
    """Test suite for MCP Sentinel API."""
    
    @pytest.fixture
    async def scanner(self):
        """Create scanner instance for testing."""
        config = Config(
            max_concurrent_files=5,
            severity_threshold="low"
        )
        return MCPSentinel(config)
    
    @pytest.mark.asyncio
    async def test_scan_directory(self, scanner, temp_directory):
        """Test directory scanning."""
        # Create test files
        test_file = temp_directory / "test.py"
        test_file.write_text("password = 'hardcoded123'")
        
        # Scan directory
        results = await scanner.scan_directory(temp_directory)
        
        # Validate results
        assert results.total_files >= 1
        assert results.scanned_files >= 1
        assert isinstance(results.vulnerabilities, list)
    
    @pytest.mark.asyncio
    async def test_scan_file(self, scanner, temp_file):
        """Test single file scanning."""
        temp_file.write_text("api_key = 'secret123'")
        
        vulnerabilities = await scanner.scan_file(temp_file)
        
        assert isinstance(vulnerabilities, list)
        # Should detect hardcoded secret
        assert any(v.detector_name == "secrets" for v in vulnerabilities)
    
    def test_configuration_validation(self):
        """Test configuration validation."""
        # Valid configuration
        config = Config(max_concurrent_files=10)
        assert config.max_concurrent_files == 10
        
        # Invalid configuration should raise ValidationError
        with pytest.raises(ValidationError):
            Config(max_concurrent_files=0)  # Below minimum
```

---

## API Documentation Standards

### Documentation Requirements

1. **Docstrings**: All public methods must have comprehensive docstrings
2. **Type Hints**: All parameters and return values must have type hints
3. **Examples**: Complex APIs must include usage examples
4. **Error Handling**: All possible exceptions must be documented
5. **Version Information**: API changes must be versioned and documented

### Documentation Format

```python
def scan_directory(self, path: Path, recursive: bool = True) -> ScanResults:
    """
    Scan directory for security vulnerabilities.
    
    Args:
        path: Directory path to scan
        recursive: Whether to scan subdirectories recursively
        
    Returns:
        ScanResults object containing:
            - total_files: Total number of files found
            - scanned_files: Number of files actually scanned
            - vulnerabilities: List of detected vulnerabilities
            - scan_duration: Time taken to complete scan
            - errors: List of errors encountered during scanning
            
    Raises:
        ValidationError: If path is invalid or inaccessible
        ScannerError: If scanning operation fails
        TimeoutError: If scanning takes longer than configured timeout
        
    Example:
        >>> scanner = MCPSentinel()
        >>> results = await scanner.scan_directory(Path("/app/code"))
        >>> print(f"Found {len(results.vulnerabilities)} vulnerabilities")
        
    Note:
        This method respects all configuration settings including
        exclude patterns, file size limits, and detector selection.
        
    Since: 1.0.0
    """
```

---

## Related Documents

- [SYSTEM_DESIGN_SPECIFICATION.md](./SYSTEM_DESIGN_SPECIFICATION.md) - System architecture details
- [PERFORMANCE_REQUIREMENTS.md](./PERFORMANCE_REQUIREMENTS.md) - Performance specifications
- [ERROR_HANDLING_STRATEGY.md](./ERROR_HANDLING_STRATEGY.md) - Comprehensive error handling
- [TEST_STRATEGY.md](./TEST_STRATEGY.md) - API testing strategies

---

*This API specification should be updated whenever public interfaces change. All changes must follow semantic versioning and include appropriate deprecation notices.*

**API Version**: v1  
**Last Updated**: January 2026  
**Status**: Review Ready*