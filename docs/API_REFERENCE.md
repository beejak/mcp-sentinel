# MCP Sentinel — Python API Reference

**Version**: v0.2.0

MCP Sentinel v0.2.0 is a CLI tool. There is no REST API. This document covers the Python API for embedding the scanner programmatically in your own Python code.

---

## Quick start

```python
import asyncio
from pathlib import Path
from mcp_sentinel import MultiEngineScanner, Settings

async def main():
    settings = Settings()
    scanner = MultiEngineScanner(settings)
    result = await scanner.scan(Path("/path/to/mcp-server"))

    for vuln in result.vulnerabilities:
        print(f"{vuln.severity.upper():8} {vuln.title} — {vuln.file}:{vuln.line}")

asyncio.run(main())
```

---

## `Settings`

```python
from mcp_sentinel import Settings

settings = Settings(
    enable_static_analysis=True,   # bool, default True
    log_level="info",              # str: debug|info|warning|error
    max_workers=4,                 # int, concurrent file workers
    cache_ttl=3600,                # int, seconds (0 = disabled)
    environment="development",     # str: development|production|testing
)
```

All fields also read from environment variables (env var takes precedence over default).

---

## `MultiEngineScanner`

```python
from mcp_sentinel.core.multi_engine_scanner import MultiEngineScanner
from mcp_sentinel import Settings

scanner = MultiEngineScanner(settings)
```

### `scan(target: Path) -> ScanResult`

Scans a file or directory. Returns a `ScanResult`.

```python
result = await scanner.scan(Path("/path/to/server"))
```

### `scan(target: Path, progress_callback=None) -> ScanResult`

Optional callback called after each file is processed:

```python
def on_progress(file: Path, current: int, total: int):
    print(f"[{current}/{total}] {file}")

result = await scanner.scan(Path("."), progress_callback=on_progress)
```

### `get_active_engines() -> list[str]`

Returns the list of enabled engine names:

```python
scanner.get_active_engines()  # ["static"]
```

---

## `ScanResult`

```python
@dataclass
class ScanResult:
    vulnerabilities: list[Vulnerability]
    total_files_scanned: int
    scan_duration_seconds: float
    risk_score: float                  # 0.0–100.0
    errors: list[str]

    def get_by_severity(self, severity: str) -> list[Vulnerability]
    # severity: "critical" | "high" | "medium" | "low" | "info"
```

Example:

```python
result = await scanner.scan(Path("."))

print(f"Scanned {result.total_files_scanned} files in {result.scan_duration_seconds:.1f}s")
print(f"Risk score: {result.risk_score:.1f}/100")
print(f"Critical: {len(result.get_by_severity('critical'))}")
print(f"High:     {len(result.get_by_severity('high'))}")
```

---

## `Vulnerability`

```python
@dataclass
class Vulnerability:
    title: str
    description: str
    severity: str          # "critical" | "high" | "medium" | "low" | "info"
    file: Path
    line: int
    code_snippet: str
    remediation: str
    references: list[str]
    detector: str          # detector class name
    vuln_type: str         # vulnerability type identifier
    confidence: float      # 0.0–1.0
```

---

## Output formats

### SARIF

```python
from mcp_sentinel.reporting.generators.sarif_generator import SARIFGenerator

generator = SARIFGenerator()
sarif_data = generator.generate(result)

import json
with open("results.sarif", "w") as f:
    json.dump(sarif_data, f, indent=2)
```

### JSON

```python
import json
from dataclasses import asdict

data = {
    "vulnerabilities": [asdict(v) for v in result.vulnerabilities],
    "total_files_scanned": result.total_files_scanned,
    "risk_score": result.risk_score,
    "scan_duration_seconds": result.scan_duration_seconds,
}
with open("results.json", "w") as f:
    json.dump(data, f, indent=2, default=str)
```

---

## Detectors

Each detector is a standalone class that can be instantiated and called directly:

```python
from pathlib import Path
from mcp_sentinel.detectors.secrets import SecretsDetector

detector = SecretsDetector()

# Check if the detector applies to a file
if detector.is_applicable(Path("config.py")):
    vulns = await detector.detect(Path("config.py"), file_content)
    for v in vulns:
        print(v.title, v.line)
```

### Available detectors

| Import path | Class |
|---|---|
| `mcp_sentinel.detectors.secrets` | `SecretsDetector` |
| `mcp_sentinel.detectors.code_injection` | `CodeInjectionDetector` |
| `mcp_sentinel.detectors.prompt_injection` | `PromptInjectionDetector` |
| `mcp_sentinel.detectors.tool_poisoning` | `ToolPoisoningDetector` |
| `mcp_sentinel.detectors.path_traversal` | `PathTraversalDetector` |
| `mcp_sentinel.detectors.config_security` | `ConfigSecurityDetector` |
| `mcp_sentinel.detectors.ssrf` | `SSRFDetector` |
| `mcp_sentinel.detectors.network_binding` | `NetworkBindingDetector` |
| `mcp_sentinel.detectors.missing_auth` | `MissingAuthDetector` |

### Detector base interface

```python
class BaseDetector:
    name: str               # detector identifier
    enabled: bool           # default True

    def is_applicable(self, file: Path) -> bool: ...
    async def detect(self, file: Path, content: str) -> list[Vulnerability]: ...
```
