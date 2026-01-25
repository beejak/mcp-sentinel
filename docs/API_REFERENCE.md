# MCP Sentinel - API Reference

**Version**: v1.0.0
**Base URL**: `/api/v1`

## Overview

The MCP Sentinel API provides programmatic access to the multi-engine vulnerability scanner. It allows you to trigger scans, retrieve results, and check system health.

## Endpoints

### 1. Trigger Scan

Initiates a vulnerability scan on a specified file or directory.

- **URL**: `/scan`
- **Method**: `POST`
- **Auth**: Required (Bearer Token) - *Note: Auth implementation depends on configuration*

#### Request Body

```json
{
  "path": "/absolute/path/to/scan",
  "engines": ["static", "sast", "semantic", "ai"],
  "recursive": true
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `path` | string | Yes | Absolute path to the file or directory to scan. |
| `engines` | array[string] | No | List of engines to use. Defaults to all available. |
| `recursive` | boolean | No | Whether to scan subdirectories recursively. Default: `true`. |

#### Response (200 OK)

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "target_path": "/absolute/path/to/scan",
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "title": "Hardcoded Secret",
      "severity": "critical",
      "file_path": "/path/to/file.py",
      "line": 42,
      "engine": "static"
    }
  ],
  "total_vulnerabilities": 1,
  "duration": 1.25,
  "timestamp": "2026-01-25T10:00:00Z"
}
```

#### Error Responses

- **404 Not Found**: If the specified path does not exist.
- **500 Internal Server Error**: If the scan fails unexpectedly.

### 2. Health Check

Checks the status of the API server.

- **URL**: `/health`
- **Method**: `GET`
- **Auth**: None

#### Response (200 OK)

```json
{
  "status": "ok",
  "version": "1.0.0"
}
```

## Schemas

### ScanRequest

```python
class ScanRequest(BaseModel):
    path: str
    engines: Optional[List[str]] = None
    recursive: bool = True
```

### ScanResponse

```python
class ScanResponse(BaseModel):
    scan_id: UUID
    status: str
    target_path: str
    vulnerabilities: List[Vulnerability]
    total_vulnerabilities: int
    duration: float
    timestamp: str
```
