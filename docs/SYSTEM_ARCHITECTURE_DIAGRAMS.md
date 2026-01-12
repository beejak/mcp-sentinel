# System Architecture Diagrams

## Overview

This document provides comprehensive architecture diagrams for the MCP Sentinel Python project, illustrating the system's design patterns, component relationships, and data flow. These diagrams serve as visual documentation for developers, architects, and stakeholders to understand the system's structure and behavior.

## Table of Contents

1. [High-Level Architecture](#high-level-architecture)
2. [Component Diagram](#component-diagram)
3. [Data Flow Diagram](#data-flow-diagram)
4. [Sequence Diagrams](#sequence-diagrams)
5. [Deployment Architecture](#deployment-architecture)
6. [Security Architecture](#security-architecture)
7. [Performance Architecture](#performance-architecture)

---

## High-Level Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           MCP Sentinel Python                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐      │
│  │   CLI Layer     │────▶│  Scanner Core    │────▶│  Output Layer    │      │
│  │  (Rich/Click)   │     │  (Async Engine)  │     │ (JSON/CSV/XML)   │      │
│  └─────────────────┘     └──────────────────┘     └──────────────────┘      │
│          │                       │                       │                   │
│          ▼                       ▼                       ▼                   │
│  ┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐      │
│  │  Configuration  │     │  Detector Chain  │     │   Reporting      │      │
│  │  (Pydantic)     │     │  (Plugin System) │     │  (Templates)     │      │
│  └─────────────────┘     └──────────────────┘     └──────────────────┘      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Supporting Systems                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐    │
│  │   File System   │     │   Async I/O      │     │   Logging/       │    │
│  │   (Pathlib)     │     │  (aiofiles)      │     │   Telemetry      │    │
│  └─────────────────┘     └──────────────────┘     └──────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Components Description

- **CLI Layer**: User interface using Rich library for enhanced terminal output and Click for command parsing
- **Scanner Core**: Async engine that orchestrates file processing and vulnerability detection
- **Detector Chain**: Plugin-based system for running multiple vulnerability detectors
- **Configuration**: Type-safe configuration management using Pydantic BaseSettings
- **Output Layer**: Flexible output formatting supporting JSON, CSV, and XML formats
- **Reporting**: Template-based report generation with customizable formats

---

## Component Diagram

### Detailed Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Scanner Orchestrator                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    ScannerOrchestrator                              │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐ │  │
│  │  │                     Configuration                               │ │  │
│  │  │  - max_concurrent_files: int = 10                            │ │  │
│  │  │  - timeout_seconds: int = 30                                 │ │  │
│  │  │  - retry_attempts: int = 3                                   │ │  │
│  │  │  - batch_size: int = 50                                      │ │  │
│  │  └─────────────────────────────────────────────────────────────────┘ │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐ │  │
│  │  │                   Circuit Breaker                              │ │  │
│  │  │  - error_threshold: float = 0.1                              │ │  │
│  │  │  - reset_timeout: int = 60                                   │ │  │
│  │  │  - should_continue_scanning()                               │ │  │
│  │  └─────────────────────────────────────────────────────────────────┘ │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐ │  │
│  │  │                    Async Pipeline                              │ │  │
│  │  │  - input_queue: asyncio.Queue(maxsize=100)                    │ │  │
│  │  │  - processing_semaphore: asyncio.Semaphore(20)                │ │  │
│  │  │  - output_queue: asyncio.Queue(maxsize=100)                   │ │  │
│  │  │  - process_files_stream()                                     │ │  │
│  │  └─────────────────────────────────────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Detector Manager                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                     DetectorManager                                 │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐ │  │
│  │  │                  Health Monitoring                             │ │  │
│  │  │  - detector_health: Dict[str, bool]                          │ │  │
│  │  │  - last_successful_run: Dict[str, datetime]                 │ │  │
│  │  │  - disable_unhealthy_detectors()                           │ │  │
│  │  └─────────────────────────────────────────────────────────────────┘ │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐ │  │
│  │  │              Detector Registration                             │ │  │
│  │  │  - register_detector(BaseDetector)                         │ │  │
│  │  │  - get_detector(name: str) -> BaseDetector                  │ │  │
│  │  │  - list_detectors() -> List[str]                          │ │  │
│  │  └─────────────────────────────────────────────────────────────────┘ │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐ │  │
│  │  │              Parallel Execution                                │ │  │
│  │  │  - run_detectors(file_path, content) -> List[Vulnerability] │ │  │
│  │  │  - semaphore-based concurrency control                     │ │  │
│  │  └─────────────────────────────────────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      Base Detector Interface                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    BaseDetector (ABC)                               │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐ │  │
│  │  │               Abstract Methods                                  │ │  │
│  │  │  - detect(file_path, content) -> List[Vulnerability]        │ │  │
│  │  │  - get_name() -> str                                          │ │  │
│  │  │  - get_description() -> str                                   │ │  │
│  │  │  - get_severity_level() -> Severity                           │ │  │
│  │  └─────────────────────────────────────────────────────────────────┘ │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐ │  │
│  │  │              Common Utilities                                   │ │  │
│  │  │  - regex_patterns: Dict[str, Pattern]                        │ │  │
│  │  │  - validate_content(content) -> bool                         │ │  │
│  │  │  - extract_context(line, match) -> str                       │ │  │
│  │  └─────────────────────────────────────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow Diagram

### Scanning Process Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   User CLI  │────▶│   Config    │────▶│   Scanner   │────▶│  Detector   │
│   Command   │     │  Validation │     │Orchestrator │     │   Manager   │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
      │                   │                   │                   │
      ▼                   ▼                   ▼                   ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Argument   │     │  Pydantic   │     │   Async     │     │   Plugin    │
│   Parsing   │     │   Config    │     │  Pipeline   │     │  Registry   │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
      │                   │                   │                   │
      ▼                   ▼                   ▼                   ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Rich UI    │     │  Type Safe  │     │  Semaphore  │     │  Detector   │
│   Output    │     │  Settings   │     │ Concurrency │     │   Chain     │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                            │
                            ▼
                    ┌─────────────┐
                    │   File      │
                    │ Processing  │
                    │   Stream    │
                    └─────────────┘
                            │
                            ▼
                    ┌─────────────┐     ┌─────────────┐
                    │Vulnerability│────▶│   Report    │
                    │ Detection   │     │ Generation  │
                    └─────────────┘     └─────────────┘
```

### Async Processing Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Async Processing Pipeline                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐│
│  │ Input Queue │────▶│  Semaphore  │────▶│ Processing  │────▶│ Output Queue││
│  │  (Files)    │     │   (Limit)   │     │  Workers    │     │ (Results)   ││
│  └─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘│
│         │                  │                     │                  │        │
│         ▼                  ▼                     ▼                  ▼        │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐│
│  │  Backpressure│    │ Concurrency │    │   Timeout   │     │  Results    ││
│  │  Handling   │     │   Control   │     │   Control   │     │ Aggregation ││
│  └─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘│
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Sequence Diagrams

### File Scanning Sequence

```
User          CLI         Scanner      Detector    File System
 │             │            │            │            │
 │ scan cmd    │            │            │            │
 │────────────▶│            │            │            │
 │             │            │            │            │
 │             │ validate   │            │            │
 │             │──────────▶│            │            │
 │             │            │            │            │
 │             │            │ get files  │            │
 │             │            │───────────▶│            │
 │             │            │            │            │
 │             │            │            │ read dir   │
 │             │            │            │───────────▶│
 │             │            │            │◀───────────│
 │             │            │            │ file list  │
 │             │            │◀───────────│            │
 │             │            │            │            │
 │             │            │ process    │            │
 │             │            │ files      │            │
 │             │            │───────────▶│            │
 │             │            │            │            │
 │             │            │            │ detect()   │
 │             │            │            │───────────▶│
 │             │            │            │◀───────────│
 │             │            │            │ results    │
 │             │            │◀───────────│            │
 │             │            │            │            │
 │             │            │ aggregate  │            │
 │             │            │ results    │            │
 │             │            │───────────▶│            │
 │             │            │            │            │
 │             │            │ generate   │            │
 │             │            │ report     │            │
 │             │            │───────────▶│            │
 │             │            │            │            │
 │             │◀───────────│            │            │
 │ results     │            │            │            │
 │◀────────────│            │            │            │
```

### Error Handling Sequence

```
Scanner      Circuit     Detector    Logger      User
  │          Breaker       │          │         │
  │          │             │          │         │
  │ scan()   │             │          │         │
  │─────────▶│             │          │         │
  │          │             │          │         │
  │          │ check()    │          │         │
  │          │────────────▶│          │         │
  │          │             │          │         │
  │          │◀────────────│          │         │
  │          │ continue?    │          │         │
  │          │             │          │         │
  │          │ error       │          │         │
  │          │────────────▶│          │         │
  │          │             │          │         │
  │          │ increment   │          │         │
  │          │ error count │          │         │
  │          │────────────▶│          │         │
  │          │             │          │         │
  │          │ threshold?  │          │         │
  │          │────────────▶│          │         │
  │          │             │          │         │
  │          │◀────────────│ exceeded  │         │
  │          │             │───────────▶│         │
  │          │             │          │ log     │
  │          │             │          │ error   │
  │          │             │          │─────────▶│
  │          │ open        │          │         │
  │          │ circuit     │          │         │
  │          │────────────▶│          │         │
  │          │             │          │         │
  │          │◀────────────│          │         │
  │          │ stop        │          │         │
  │          │ scanning    │          │         │
  │◀─────────│             │          │         │
  │ error msg  │             │          │         │
  │───────────▶│             │          │         │
```

---

## Deployment Architecture

### Container Deployment

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Docker Deployment                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    Multi-Stage Build                                │  │
│  │  ┌─────────────────┐     ┌──────────────────┐     ┌─────────────┐ │  │
│  │  │   Build Stage   │     │   Runtime Stage  │     │   Config    │ │  │
│  │  │                 │     │                  │     │   Volume    │ │  │
│  │  │ - Python 3.11  │     │ - Python 3.11    │     │             │ │  │
│  │  │ - Poetry       │     │ - Poetry deps    │     │ - Config    │ │  │
│  │  │ - Build deps     │     │ - App code       │     │ - Rules     │ │  │
│  │  │ - Compile        │     │ - Non-root user  │     │ - Patterns  │ │  │
│  │  │   bytecode       │     │                  │     │             │ │  │
│  │  └─────────────────┘     └──────────────────┘     └─────────────┘ │  │
│  │           │                       │                       │        │  │
│  │           ▼                       ▼                       ▼        │  │
│  │  ┌─────────────────┐     ┌──────────────────┐     ┌─────────────┐ │  │
│  │  │   Security      │     │   Optimization   │     │   Health    │ │  │
│  │  │   Scanning      │     │   Layers         │     │   Checks    │ │  │
│  │  │   (Trivy)       │     │   Caching        │     │   (HEALTH)  │ │  │
│  │  └─────────────────┘     └──────────────────┘     └─────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Kubernetes Deployment                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    Pod Configuration                                │  │
│  │  ┌─────────────────┐     ┌──────────────────┐     ┌─────────────┐ │  │
│  │  │   Deployment    │     │   Service        │     │   Config    │ │  │
│  │  │                 │     │                  │     │    Map      │ │  │
│  │  │ - Replicas: 3   │     │ - Type: ClusterIP│     │             │ │  │
│  │  │ - Rolling       │     │ - Port: 8080     │     │ - Config    │ │  │
│  │  │   update        │     │ - Target: 8080   │     │ - Secrets   │ │  │
│  │  │ - Resource      │     │                  │     │             │ │  │
│  │  │   limits        │     │                  │     │             │ │  │
│  │  └─────────────────┘     └──────────────────┘     └─────────────┘ │  │
│  │           │                       │                       │        │  │
│  │           ▼                       ▼                       ▼        │  │
│  │  ┌─────────────────┐     ┌──────────────────┐     ┌─────────────┐ │  │
│  │  │   Horizontal    │     │   Auto-scaling   │     │   Storage   │ │  │
│  │  │   Pod Autoscaler│     │   (HPA)          │     │   (PVC)     │ │  │
│  │  │                 │     │                  │     │             │ │  │
│  │  │ - Min: 1        │     │ - CPU: 70%       │     │ - Results   │ │  │
│  │  │ - Max: 10       │     │ - Memory: 80%    │     │ - Cache     │ │  │
│  │  │ - Target: 50%   │     │                  │     │ - Logs      │ │  │
│  │  │   CPU           │     │                  │     │             │ │  │
│  │  └─────────────────┘     └──────────────────┘     └─────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Security Architecture

### Security Layers

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Security Architecture                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    Application Security                             │  │
│  │  ┌─────────────────┐     ┌──────────────────┐     ┌─────────────┐ │  │
│  │  │   Input         │     │   Secrets        │     │   Output    │ │  │
│  │  │   Validation    │     │   Management     │     │   Sanitization│ │  │
│  │  │                 │     │                  │     │             │ │  │
│  │  │ - Path traversal│     │ - Environment    │     │ - Redact    │ │  │
│  │  │   prevention    │     │   variables      │     │   secrets   │ │  │
│  │  │ - File size     │     │ - Vault          │     │ - Mask      │ │  │
│  │  │   limits          │     │   integration    │     │   sensitive │ │  │
│  │  │ - Content       │     │                  │     │   data      │ │  │
│  │  │   filtering       │     │                  │     │             │ │  │
│  │  └─────────────────┘     └──────────────────┘     └─────────────┘ │  │
│  │           │                       │                       │        │  │
│  │           ▼                       ▼                       ▼        │  │
│  │  ┌─────────────────┐     ┌──────────────────┐     ┌─────────────┐ │  │
│  │  │   Code        │     │   Runtime        │     │   Network   │ │  │
│  │  │   Security    │     │   Security       │     │   Security  │ │  │
│  │  │               │     │                  │     │             │ │  │
│  │  │ - Bandit      │     │ - Sandboxing     │     │ - TLS 1.3   │ │  │
│  │  │   scanning    │     │ - Resource       │     │ - mTLS      │ │  │
│  │  │ - Dependency  │     │   limits         │     │ - Firewall  │ │  │
│  │  │   scanning    │     │ - Privilege      │     │   rules     │ │  │
│  │  │               │     │   dropping       │     │             │ │  │
│  │  └─────────────────┘     └──────────────────┘     └─────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      Infrastructure Security                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    Container Security                               │  │
│  │  ┌─────────────────┐     ┌──────────────────┐     ┌─────────────┐ │  │
│  │  │   Image       │     │   Runtime        │     │   Secrets   │ │  │
│  │  │   Scanning    │     │   Security       │     │   Management│ │  │
│  │  │               │     │                  │     │             │ │  │
│  │  │ - Trivy       │     │ - Read-only      │     │ - Sealed    │ │  │
│  │  │   scanning    │     │   root           │     │   secrets   │ │  │
│  │  │ - CVE checks  │     │ - Non-root       │     │ - Rotation  │ │  │
│  │  │               │     │   user           │     │   policy    │ │  │
│  │  │               │     │ - Capabilities   │     │             │ │  │
│  │  └─────────────────┘     └──────────────────┘     └─────────────┘ │  │
│  │           │                       │                       │        │  │
│  │           ▼                       ▼                       ▼        │  │
│  │  ┌─────────────────┐     ┌──────────────────┐     ┌─────────────┐ │  │
│  │  │   Network     │     │   Storage        │     │   Monitoring│ │  │
│  │  │   Policies    │     │   Encryption     │     │   & Audit   │ │  │
│  │  │               │     │                  │     │             │ │  │
│  │  │ - Network     │     │ - At-rest        │     │ - Security  │ │  │
│  │  │   policies    │     │   encryption     │     │   events    │ │  │
│  │  │ - Segmentation│     │ - Key            │     │ - Alerts    │ │  │
│  │  │               │     │   management     │     │             │ │  │
│  │  └─────────────────┘     └──────────────────┘     └─────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Performance Architecture

### Scalability Design

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      Performance Architecture                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    Memory Management                                │  │
│  │  ┌─────────────────┐     ┌──────────────────┐     ┌─────────────┐ │  │
│  │  │   Streaming     │     │   Object         │     │   Cache     │ │  │
│  │  │   Processing    │     │   Pooling        │     │   Strategy  │ │  │
│  │  │                 │     │                  │     │             │ │  │
│  │  │ - File stream   │     │ - Regex          │     │ - LRU       │ │  │
│  │  │   processing    │     │   compilation    │     │   cache     │ │  │
│  │  │ - Chunked       │     │   caching        │     │ - Pattern   │ │  │
│  │  │   reading       │     │                  │     │   cache     │ │  │
│  │  │ - Generator     │     │                  │     │             │ │  │
│  │  │   functions     │     │                  │     │             │ │  │
│  │  └─────────────────┘     └──────────────────┘     └─────────────┘ │  │
│  │           │                       │                       │        │  │
│  │           ▼                       ▼                       ▼        │  │
│  │  ┌─────────────────┐     ┌──────────────────┐     ┌─────────────┐ │  │
│  │  │   Concurrency   │     │   Async I/O      │     │   Resource  │ │  │
│  │  │   Control       │     │   Optimization   │     │   Limits    │ │  │
│  │  │               │     │                  │     │             │ │  │
│  │  │ - Semaphore   │     │ - aiofiles       │     │ - CPU       │ │  │
│  │  │   limits      │     │ - Async context  │     │ - Memory    │ │  │
│  │  │ - Worker      │     │   managers       │     │ - File      │ │  │
│  │  │   pools       │     │                  │     │   handles   │ │  │
│  │  │               │     │                  │     │             │ │  │
│  │  └─────────────────┘     └──────────────────┘     └─────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Distributed Processing                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    Worker Coordination                              │  │
│  │  ┌─────────────────┐     ┌──────────────────┐     ┌─────────────┐ │  │
│  │  │   Job         │     │   Queue        │     │   Results   │ │  │
│  │  │   Queue       │     │   Management   │     │   Aggregation│ │  │
│  │  │               │     │                  │     │             │ │  │
│  │  │ - Redis       │     │ - Priority       │     │ - Streaming │ │  │
│  │  │   backend     │     │   queues         │     │   results   │ │  │
│  │  │ - Task        │     │ - Dead letter    │     │ - Batch     │ │  │
│  │  │   routing     │     │   queues         │     │   processing│ │  │
│  │  │               │     │                  │     │             │ │  │
│  │  └─────────────────┘     └──────────────────┘     └─────────────┘ │  │
│  │           │                       │                       │        │  │
│  │           ▼                       ▼                       ▼        │  │
│  │  ┌─────────────────┐     ┌──────────────────┐     ┌─────────────┐ │  │
│  │  │   Load        │     │   Fault        │     │   Monitoring│ │  │
│  │  │   Balancing   │     │   Tolerance    │     │   & Metrics │ │  │
│  │  │               │     │                  │     │             │ │  │
│  │  │ - Round-robin │     │ - Retry          │     │ - Latency   │ │  │
│  │  │ - Least conn  │     │   policies       │     │ - Throughput│ │  │
│  │  │ - Health      │     │ - Circuit        │     │ - Error     │ │  │
│  │  │   checks      │     │   breaker        │     │   rates     │ │  │
│  │  │               │     │                  │     │             │ │  │
│  │  └─────────────────┘     └──────────────────┘     └─────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Implementation Notes

### Diagram Standards

- **Mermaid Compatibility**: All diagrams are compatible with Mermaid.js for rendering
- **Color Coding**: Consistent color scheme for different component types
- **Layer Separation**: Clear separation between application, infrastructure, and security layers
- **Scalability**: Diagrams designed to accommodate future architectural changes

### Usage Guidelines

1. **Documentation Integration**: Include relevant diagrams in API documentation
2. **Code Reviews**: Reference diagrams during architecture discussions
3. **Onboarding**: Use diagrams for new developer orientation
4. **Stakeholder Communication**: Simplified views for non-technical audiences

### Maintenance

- **Version Control**: Track diagram changes in Git
- **Regular Updates**: Update diagrams with architectural changes
- **Review Process**: Include diagram review in code review process
- **Automation**: Consider automated diagram generation from code

---

## Related Documents

- [SYSTEM_DESIGN_SPECIFICATION.md](./SYSTEM_DESIGN_SPECIFICATION.md) - Detailed system design
- [ARCHITECTURE.md](./ARCHITECTURE.md) - Core architecture documentation
- [DEPLOYMENT.md](./DEPLOYMENT.md) - Deployment procedures
- [SECURITY.md](./SECURITY.md) - Security implementation details

---

*Last Updated: January 2026*
*Version: 1.0*
*Status: Review Ready*