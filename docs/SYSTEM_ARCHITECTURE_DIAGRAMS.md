# System Architecture Diagrams

## Overview

This document provides comprehensive architecture diagrams for the MCP Sentinel Python project, using the C4 model and Mermaid.js to illustrate the system's design, component relationships, and data flow. These diagrams reflect the Phase 4.4 architecture, including **RAG (Retrieval-Augmented Generation)** and **Automated Remediation**.

## Table of Contents

1. [System Context (C4 Level 1)](#system-context-c4-level-1)
2. [Container Diagram (C4 Level 2)](#container-diagram-c4-level-2)
3. [Component Diagram - AI & RAG (C4 Level 3)](#component-diagram---ai--rag-c4-level-3)
4. [Remediation Data Flow](#remediation-data-flow)
5. [Deployment Architecture](#deployment-architecture)

---

## System Context (C4 Level 1)

This diagram shows the high-level interactions between the User, MCP Sentinel, and external systems.

```mermaid
C4Context
    title System Context Diagram for MCP Sentinel

    Person(user, "Security Engineer", "Runs scans, reviews findings, applies fixes")
    System(sentinel, "MCP Sentinel", "AI-Powered Security Scanner with RAG & Remediation")

    System_Ext(target_code, "Target Codebase", "Source code to be analyzed")
    System_Ext(llm_providers, "AI Providers", "Anthropic Claude, OpenAI GPT-4, Google Gemini")
    System_Ext(knowledge_base, "Security Knowledge Base", "OWASP, CWE, Framework Patterns")

    Rel(user, sentinel, "Uses CLI to scan/fix", "Terminal")
    Rel(sentinel, target_code, "Reads/Analyzes", "File System")
    Rel(sentinel, llm_providers, "Sends Context/Code, Receives Analysis/Fixes", "HTTPS/API")
    Rel(sentinel, knowledge_base, "Retrieves Security Patterns", "Local/Embedded")
```

## Container Diagram (C4 Level 2)

This diagram breaks down the MCP Sentinel system into its core containers and their interactions.

```mermaid
C4Container
    title Container Diagram for MCP Sentinel

    Container(cli, "CLI Layer", "Python/Click/Rich", "Handles user input, displays results, renders diffs")
    Container(scanner_core, "Scanner Core", "MultiEngineScanner", "Orchestrates scanning pipelines, manages concurrency")
    Container(ai_engine, "AI Engine", "AIEngine", "Manages AI interactions, context windowing, prompt engineering")
    Container(rag_engine, "RAG Engine", "ChromaDB/Embeddings", "Retrieves context-aware security patterns")
    Container(detectors, "Detector Plugins", "Python Modules", "Specialized logic for Frameworks, Secrets, Injection")
    Container(remediation, "Remediation System", "DiffBuilder/Patch", "Generates and applies code fixes")
    ContainerDb(kb_store, "Vector Store", "ChromaDB", "Stores embeddings of security patterns")

    Rel(cli, scanner_core, "Initiates Scan/Fix")
    Rel(scanner_core, detectors, "Delegates Static Analysis")
    Rel(scanner_core, ai_engine, "Delegates Semantic Analysis")
    Rel(ai_engine, rag_engine, "Queries for Context")
    Rel(rag_engine, kb_store, "Retrieves Embeddings")
    Rel(ai_engine, remediation, "Generates Fix Suggestions")
    Rel(remediation, cli, "Returns Unified Diffs")
```

## Component Diagram - AI & RAG (C4 Level 3)

Detailed view of the AI Engine and its integration with RAG and Remediation.

```mermaid
classDiagram
    class MultiEngineScanner {
        +scan_project()
        +orchestrate_scan()
    }
    
    class AIEngine {
        -providers: Dict
        -rag_controller: RAGController
        +analyze_code()
        +generate_fix()
    }
    
    class RAGController {
        -vector_store: ChromaDB
        -retriever: SemanticRetriever
        +retrieve_context(query)
        +populate_knowledge_base()
    }
    
    class AIProvider {
        <<Interface>>
        +analyze()
        +generate_fix()
    }
    
    class AnthropicProvider {
        +analyze()
        +generate_fix()
    }
    
    class DiffBuilder {
        +create_unified_diff(original, modified)
        +apply_patch(file_path, diff)
    }

    MultiEngineScanner --> AIEngine : Uses
    AIEngine --> RAGController : Queries Context
    AIEngine --> AIProvider : Delegates LLM Calls
    AIProvider <|.. AnthropicProvider : Implements
    AnthropicProvider --> DiffBuilder : Formats Output
    RAGController --> KnowledgeBase : Loads Data
```

## Remediation Data Flow

The flow of data when generating an automated fix.

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant AIEngine
    participant RAG
    participant LLM
    participant DiffBuilder

    User->>CLI: mcp-sentinel fix
    CLI->>AIEngine: Request Remediation (Vulnerability)
    AIEngine->>RAG: Retrieve Context (CWE/OWASP)
    RAG-->>AIEngine: Context Docs
    AIEngine->>LLM: Prompt (Code + Vuln + Context)
    LLM-->>AIEngine: Fixed Code Block
    AIEngine->>DiffBuilder: Generate Diff (Original, Fixed)
    DiffBuilder-->>AIEngine: Unified Diff Object
    AIEngine-->>CLI: RemediationSuggestion
    CLI-->>User: Display Diff & Ask Confirmation
```

## Deployment Architecture

Deployment view for Docker-based distribution.

```mermaid
graph TB
    subgraph "Docker Host"
        subgraph "Container: mcp-sentinel"
            CLI[CLI / App]
            Code[Source Code]
            Env[Environment Vars]
        end
        
        subgraph "Volumes"
            DataVol[./data - ChromaDB]
            LogVol[./logs]
            ConfigVol[./config]
        end
        
        CLI --> DataVol
        CLI --> LogVol
        CLI --> ConfigVol
    end
    
    Target[Target Project] --> CLI
```
