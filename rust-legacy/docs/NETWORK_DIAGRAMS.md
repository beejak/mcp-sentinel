# MCP Sentinel - Network Architecture & Flow Diagrams

**Version**: 2.0.0
**Purpose**: Detailed network communication patterns, data flows, and security boundaries

---

## Table of Contents

1. [Overview](#overview)
2. [Network Topology](#network-topology)
3. [Communication Patterns](#communication-patterns)
4. [LLM Provider Integration](#llm-provider-integration)
5. [Proxy Architecture](#proxy-architecture)
6. [Security Boundaries](#security-boundaries)
7. [Data Flow Diagrams](#data-flow-diagrams)
8. [Performance & Latency](#performance--latency)
9. [Error Handling & Retries](#error-handling--retries)
10. [Rate Limiting & Backpressure](#rate-limiting--backpressure)

---

## Overview

MCP Sentinel operates in multiple network modes depending on the command:

| Mode           | Network Activity                          | External Connections |
|----------------|-------------------------------------------|----------------------|
| **Scan**       | Outbound HTTPS to LLM providers (optional)| Yes (deep mode only) |
| **Proxy**      | Bidirectional MCP traffic interception   | Depends on servers   |
| **Monitor**    | No network (local file system only)      | No                   |
| **Audit**      | All of the above                         | Yes                  |

**Why This Architecture?**

1. **Zero Network by Default**: Quick scans work offline (no external dependencies)
2. **Opt-In Cloud**: Deep mode explicitly requires LLM provider flag
3. **Transparent Proxying**: Runtime monitoring without client/server changes
4. **Local-First**: Ollama enables zero-latency, zero-cost, private AI analysis

---

## Network Topology

### Scan Mode (Quick)

```
┌─────────────────────────────────────────────────────────────┐
│                      Local System                           │
│                                                             │
│  ┌──────────────┐                                          │
│  │   Terminal   │                                          │
│  │  (User CLI)  │                                          │
│  └──────┬───────┘                                          │
│         │                                                   │
│         ▼                                                   │
│  ┌──────────────┐                                          │
│  │ MCP Sentinel │                                          │
│  │   Scanner    │                                          │
│  └──────┬───────┘                                          │
│         │                                                   │
│         ├──> Read Files (Local FS)                         │
│         ├──> Pattern Matching (In-Memory)                  │
│         ├──> AST Analysis (In-Memory)                      │
│         └──> Output Results                                │
│                                                             │
│  NO EXTERNAL NETWORK CONNECTIONS                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘

Why: Privacy, speed, offline capability
```

---

### Scan Mode (Deep - Cloud LLM)

```
┌────────────────────────────────────┐         ┌──────────────────────────┐
│        Local System                │         │    Cloud LLM Provider    │
│                                    │         │                          │
│  ┌──────────────┐                 │         │  ┌────────────────────┐  │
│  │ MCP Sentinel │                 │         │  │  OpenAI API Server │  │
│  │   Scanner    │                 │         │  │  api.openai.com    │  │
│  └──────┬───────┘                 │         │  └────────────────────┘  │
│         │                          │         │                          │
│         ├──> 1. Local Analysis    │         │  ┌────────────────────┐  │
│         │                          │         │  │ Anthropic API      │  │
│         ├──> 2. Code Snippet      │  HTTPS  │  │ api.anthropic.com  │  │
│         │     Extraction           ├────────>│  └────────────────────┘  │
│         │                          │  TLS    │                          │
│         ├──> 3. API Request        │  1.3    │  ┌────────────────────┐  │
│         │     (POST /chat)         │         │  │  Google Gemini     │  │
│         │                          │         │  │  generativelanguage│  │
│         │                          │         │  │  .googleapis.com   │  │
│         │<─── 4. AI Analysis       │<────────┤  └────────────────────┘  │
│         │     Response             │         │                          │
│         │                          │         └──────────────────────────┘
│         └──> 5. Generate Report    │
│                                    │
└────────────────────────────────────┘

Network Properties:
- Protocol: HTTPS (TLS 1.3)
- Direction: Outbound only
- Ports: 443 (HTTPS)
- Firewall: Requires outbound HTTPS
- Proxy: Respects HTTP_PROXY, HTTPS_PROXY env vars

Data Sent:
- Code snippets (max 4KB per request)
- Vulnerability context
- API key (Authorization header)

Data Received:
- AI analysis results
- Confidence scores
- Recommendations

Why HTTPS Only: Encryption in transit, authentication, industry standard
Why Outbound Only: Minimizes attack surface, no listening ports
```

---

### Scan Mode (Deep - Local Ollama)

```
┌────────────────────────────────────────────────────┐
│              Local System (localhost)              │
│                                                    │
│  ┌──────────────┐              ┌───────────────┐  │
│  │ MCP Sentinel │              │ Ollama Server │  │
│  │   Scanner    │              │ localhost:    │  │
│  └──────┬───────┘              │   11434       │  │
│         │                       └───────┬───────┘  │
│         │                               │          │
│         │    HTTP POST                  │          │
│         ├───> /api/generate ───────────>│          │
│         │    (Code snippet)             │          │
│         │                               │          │
│         │                      ┌────────▼──────┐   │
│         │                      │  LLaMA 3.2    │   │
│         │                      │  (8B params)  │   │
│         │                      │  In-Memory    │   │
│         │                      └────────┬──────┘   │
│         │                               │          │
│         │<─── HTTP 200 OK ──────────────┤          │
│         │     (Analysis result)         │          │
│         │                               │          │
│         └──> Combine with local         │          │
│              pattern results            │          │
│                                         │          │
└─────────────────────────────────────────┼──────────┘
                                          │
                          GPU (optional)  │  CPU
                          ┌───────────────▼──────┐
                          │  Hardware Inference  │
                          │  RTX 4090: ~50ms     │
                          │  M1 Max: ~200ms      │
                          │  CPU: ~2000ms        │
                          └──────────────────────┘

Network Properties:
- Protocol: HTTP (localhost only, no encryption needed)
- Port: 11434 (default)
- Latency: 50-2000ms (hardware-dependent)
- Cost: $0 (free)
- Privacy: 100% local (no data leaves machine)

Why HTTP (not HTTPS): Localhost traffic, encryption overhead unnecessary
Why Port 11434: Ollama default, configurable via OLLAMA_HOST
Why Local Only: Privacy, zero cost, no rate limits
```

---

## Communication Patterns

### Request/Response Flow (OpenAI Example)

```
MCP Sentinel                                 OpenAI API
     │                                           │
     ├──> 1. HTTPS Connection (TLS 1.3)         │
     │         Host: api.openai.com:443         │
     │         SNI: api.openai.com              │
     │         ALPN: h2 (HTTP/2)                │
     │                                           │
     │<─── 2. TLS Handshake Complete            │
     │         Certificate Validated            │
     │         Session Established              │
     │                                           │
     ├──> 3. HTTP POST /v1/chat/completions     │
     │         Headers:                          │
     │           Authorization: Bearer sk-...   │
     │           Content-Type: application/json │
     │           User-Agent: mcp-sentinel/2.0   │
     │         Body: {                           │
     │           "model": "gpt-4o",             │
     │           "messages": [                  │
     │             {"role": "system", ...},     │
     │             {"role": "user", ...}        │
     │           ],                              │
     │           "temperature": 0.0,            │
     │           "max_tokens": 2000             │
     │         }                                 │
     │                                           │
     │         [Processing: 500-2000ms]          │
     │                                           │
     │<─── 4. HTTP 200 OK                        │
     │         Headers:                          │
     │           Content-Type: application/json │
     │           X-Request-ID: req_abc123...    │
     │         Body: {                           │
     │           "id": "chatcmpl-...",          │
     │           "choices": [                   │
     │             {                             │
     │               "message": {               │
     │                 "role": "assistant",     │
     │                 "content": "Analysis..." │
     │               },                          │
     │               "finish_reason": "stop"    │
     │             }                             │
     │           ],                              │
     │           "usage": {                     │
     │             "prompt_tokens": 856,        │
     │             "completion_tokens": 342,    │
     │             "total_tokens": 1198         │
     │           }                               │
     │         }                                 │
     │                                           │
     ├──> 5. Extract Analysis                    │
     │         Parse JSON response              │
     │         Update cost counters             │
     │         Cache result (SHA-256 hash)      │
     │                                           │
     └──> 6. Close Connection (or reuse)        │
              HTTP/2 connection pooling         │

Timing Breakdown:
┌─────────────────────────────────────────────────────┐
│ Step                │ Typical Latency               │
├─────────────────────┼───────────────────────────────┤
│ DNS Lookup          │ 10-50ms (cached after first)  │
│ TCP Handshake       │ 20-100ms (RTT dependent)      │
│ TLS Handshake       │ 30-150ms (includes cert)      │
│ HTTP Request        │ 5-20ms                        │
│ API Processing      │ 500-2000ms (model dependent)  │
│ HTTP Response       │ 5-20ms                        │
│ Total               │ 570-2340ms per request        │
└─────────────────────────────────────────────────────┘

Why HTTP/2: Multiplexing, header compression, server push capability
Why TLS 1.3: Security, forward secrecy, faster handshake
Why Connection Pooling: Amortize handshake cost across multiple requests
```

---

### Concurrent Requests (Rate Limiting)

```
Scan with 100 Files Needing AI Analysis
         │
         ▼
    Rate Limiter
    (Semaphore: 5)
         │
    ┌────┴────┬────────┬────────┬────────┬────────┐
    │         │        │        │        │        │
    ▼         ▼        ▼        ▼        ▼        ▼
  File 1   File 2   File 3   File 4   File 5   File 6 (queued)
    │        │        │        │        │        │
    │        │        │        │        │        │
    └────────┴────────┴────────┴────────┴────────┘
         │                                    ▲
         ▼                                    │
    API Requests (concurrent: 5)              │
         │                                    │
    ┌────┴────┬────────┬────────┬────────┐   │
    │         │        │        │        │   │
    ▼         ▼        ▼        ▼        ▼   │
 OpenAI   OpenAI   OpenAI   OpenAI   OpenAI  │
 API      API      API      API      API     │
 (500ms)  (600ms)  (700ms)  (550ms)  (800ms) │
    │         │        │        │        │   │
    └─────────┴────────┴────────┴────────┘   │
         │                                    │
         ▼                                    │
    Responses Received                        │
         │                                    │
         ├──> Release semaphore slot ─────────┘
         │
         ├──> File 6 starts (now has slot)
         │
         ▼
    Continue until all files processed

Rate Limiting Strategy:
- Provider: OpenAI
  - Limit: 10 requests/second
  - Semaphore: 5 concurrent
  - Reasoning: Conservative (avoid 429 errors)

- Provider: Anthropic
  - Limit: 5 requests/second
  - Semaphore: 3 concurrent
  - Reasoning: Stricter limits

- Provider: Ollama (local)
  - Limit: Unlimited
  - Semaphore: 10 concurrent
  - Reasoning: Hardware-bound, not network

Why Semaphores: Fair access, prevents rate limit errors, backpressure
Why Provider-Specific: Different rate limits require different strategies
```

---

## LLM Provider Integration

### OpenAI Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         OpenAI Network Flow                     │
└─────────────────────────────────────────────────────────────────┘

MCP Sentinel                                         OpenAI Infrastructure
     │                                                      │
     ├──> DNS Lookup: api.openai.com                       │
     │    Result: 104.18.6.192 (Cloudflare CDN)           │
     │                                                      │
     ├──> HTTPS POST                                       │
     │    Endpoint: /v1/chat/completions                   │
     │    Cloudflare Edge (CDN)                            │
     │         │                                            │
     │         └──> OpenAI Load Balancer                   │
     │                   │                                  │
     │                   ├──> GPU Cluster (GPT-4)          │
     │                   │     Region: us-west-2           │
     │                   │     Inference Time: ~500-2000ms │
     │                   │                                  │
     │<──────────────────┴── Response                      │
     │    Status: 200 OK                                   │
     │    X-Request-ID: req_abc123                         │
     │    Rate Limit Headers:                              │
     │      X-RateLimit-Limit-Requests: 10000              │
     │      X-RateLimit-Remaining-Requests: 9999           │
     │      X-RateLimit-Reset-Requests: 6s                 │
     │                                                      │
     └──> Parse & Process                                  │

Endpoints Used:
- POST /v1/chat/completions (GPT-4, GPT-3.5)

Authentication:
- Header: Authorization: Bearer sk-...
- API Key Format: sk-proj-... (project keys)

Models Available:
┌─────────────────┬──────────┬──────────┬──────────────┐
│ Model           │ Cost/1K  │ Latency  │ Quality      │
├─────────────────┼──────────┼──────────┼──────────────┤
│ gpt-4o          │ $0.015   │ 800ms    │ Excellent    │
│ gpt-4-turbo     │ $0.030   │ 600ms    │ Excellent    │
│ gpt-4           │ $0.060   │ 1200ms   │ Best         │
│ gpt-3.5-turbo   │ $0.002   │ 300ms    │ Good         │
└─────────────────┴──────────┴──────────┴──────────────┘

Rate Limits (Tier 1):
- 10,000 requests/day
- 10 requests/second
- 150,000 tokens/minute

Error Handling:
- 429 Too Many Requests → Exponential backoff (1s, 2s, 4s, 8s)
- 500 Internal Server Error → Retry 3 times with jitter
- 401 Unauthorized → Fail fast (invalid API key)

Why Cloudflare CDN: Global edge network, DDoS protection
Why Rate Limit Headers: Proactive throttling before 429 errors
Why Multiple Models: Cost/quality tradeoffs
```

---

### Anthropic Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Anthropic Network Flow                     │
└─────────────────────────────────────────────────────────────────┘

MCP Sentinel                                    Anthropic Infrastructure
     │                                                      │
     ├──> DNS Lookup: api.anthropic.com                    │
     │    Result: AWS CloudFront Distribution              │
     │                                                      │
     ├──> HTTPS POST                                       │
     │    Endpoint: /v1/messages                           │
     │    Headers:                                          │
     │      x-api-key: sk-ant-...                          │
     │      anthropic-version: 2023-06-01                  │
     │      content-type: application/json                 │
     │         │                                            │
     │         └──> AWS CloudFront (CDN)                   │
     │                   │                                  │
     │                   └──> Anthropic API Gateway        │
     │                          │                           │
     │                          ├──> Claude Inference      │
     │                          │     (AWS Trainium chips) │
     │                          │     Latency: ~800ms      │
     │                          │                           │
     │<─────────────────────────┴── Response               │
     │    Status: 200 OK                                   │
     │    Rate Limit Headers:                              │
     │      anthropic-ratelimit-requests-limit: 1000       │
     │      anthropic-ratelimit-requests-remaining: 999    │
     │      anthropic-ratelimit-requests-reset: 2025-...   │
     │                                                      │
     └──> Parse & Process                                  │

Endpoints Used:
- POST /v1/messages (Claude 3 family)

Authentication:
- Header: x-api-key: sk-ant-api03-...

Models Available:
┌──────────────────────────┬──────────┬──────────┬──────────────┐
│ Model                    │ Cost/1K  │ Latency  │ Quality      │
├──────────────────────────┼──────────┼──────────┼──────────────┤
│ claude-3-opus-20240229   │ $0.075   │ 1000ms   │ Best         │
│ claude-3-sonnet-20240229 │ $0.015   │ 800ms    │ Excellent    │
│ claude-3-haiku-20240307  │ $0.001   │ 300ms    │ Very Good    │
└──────────────────────────┴──────────┴──────────┴──────────────┘

Rate Limits (Tier 1):
- 1,000 requests/day
- 5 requests/second (Haiku)
- 2 requests/second (Sonnet/Opus)

Unique Features:
- System prompts (separate from messages)
- Thinking tokens (separate pricing)
- Extended context (200K tokens)

Why AWS Infrastructure: High availability, global reach
Why Trainium: Custom AI chips, cost-effective inference
Why Haiku: Fastest model for time-sensitive scans
```

---

### Google Gemini Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Google Gemini Network Flow                 │
└─────────────────────────────────────────────────────────────────┘

MCP Sentinel                                    Google Cloud Infrastructure
     │                                                      │
     ├──> DNS Lookup: generativelanguage.googleapis.com    │
     │    Result: Google Cloud Load Balancer               │
     │                                                      │
     ├──> HTTPS POST                                       │
     │    Endpoint: /v1beta/models/gemini-1.5-pro:        │
     │              generateContent                         │
     │    URL Param: key=AIza...                           │
     │         │                                            │
     │         └──> Google Cloud Load Balancer             │
     │                   │                                  │
     │                   └──> Vertex AI (Gemini)           │
     │                          │                           │
     │                          ├──> TPU v5 Pods           │
     │                          │     Inference: ~600ms    │
     │                          │                           │
     │<─────────────────────────┴── Response               │
     │    Status: 200 OK                                   │
     │                                                      │
     └──> Parse & Process                                  │

Endpoints Used:
- POST /v1beta/models/{model}:generateContent

Authentication:
- URL Parameter: ?key=AIza...
- Or Header: x-goog-api-key: AIza...

Models Available:
┌──────────────────┬──────────┬──────────┬──────────────┐
│ Model            │ Cost/1K  │ Latency  │ Quality      │
├──────────────────┼──────────┼──────────┼──────────────┤
│ gemini-1.5-pro   │ $0.0035  │ 600ms    │ Excellent    │
│ gemini-1.5-flash │ $0.0007  │ 200ms    │ Very Good    │
│ gemini-1.0-pro   │ $0.0005  │ 400ms    │ Good         │
└──────────────────┴──────────┴──────────┴──────────────┘

Rate Limits:
- 60 requests/minute (free tier)
- 1,000 requests/minute (paid tier)

Unique Features:
- Native multimodal (text + images)
- 1M token context window
- Function calling
- Cheapest cloud option

Why Google TPUs: Custom AI accelerators, high throughput
Why Cheapest: Aggressive pricing to gain market share
Why 1M Context: Analyze entire large codebases in one request
```

---

### Local Ollama Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Ollama Local Network Flow                  │
└─────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│                         localhost                              │
│                                                                │
│  MCP Sentinel                    Ollama Server                │
│       │                                │                       │
│       ├──> HTTP POST                   │                       │
│       │    Host: 127.0.0.1:11434       │                       │
│       │    Endpoint: /api/generate     │                       │
│       │    Body: {                     │                       │
│       │      "model": "llama3.2:8b",  │                       │
│       │      "prompt": "Analyze...",  │                       │
│       │      "stream": false           │                       │
│       │    }                            │                       │
│       │         │                      │                       │
│       │         └──────────────────────┼──> Parse Request     │
│       │                                 │                       │
│       │                                 ├──> Load Model        │
│       │                                 │    (if not loaded)   │
│       │                                 │    Location:         │
│       │                                 │    ~/.ollama/models/ │
│       │                                 │    Size: 4.7GB       │
│       │                                 │                       │
│       │                                 ├──> Run Inference     │
│       │                                 │    Hardware:         │
│       │                                 │    - GPU (CUDA/ROCm) │
│       │                                 │    - Metal (macOS)   │
│       │                                 │    - CPU (fallback)  │
│       │                                 │                       │
│       │                        ┌────────▼──────────┐           │
│       │                        │  Model Inference  │           │
│       │                        │  8B parameters    │           │
│       │                        │  FP16/INT4 quant  │           │
│       │                        └────────┬──────────┘           │
│       │                                 │                       │
│       │<────────────────────────────────┤                       │
│       │    HTTP 200 OK                  │                       │
│       │    Body: {                      │                       │
│       │      "model": "llama3.2:8b",   │                       │
│       │      "response": "Analysis...", │                       │
│       │      "done": true               │                       │
│       │    }                             │                       │
│       │                                 │                       │
│       └──> Process Response              │                       │
│                                         │                       │
└─────────────────────────────────────────┼───────────────────────┘
                                          │
                           Hardware Layer │
                  ┌─────────────────────────────────────┐
                  │  GPU / CPU Execution                │
                  │  - NVIDIA RTX 4090: 50ms            │
                  │  - Apple M1 Max: 200ms              │
                  │  - CPU (16 cores): 2000ms           │
                  └─────────────────────────────────────┘

Network Properties:
- Protocol: HTTP (unencrypted - localhost only)
- Port: 11434 (default, configurable)
- Latency: 50-2000ms (hardware-dependent)
- Throughput: Limited by GPU/CPU
- Cost: $0 (free)
- Privacy: 100% local (no external network)

Available Models:
┌──────────────────┬────────┬──────────┬──────────────┬──────────┐
│ Model            │ Size   │ Params   │ GPU Latency  │ Quality  │
├──────────────────┼────────┼──────────┼──────────────┼──────────┤
│ llama3.2:8b      │ 4.7GB  │ 8B       │ 50ms         │ Excellent│
│ codestral:22b    │ 12GB   │ 22B      │ 150ms        │ Best     │
│ qwen2.5-coder:7b │ 4.3GB  │ 7B       │ 40ms         │ Very Good│
│ phi3:14b         │ 7.9GB  │ 14B      │ 100ms        │ Excellent│
└──────────────────┴────────┴──────────┴──────────────┴──────────┘

Why HTTP (not HTTPS): Localhost traffic, no encryption needed
Why No Rate Limits: Local execution, hardware-bound only
Why Multiple Models: Different size/quality tradeoffs
Why Free: No API costs, one-time hardware investment
```

---

## Proxy Architecture

### Transparent MCP Proxy Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     MCP Sentinel Proxy Architecture                         │
└─────────────────────────────────────────────────────────────────────────────┘

   Claude Desktop                MCP Sentinel Proxy             MCP Server
   (MCP Client)                  (Transparent Proxy)            (Backend)
        │                                │                           │
        ├──> 1. MCP Request              │                           │
        │    Method: tools/call          │                           │
        │    Tool: read_file             │                           │
        │    Args: {path: "/etc/passwd"} │                           │
        │                                │                           │
        │                                ├──> 2. Intercept Request   │
        │                                │     Parse MCP message     │
        │                                │                           │
        │                                ├──> 3. Risk Analysis       │
        │                                │     - Path traversal?     │
        │                                │     - Sensitive file?     │
        │                                │     - Rate limit OK?      │
        │                                │                           │
        │                                ├──> 4. Apply Guardrails    │
        │                                │     Rule: block-sensitive │
        │                                │     Match: /etc/passwd    │
        │                                │     Action: BLOCK         │
        │                                │                           │
        │<────────── 5. Blocked ─────────┤                           │
        │    Status: Error               │                           │
        │    Message: "Access denied"    │                           │
        │    Reason: "Sensitive path"    │      [Request never       │
        │                                │       forwarded to        │
        │                                │       backend server]     │
        │                                │                           │
        ├──> 6. Legitimate Request       │                           │
        │    Method: tools/call          │                           │
        │    Tool: read_file             │                           │
        │    Args: {path: "/tmp/data"}   │                           │
        │                                │                           │
        │                                ├──> 7. Risk Analysis       │
        │                                │     - Path OK             │
        │                                │     - Rate limit OK       │
        │                                │     - No guardrail match  │
        │                                │                           │
        │                                ├──> 8. Forward Request ───>│
        │                                │                           ├──> Execute
        │                                │                           │    read_file
        │                                │                           │
        │                                │<─── 9. MCP Response ──────┤
        │                                │    Result: {content: ...} │
        │                                │                           │
        │                                ├──> 10. Inspect Response   │
        │                                │     - Check for secrets   │
        │                                │     - Check data size     │
        │                                │     - Log traffic         │
        │                                │                           │
        │<────── 11. Forward Response ───┤                           │
        │    Result: {content: ...}      │                           │
        │                                │                           │
        │                                ├──> 12. Audit Log          │
        │                                │     Log: {                │
        │                                │       timestamp,          │
        │                                │       tool,               │
        │                                │       args,               │
        │                                │       result,             │
        │                                │       risk_level: low     │
        │                                │     }                     │
        │                                │                           │
        └────────────────────────────────┴───────────────────────────┘

Proxy Modes:
┌──────────────┬──────────────────┬──────────────────────────────┐
│ Mode         │ Action           │ Use Case                     │
├──────────────┼──────────────────┼──────────────────────────────┤
│ Monitor      │ Log + Forward    │ Observability                │
│ Alert        │ Log + Alert + Fw │ Security monitoring          │
│ Block        │ Log + Block      │ Policy enforcement           │
└──────────────┴──────────────────┴──────────────────────────────┘

Proxy Components:
┌───────────────────────────────────────────────────────────┐
│ 1. MCP Parser       │ Decode STDIO/HTTP MCP messages      │
│ 2. Risk Analyzer    │ Evaluate request risk (0-100)       │
│ 3. Guardrails Engine│ Apply security policies             │
│ 4. Logger           │ Audit trail (JSON Lines)            │
│ 5. Alerter          │ Send webhooks for violations        │
│ 6. Rate Limiter     │ Prevent abuse                       │
└───────────────────────────────────────────────────────────┘

Why Transparent: No client/server modifications needed
Why Bidirectional: Inspect both requests and responses
Why Real-Time: Detect attacks as they happen, not after
```

---

### Proxy Connection Types

#### STDIO Transport (Standard)

```
┌─────────────────────────────────────────────────────────────────┐
│                      STDIO MCP Transport                        │
└─────────────────────────────────────────────────────────────────┘

Claude Desktop                                          MCP Server
      │                                                      │
      ├──> Fork Process: mcp-sentinel proxy                 │
      │    STDIN/STDOUT piped                               │
      │                                                      │
      ├──> Write to STDIN ──────────────────────────┐       │
      │    {"jsonrpc":"2.0","method":"tools/call"}  │       │
      │                                              │       │
      │                          MCP Sentinel Proxy │       │
      │                                 │            │       │
      │                                 ├──> Read STDIN      │
      │                                 ├──> Parse JSON-RPC  │
      │                                 ├──> Apply Rules     │
      │                                 ├──> Fork MCP Server │
      │                                 │                    │
      │                                 └──> Write to Server │
      │                                      STDIN ─────────>│
      │                                                      │
      │                                      Read from Server│
      │                                      STDOUT <────────┤
      │                                 ┌─── Inspect        │
      │                                 │                    │
      │<─── Read from STDOUT ───────────┴────────────────────┤
      │    {"jsonrpc":"2.0","result":{...}}                  │
      │                                                      │

Connection Properties:
- Protocol: JSON-RPC 2.0 over STDIO
- Transport: stdin/stdout pipes
- Latency: <1ms (in-process)
- Isolation: Process-level

Why STDIO: MCP standard, simple, secure (no network)
Why Process Isolation: Security boundary, resource limits
```

---

#### HTTP Transport (Optional)

```
┌─────────────────────────────────────────────────────────────────┐
│                      HTTP MCP Transport                         │
└─────────────────────────────────────────────────────────────────┘

Claude Desktop                                          MCP Server
      │                                                      │
      ├──> HTTP POST                                         │
      │    Host: localhost:8080                              │
      │    Endpoint: /mcp                                    │
      │    Body: {"jsonrpc":"2.0",...}                       │
      │                                                       │
      │                          MCP Sentinel Proxy          │
      │                          (HTTP Server :8080)         │
      │                                 │                     │
      │                                 ├──> Parse Request   │
      │                                 ├──> Apply Rules     │
      │                                 │                     │
      │                                 ├──> HTTP POST ──────>│
      │                                 │    Host: localhost: │
      │                                 │          9000       │
      │                                 │                     │
      │                                 │<─── HTTP Response ──┤
      │                                 │                     │
      │<────────────────────────────────┤                     │
      │    HTTP 200 OK                  │                     │
      │    Body: {"jsonrpc":"2.0",...}  │                     │

Connection Properties:
- Protocol: HTTP/1.1 or HTTP/2
- Port: 8080 (configurable)
- Latency: ~5-10ms (localhost)
- Multiple clients: Yes

Why HTTP: Multi-client support, web dashboard access
Why Localhost Only: Security (no external exposure)
```

---

## Security Boundaries

### Network Security Zones

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Security Zones                                │
└─────────────────────────────────────────────────────────────────────────┘

Zone 1: Trusted (Local System)
┌─────────────────────────────────────────────────────────────────┐
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ MCP Sentinel │  │    Ollama    │  │   File       │          │
│  │   Scanner    │  │    Server    │  │   System     │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│                                                                  │
│  Security Controls:                                             │
│  - OS-level permissions                                         │
│  - Process isolation                                            │
│  - No network exposure                                          │
│                                                                  │
│  Trust Level: HIGH                                              │
│  Data Handling: Source code, config files, credentials         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS (TLS 1.3)
                              │ API Key Authentication
                              │
                              ▼
Zone 2: Semi-Trusted (Cloud LLM Providers)
┌─────────────────────────────────────────────────────────────────┐
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   OpenAI     │  │  Anthropic   │  │   Google     │          │
│  │     API      │  │     API      │  │   Gemini     │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│                                                                  │
│  Security Controls:                                             │
│  - TLS encryption in transit                                    │
│  - API key authentication                                       │
│  - Rate limiting                                                │
│  - Request size limits (4KB)                                    │
│  - No sensitive data in prompts                                 │
│                                                                  │
│  Trust Level: MEDIUM                                            │
│  Data Handling: Code snippets only (sanitized)                 │
│  Data Residency: Provider-controlled                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS
                              │ Potential interception
                              │
                              ▼
Zone 3: Untrusted (Public Internet)
┌─────────────────────────────────────────────────────────────────┐
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │     ISP      │  │   Firewall   │  │   Routers    │          │
│  │   Network    │  │              │  │              │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│                                                                  │
│  Security Controls:                                             │
│  - HTTPS only (no HTTP)                                         │
│  - Certificate pinning (optional)                               │
│  - Proxy support (corporate firewalls)                          │
│                                                                  │
│  Trust Level: LOW                                               │
│  Threats: MITM, eavesdropping, packet inspection               │
└─────────────────────────────────────────────────────────────────┘

Data Flow Security:
┌────────────────────────────────────────────────────────────────┐
│ Zone 1 → Zone 2 (Outbound):                                    │
│   ✓ TLS 1.3 encryption                                         │
│   ✓ Code snippets sanitized (remove secrets, PII)             │
│   ✓ Max 4KB per request                                        │
│   ✓ API key in header (not URL)                               │
│   ✓ No full source code sent                                  │
│                                                                 │
│ Zone 2 → Zone 1 (Inbound):                                     │
│   ✓ TLS certificate validation                                 │
│   ✓ Response size limits                                       │
│   ✓ Content type validation (JSON only)                       │
│   ✓ Timeout enforcement (30s)                                  │
│                                                                 │
│ Zone 1 → Zone 1 (Local):                                       │
│   ✓ Unix sockets (secure IPC)                                  │
│   ✓ File permissions (0600 for config)                        │
│   ✓ Process isolation                                          │
└────────────────────────────────────────────────────────────────┘

Why Three Zones: Defense in depth, minimize trust boundaries
Why Sanitization: Prevent code/credential leakage to cloud
Why TLS Only: Encryption mandatory for untrusted networks
```

---

### Data Sanitization Pipeline

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Code Snippet Sanitization                            │
│                    (Before Sending to Cloud LLM)                        │
└─────────────────────────────────────────────────────────────────────────┘

Original Source Code
         │
         ▼
┌─────────────────────────────────────────┐
│ def authenticate(user, password):       │
│     API_KEY = "sk-abc123..."            │  <- Secret detected
│     DB_PASSWORD = "mypassword123"       │  <- Credential detected
│     if user == "admin":                 │
│         return True                     │
│     return False                        │
└─────────────────────────────────────────┘
         │
         ▼
    Sanitization Pipeline
         │
    ┌────┴────┬────────────┬──────────────┬───────────────┐
    │         │            │              │               │
    ▼         ▼            ▼              ▼               ▼
 Secret    Credential   PII Removal   Size Limit    Format Check
 Removal   Masking                    (4KB max)     (Valid syntax)
    │         │            │              │               │
    └────┬────┴────────────┴──────────────┴───────────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│ def authenticate(user, password):       │
│     API_KEY = "[REDACTED]"              │  <- Masked
│     DB_PASSWORD = "[REDACTED]"          │  <- Masked
│     if user == "admin":                 │
│         return True                     │
│     return False                        │
└─────────────────────────────────────────┘
         │
         ▼
   Sent to Cloud LLM
         │
         ▼
┌─────────────────────────────────────────┐
│ AI Analysis Result:                     │
│ - Hardcoded credentials (masked)        │
│ - Authentication bypass vulnerability   │
│ - Recommendation: Use env variables     │
└─────────────────────────────────────────┘

Sanitization Rules:
1. Secret Patterns:
   - AWS Keys: AKIA[0-9A-Z]{16} → [REDACTED_AWS_KEY]
   - API Keys: [a-zA-Z0-9]{32,} → [REDACTED_API_KEY]
   - Tokens: Bearer .* → [REDACTED_TOKEN]

2. Credentials:
   - Passwords: password\s*=\s*".*" → password="[REDACTED]"
   - Database URLs: postgresql://user:pass@host → [REDACTED_DB_URL]

3. PII:
   - Emails: .+@.+\..+ → [EMAIL]
   - Phone: \d{3}-\d{3}-\d{4} → [PHONE]
   - IP Addresses: \d+\.\d+\.\d+\.\d+ → [IP]

4. Size Limits:
   - Max snippet: 4KB
   - Truncate with: ... [truncated]

5. Context Preservation:
   - Keep function structure
   - Keep variable names (if not sensitive)
   - Keep control flow
   - Mask only values, not patterns

Why Sanitize: Prevent credential leakage to cloud providers
Why 4KB Limit: Reduce costs, prevent context overflow
Why Mask (not Remove): Preserve code structure for analysis
```

---

## Data Flow Diagrams

### Full Scan Flow with AI Analysis

```
┌─────────────────────────────────────────────────────────────────────────┐
│                   Complete Scan Data Flow (Deep Mode)                   │
└─────────────────────────────────────────────────────────────────────────┘

User Input
    │
    ├──> mcp-sentinel scan ./server --mode deep --llm-provider openai
    │
    ▼
┌─────────────────┐
│ CLI Parser      │  Parse arguments, validate inputs
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Config Loader   │  Load .mcp-sentinel.yaml + CLI overrides
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ File Discovery  │  Find all files matching patterns
│                 │  Exclude node_modules, tests, etc.
└────────┬────────┘  Result: ["file1.py", "file2.ts", ...]
         │
         ▼
┌─────────────────┐
│ Git Integration │  (Optional) Filter to changed files only
│                 │  git diff --name-only
└────────┬────────┘  Result: ["file1.py"] (10x faster)
         │
         ▼
         ├──> For Each File (Parallel: 4 workers)
         │         │
         │         ▼
         │    ┌─────────────────┐
         │    │ Static Analysis │
         │    ├─────────────────┤
         │    │ 1. Regex Scan   │  Pattern matching: secrets, unsafe code
         │    │ 2. AST Parse    │  Syntax tree analysis
         │    │ 3. Dataflow     │  Trace variable flow
         │    └────────┬────────┘
         │             │
         │             ├──> Vulnerabilities Found (Local)
         │             │    [{type: "secrets", line: 42, ...}, ...]
         │             │
         │             ▼
         │    ┌─────────────────┐
         │    │ Cache Check     │  SHA-256(file_content)
         │    │                 │  Query: Sled DB
         │    └────────┬────────┘
         │             │
         │        ┌────┴────┐
         │        │         │
         │     CACHE      CACHE
         │      HIT       MISS
         │        │         │
         │        │         ▼
         │        │    ┌─────────────────┐
         │        │    │ Code Sanitizer  │  Remove secrets, PII
         │        │    │                 │  Truncate to 4KB
         │        │    └────────┬────────┘
         │        │             │
         │        │             ▼
         │        │    ┌─────────────────┐
         │        │    │ Rate Limiter    │  Semaphore: 5 concurrent
         │        │    │ (Semaphore)     │  Wait for available slot
         │        │    └────────┬────────┘
         │        │             │
         │        │             ▼
         │        │    ┌─────────────────┐
         │        │    │ LLM Provider    │  HTTPS POST to OpenAI
         │        │    │ API Call        │  Latency: ~800ms
         │        │    └────────┬────────┘
         │        │             │
         │        │             ▼
         │        │    ┌─────────────────┐
         │        │    │ Response Parser │  Extract vulnerabilities
         │        │    │                 │  Parse JSON response
         │        │    └────────┬────────┘
         │        │             │
         │        │             ▼
         │        │    ┌─────────────────┐
         │        │    │ Cache Store     │  Store result for future
         │        │    │                 │  gzip + bincode
         │        │    └────────┬────────┘
         │        │             │
         │        └─────────────┴──> Vulnerabilities (AI + Local)
         │                            Merge results
         │
         ├──> Aggregate All Files
         │
         ▼
┌─────────────────┐
│ Suppression     │  Apply .mcp-sentinel-ignore.yaml
│ Manager         │  Filter false positives
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Baseline        │  (Optional) Compare with previous scan
│ Comparison      │  Identify NEW/FIXED/CHANGED
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Result          │  Aggregate statistics
│ Aggregation     │  Sort by severity
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Output          │  Generate report
│ Formatter       │  Format: Terminal / JSON / SARIF
└────────┬────────┘
         │
         ▼
    User Output
    (Terminal/File)

Timing Breakdown (100 files, 10 need AI):
┌──────────────────────────┬──────────────────┐
│ Phase                    │ Duration         │
├──────────────────────────┼──────────────────┤
│ Config Load              │ 10ms             │
│ File Discovery           │ 50ms             │
│ Static Analysis (100)    │ 2,000ms (20ms/f) │
│ Cache Check (10)         │ 5ms              │
│ AI Analysis (10)         │ 8,000ms (800ms/f)│
│ Suppression Filter       │ 5ms              │
│ Output Format            │ 50ms             │
├──────────────────────────┼──────────────────┤
│ TOTAL                    │ ~10 seconds      │
└──────────────────────────┴──────────────────┘

Why Parallel: Maximize CPU/network utilization
Why Cache: Avoid redundant AI API calls (expensive)
Why Sanitize: Prevent credential leakage
Why Semaphore: Respect rate limits, prevent 429 errors
```

---

## Performance & Latency

### Latency Comparison (Single File)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Scan Mode Latency Comparison                       │
└─────────────────────────────────────────────────────────────────────────┘

Quick Mode (Static Only)
├──> File Read: 1ms
├──> Regex Scan: 5ms
├──> AST Parse: 10ms
├──> Dataflow: 5ms
└──> Total: ~21ms per file

Deep Mode + OpenAI
├──> Quick Mode: 21ms
├──> Sanitization: 2ms
├──> Cache Check: 0.1ms (hit) / 800ms (miss + API)
├──> Rate Limiter Wait: 0-2000ms (depends on queue)
├──> API Call: 800ms (average)
│     ├──> DNS: 10ms (cached)
│     ├──> TCP Handshake: 50ms
│     ├──> TLS Handshake: 80ms
│     ├──> HTTP Request: 5ms
│     ├──> OpenAI Processing: 600ms
│     └──> HTTP Response: 5ms
├──> Response Parse: 2ms
└──> Total: ~825ms per file (cache miss)
          ~23ms per file (cache hit)

Deep Mode + Ollama (Local)
├──> Quick Mode: 21ms
├──> Sanitization: 2ms
├──> HTTP Request (localhost): 1ms
├──> Ollama Inference:
│     ├──> GPU (RTX 4090): 50ms
│     ├──> GPU (M1 Max): 200ms
│     └──> CPU (16 cores): 2000ms
├──> Response Parse: 1ms
└──> Total: ~75ms (GPU) / ~2024ms (CPU)

Caching Impact (Second Scan, No Changes):
├──> File Read: 1ms
├──> SHA-256 Hash: 0.5ms
├──> Cache Lookup: 0.1ms
├──> Decompress (gzip): 1ms
├──> Deserialize (bincode): 0.5ms
└──> Total: ~3ms per file (250x faster!)

Why Cache is Critical: Deep mode is expensive (800ms → 3ms)
Why Ollama: Local GPU gives 10x faster than cloud (no network)
Why Quick Mode Default: 40x faster than deep mode
```

---

### Throughput Analysis

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Scan Throughput (Files/Second)                       │
└─────────────────────────────────────────────────────────────────────────┘

Quick Mode (Pattern Matching Only)
┌────────────────────────────────────────────────────────────┐
│ Workers: 4 (parallel)                                      │
│ Time per file: 21ms                                        │
│ Throughput: 4 / 0.021 = 190 files/second                  │
│                                                            │
│ 1,000 files = 5.3 seconds                                 │
│ 10,000 files = 53 seconds                                 │
│ 100,000 files = 8.8 minutes                               │
└────────────────────────────────────────────────────────────┘

Deep Mode + OpenAI (Cache Cold)
┌────────────────────────────────────────────────────────────┐
│ Workers: 5 (rate limit)                                    │
│ Time per file: 825ms                                       │
│ Throughput: 5 / 0.825 = 6 files/second                    │
│                                                            │
│ 100 files = 16.7 seconds                                  │
│ 1,000 files = 2.8 minutes                                 │
│ 10,000 files = 28 minutes                                 │
│                                                            │
│ Cost: $0.015/1K tokens × 1 req/file = ~$15 per 1K files  │
└────────────────────────────────────────────────────────────┘

Deep Mode + OpenAI (Cache Hot)
┌────────────────────────────────────────────────────────────┐
│ Workers: 4 (cache-bound)                                   │
│ Time per file: 23ms                                        │
│ Throughput: 4 / 0.023 = 174 files/second                  │
│                                                            │
│ 1,000 files = 5.7 seconds (effectively same as quick!)    │
│ Cost: $0 (cache hit)                                      │
└────────────────────────────────────────────────────────────┘

Deep Mode + Ollama (Local GPU)
┌────────────────────────────────────────────────────────────┐
│ Workers: 10 (no rate limit)                                │
│ Time per file: 75ms (RTX 4090)                            │
│ Throughput: 10 / 0.075 = 133 files/second                 │
│                                                            │
│ 1,000 files = 7.5 seconds                                 │
│ 10,000 files = 1.25 minutes                               │
│ Cost: $0 (local)                                          │
└────────────────────────────────────────────────────────────┘

Why Quick is Fastest: No network, pure CPU
Why Ollama Competitive: No network latency, parallel GPU
Why Cache Critical: Makes deep mode cost = quick mode speed
Why Rate Limits Matter: Cloud providers throttle (10/sec)
```

---

## Error Handling & Retries

### Network Error Handling Strategy

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Network Error Handling Flow                        │
└─────────────────────────────────────────────────────────────────────────┘

API Request
     │
     ▼
┌─────────────────┐
│ Send Request    │
└────────┬────────┘
         │
         ▼
    Success?
    ┌──┴──┐
    │     │
   YES    NO
    │     │
    │     ▼
    │  Error Type?
    │     │
    │     ├──> 401 Unauthorized ────────> FAIL FAST
    │     │    (Invalid API key)          ├──> Log error
    │     │                               └──> Exit code 3
    │     │
    │     ├──> 429 Too Many Requests ───> RETRY with Backoff
    │     │    (Rate limited)             ├──> Wait: 1s, 2s, 4s, 8s, 16s
    │     │                               ├──> Max retries: 5
    │     │                               ├──> Exponential backoff
    │     │                               └──> Jitter: ±20%
    │     │                                    (Prevent thundering herd)
    │     │
    │     ├──> 500 Internal Server Error ─> RETRY Linear
    │     │    (Provider issue)            ├──> Wait: 5s, 10s, 15s
    │     │                                ├──> Max retries: 3
    │     │                                └──> Log to warning
    │     │
    │     ├──> 503 Service Unavailable ──> FALLBACK Provider
    │     │    (Provider down)             ├──> Try next provider
    │     │                                │    (if configured)
    │     │                                └──> Or retry 2 times
    │     │
    │     ├──> Timeout (>30s) ───────────> RETRY Once
    │     │    (Slow response)             ├──> Increase timeout to 60s
    │     │                                └──> If still fails, skip file
    │     │
    │     ├──> Connection Refused ────────> CHECK LOCAL
    │     │    (Ollama not running)        ├──> If Ollama: Show error
    │     │                                │    "Start Ollama: ollama serve"
    │     │                                └──> Exit code 2
    │     │
    │     ├──> DNS Failure ───────────────> NETWORK CHECK
    │     │    (No internet)               ├──> Suggest: Check connection
    │     │                                └──> Exit code 2
    │     │
    │     └──> TLS Error ─────────────────> CERTIFICATE CHECK
    │          (Certificate invalid)       ├──> Warn: Update system certs
    │                                      └──> Exit code 2
    │
    └──> Parse Response
         │
         ▼
    Return Result

Retry Logic Example (429 Rate Limit):
┌─────────────────────────────────────────────────────────────┐
│ Attempt 1: Request → 429 → Wait 1s   (2^0 = 1s)            │
│ Attempt 2: Request → 429 → Wait 2s   (2^1 = 2s)            │
│ Attempt 3: Request → 429 → Wait 4s   (2^2 = 4s)            │
│ Attempt 4: Request → 429 → Wait 8s   (2^3 = 8s)            │
│ Attempt 5: Request → 429 → Wait 16s  (2^4 = 16s)           │
│ Attempt 6: FAIL → Log error, skip file                     │
│                                                             │
│ Total time spent: 1+2+4+8+16 = 31 seconds                  │
│ Jitter: Each wait ± 20% random (prevent sync retries)      │
└─────────────────────────────────────────────────────────────┘

Why Exponential Backoff: Give provider time to recover
Why Jitter: Prevent multiple clients retrying synchronously
Why Fail Fast (401): No point retrying invalid credentials
Why Fallback Providers: High availability, redundancy
```

---

## Rate Limiting & Backpressure

### Rate Limiting Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Rate Limiting Strategy                             │
└─────────────────────────────────────────────────────────────────────────┘

                         Files Needing AI Analysis (100)
                                      │
                                      ▼
                         ┌────────────────────────┐
                         │   File Queue           │
                         │   (Tokio Channel)      │
                         │   Capacity: Unbounded  │
                         └────────────┬───────────┘
                                      │
                                      ▼
                         ┌────────────────────────┐
                         │   Rate Limiter         │
                         │   (Tokio Semaphore)    │
                         │                        │
                         │   Permits: 5 (OpenAI)  │
                         │           3 (Anthropic)│
                         │          10 (Ollama)   │
                         └────────────┬───────────┘
                                      │
                         ┌────────────┴────────────┐
                         │   Wait for permit      │
                         │   Blocking if full     │
                         └────────────┬────────────┘
                                      │
                ┌─────────────────────┼─────────────────────┐
                │                     │                     │
                ▼                     ▼                     ▼
        ┌──────────────┐      ┌──────────────┐    ┌──────────────┐
        │  Task 1      │      │  Task 2      │    │  Task 3      │
        │  (Worker)    │      │  (Worker)    │    │  (Worker)    │
        └──────┬───────┘      └──────┬───────┘    └──────┬───────┘
               │                     │                    │
               ├──> API Request (800ms)                   │
               │                     ├──> API Request     │
               │                     │                    ├──> API Request
               │                     │                    │
               │<─── Response        │                    │
               │                     │<─── Response       │
               │                     │                    │<─── Response
               │                     │                    │
               ├──> Release permit   ├──> Release permit  ├──> Release permit
               │                     │                    │
               ▼                     ▼                    ▼
        Next file in queue      Next file           Next file
        can now start           can now start       can now start

Provider-Specific Limits:
┌─────────────┬──────────────────┬────────────────┬──────────────┐
│ Provider    │ API Rate Limit   │ Semaphore Size │ Reasoning    │
├─────────────┼──────────────────┼────────────────┼──────────────┤
│ OpenAI      │ 10 req/sec       │ 5              │ 50% safety   │
│ Anthropic   │ 5 req/sec (Haiku)│ 3              │ 60% safety   │
│ Gemini      │ 60 req/min       │ 1              │ Conservative │
│ Ollama      │ Unlimited        │ 10             │ GPU-bound    │
└─────────────┴──────────────────┴────────────────┴──────────────┘

Why Semaphore: Fair access, prevents rate limit errors
Why Conservative: Safety margin for bursty traffic
Why Provider-Specific: Different rate limits need different strategies
Why Tokio: Async-aware, non-blocking, efficient
```

---

### Backpressure Handling

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Backpressure Flow                               │
└─────────────────────────────────────────────────────────────────────────┘

Scenario: Scanning 1,000 files, but API rate limit = 5/sec

Without Backpressure (BAD):
├──> Queue all 1,000 requests immediately
├──> Overload API (429 errors)
├──> Waste time on retries
└──> Memory exhaustion (queue too large)

With Backpressure (GOOD):
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  File Scanner (Producer)                                    │
│       │                                                     │
│       ├──> Produce: 100 files/sec                          │
│       │                                                     │
│       ▼                                                     │
│  ┌─────────────────┐                                       │
│  │  Bounded Queue  │  Capacity: 50                         │
│  │  (Channel)      │                                       │
│  └────────┬────────┘                                       │
│           │                                                 │
│           │  FULL? ──> Block producer (backpressure)       │
│           │           ├──> Scanner waits                   │
│           │           └──> Memory usage controlled         │
│           │                                                 │
│           ▼                                                 │
│  ┌─────────────────┐                                       │
│  │  Rate Limiter   │  Semaphore: 5                         │
│  └────────┬────────┘                                       │
│           │                                                 │
│           ▼                                                 │
│  API Workers (Consumer)                                     │
│       │                                                     │
│       ├──> Consume: 5 files/sec (rate limited)             │
│       │                                                     │
│       └──> Process at sustainable rate                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘

Backpressure Benefits:
1. Memory Control: Queue size bounded (50 items = ~5MB)
2. Rate Limit Compliance: Never exceed provider limits
3. Fair Scheduling: FIFO processing
4. Resource Protection: No API overload
5. Graceful Degradation: Slow down instead of crash

Backpressure Metrics:
┌──────────────────────────────────────────────────────────┐
│ Metric               │ Value           │ Meaning        │
├──────────────────────┼─────────────────┼────────────────┤
│ Queue Size           │ 10/50           │ Healthy        │
│ Producer Blocked     │ 0%              │ No backpressure│
│ Consumer Utilization │ 100%            │ Fully utilized │
│                      │                 │                │
│ Queue Size           │ 50/50 (FULL)    │ Backpressure!  │
│ Producer Blocked     │ 80%             │ Heavy backpr.  │
│ Consumer Utilization │ 100%            │ Bottleneck     │
│                      │                 │                │
│ Solution: Increase semaphore size (if rate limit allows) │
│           Or accept slower scan speed                    │
└──────────────────────────────────────────────────────────┘

Why Bounded Queue: Prevent memory exhaustion
Why Block Producer: Natural backpressure mechanism
Why Tokio Channels: Async-aware, efficient, zero-copy
```

---

## Summary

**Key Network Principles**:

1. **Zero Network by Default**: Quick scans work offline
2. **Explicit Cloud Opt-In**: Deep mode requires `--llm-provider` flag
3. **Local-First AI**: Ollama enables private, fast, free analysis
4. **TLS Everywhere**: All cloud communication encrypted (TLS 1.3)
5. **Rate Limiting**: Respect provider limits via semaphores
6. **Data Sanitization**: Remove secrets before sending to cloud
7. **Caching**: Avoid redundant expensive API calls
8. **Error Handling**: Exponential backoff, fallback providers
9. **Backpressure**: Bounded queues prevent overload
10. **Transparency**: Proxy mode requires zero config changes

**Network Security Best Practices**:
- ✅ HTTPS only (no HTTP for cloud APIs)
- ✅ API keys in headers (not URLs)
- ✅ Certificate validation enforced
- ✅ Request size limits (4KB max per snippet)
- ✅ Timeout enforcement (30s default)
- ✅ Credential sanitization before cloud
- ✅ Local-first design (Ollama preferred)

**Performance Optimization**:
- ✅ Connection pooling (HTTP/2)
- ✅ Concurrent requests (semaphore-controlled)
- ✅ Content-addressable caching (SHA-256)
- ✅ gzip compression (70-90% size reduction)
- ✅ Incremental scanning (git diff-aware)

For more information, see:
- [Architecture Documentation](./ARCHITECTURE.md)
- [CLI Reference](./CLI_REFERENCE.md)
- [GitHub Repository](https://github.com/mcpsentinel/mcp-sentinel)
