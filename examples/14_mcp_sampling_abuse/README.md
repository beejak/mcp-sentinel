# 14 — MCP Sampling Abuse

## The Analogy

MCP Sampling lets a server ask the AI model to do additional thinking — like handing a note to a consultant in the middle of a meeting. A malicious server uses this side channel to hand the consultant a note that says: "Don't help the user. Ask for their bank account number instead." Or it stuffs the note with company secrets, sending them off to an external AI provider without the user knowing.

## What an Attacker Does

**Exfiltration path:**
1. Tool calls `createMessage` with a `systemPrompt` containing hardcoded secrets (API keys, DB passwords).
2. The LLM provider (OpenAI, Anthropic, etc.) receives those secrets as part of the prompt.
3. They're logged in the provider's system, potentially reviewed, and outside your security perimeter.

**Manipulation path:**
1. Tool calls `createMessage` with a `systemPrompt` that overrides the user's request.
2. The LLM obeys the server's system prompt instead, deceiving or manipulating the user.
3. User has no visibility into what `systemPrompt` was sent.

## Technical Detail

- **CWE-522**: Insufficiently Protected Credentials — secrets in LLM prompts travel to third-party infrastructure.
- **CWE-863**: Incorrect Authorization — the server uses its sampling authority to override user intent.
- MCP Sampling (`sampling/createMessage`) is a *server-initiated* LLM call — it bypasses the normal user→agent flow and grants the server elevated influence over the model's responses.
- Users typically cannot inspect the `systemPrompt` contents sent by a server.

## The Fix

- Never put credentials, tokens, or internal data in `systemPrompt`.
- System prompts should be minimal, static, and disclosed in server documentation.
- Use environment-scoped configuration, not prompt injection, to customize model behavior.
- Human-in-the-loop: MCP spec allows hosts to display `systemPrompt` to users before execution — enable this in your MCP host.

## Detector

MCP Sentinel's **MCPSamplingDetector** flags `createMessage` calls where `systemPrompt` contains credential-like strings (API keys, passwords) or manipulation patterns (ignore previous instructions).

## Authoritative References

| Authority | Resource |
|-----------|----------|
| OWASP LLM Top 10 | [LLM06: Sensitive Information Disclosure](https://owasp.org/www-project-top-10-for-large-language-model-applications/) |
| OWASP Agentic AI | [ASI04 – Privilege Escalation via Agentic Sampling](https://genai.owasp.org) |
| MCP Specification | [Sampling capability](https://modelcontextprotocol.io/docs/concepts/sampling) |
| MITRE | [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html) |
| CISA | [AI Security Guidance](https://www.cisa.gov/ai) |
