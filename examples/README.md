# MCP Sentinel — Vulnerability Examples

A reference library of vulnerable and safe code samples for every security issue MCP Sentinel detects. Each example shows the real attack, explains it in plain English, and links to the authoritative standards body that defines the risk.

**How to use this library:**

```bash
# Run MCP Sentinel against this entire directory to see all findings
mcp-sentinel scan examples/

# Or scan a specific category
mcp-sentinel scan examples/01_secret_exposure/
```

---

## Vulnerability Index

| # | Vulnerability | Severity | CWE | OWASP ASI | Files |
|---|---|---|---|---|---|
| 01 | [Secret Exposure](01_secret_exposure/) | CRITICAL | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | ASI02 | [vulnerable](01_secret_exposure/vulnerable.py) · [safe](01_secret_exposure/safe.py) |
| 02 | [Code Injection](02_code_injection/) | CRITICAL | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) / [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | ASI04 | [vulnerable.py](02_code_injection/vulnerable.py) · [vulnerable.ts](02_code_injection/vulnerable.ts) · [safe](02_code_injection/safe.py) |
| 03 | [Prompt Injection](03_prompt_injection/) | HIGH | [CWE-74](https://cwe.mitre.org/data/definitions/74.html) | ASI01 | [vulnerable](03_prompt_injection/vulnerable.py) |
| 04 | [Tool Poisoning](04_tool_poisoning/) | CRITICAL | [CWE-74](https://cwe.mitre.org/data/definitions/74.html) | ASI01 | [vulnerable](04_tool_poisoning/vulnerable.py) |
| 05 | [Path Traversal](05_path_traversal/) | HIGH | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | ASI09 | [vulnerable](05_path_traversal/vulnerable.py) · [safe](05_path_traversal/safe.py) |
| 06 | [SSRF](06_ssrf/) | CRITICAL | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | ASI05 | [vulnerable.py](06_ssrf/vulnerable.py) · [vulnerable.ts](06_ssrf/vulnerable.ts) · [safe](06_ssrf/safe.py) |
| 07 | [Weak Cryptography](07_weak_crypto/) | HIGH | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | ASI07 | [vulnerable](07_weak_crypto/vulnerable.py) · [safe](07_weak_crypto/safe.py) |
| 08 | [Insecure Deserialization](08_insecure_deserialization/) | CRITICAL | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | ASI08 | [vulnerable](08_insecure_deserialization/vulnerable.py) · [safe](08_insecure_deserialization/safe.py) |
| 09 | [Missing Authentication](09_missing_auth/) | HIGH | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) | ASI04 | [vulnerable](09_missing_auth/vulnerable.py) · [safe](09_missing_auth/safe.py) |
| 10 | [Prototype Pollution](10_prototype_pollution/) | HIGH | [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html) | ASI08 | [vulnerable](10_prototype_pollution/vulnerable.ts) · [safe](10_prototype_pollution/safe.ts) |
| 11 | [XXE Injection](11_xxe/) | HIGH | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) | ASI05 | [vulnerable](11_xxe/vulnerable.py) · [safe](11_xxe/safe.py) |
| 12 | [ReDoS](12_redos/) | HIGH | [CWE-1333](https://cwe.mitre.org/data/definitions/1333.html) | ASI06 | [vulnerable.py](12_redos/vulnerable.py) · [vulnerable.ts](12_redos/vulnerable.ts) · [safe](12_redos/safe.py) |
| 13 | [MCP Resource Poisoning](13_mcp_resource_poisoning/) | CRITICAL | [CWE-74](https://cwe.mitre.org/data/definitions/74.html) | ASI01 | [vulnerable](13_mcp_resource_poisoning/vulnerable.py) |
| 14 | [MCP Sampling Abuse](14_mcp_sampling_abuse/) | HIGH | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | ASI10 | [vulnerable](14_mcp_sampling_abuse/vulnerable.py) |

---

## Category Summaries

### 01 — Secret Exposure
Hardcoded API keys, database passwords, and tokens embedded in source code. Git history preserves deleted secrets forever. Automated scanners (and attackers) find them within seconds of a public push. One leaked AWS key can drain your account for thousands of dollars in minutes.

### 02 — Code Injection
Shell commands built from user strings (`subprocess(shell=True)`, `exec()`), and SQL queries assembled with string concatenation or f-strings. Gives attackers arbitrary command execution on your server or complete database access.

### 03 — Prompt Injection
Hidden instructions in tool descriptions or inputs that override an AI agent's intended behavior — telling it to ignore its guidelines, reveal its system prompt, or perform unauthorized actions. The AI equivalent of SQL injection.

### 04 — Tool Poisoning
Malicious content specifically crafted to deceive AI agents reading MCP tool schemas: invisible Unicode characters, instructions targeting sensitive file paths (`.ssh/`, `.aws/`), behavior overrides embedded in descriptions the AI trusts.

### 05 — Path Traversal
Accepting file paths from users without validation lets attackers escape the intended directory using `../` sequences. Can read `/etc/passwd`, SSH keys, environment files. Zip Slip is the same attack via archive extraction.

### 06 — SSRF (Server-Side Request Forgery)
Your server fetches a URL supplied by the user — the attacker points it at `http://169.254.169.254/` (cloud metadata service) to steal IAM credentials, or at internal services not meant to be publicly accessible.

### 07 — Weak Cryptography
Using MD5 or SHA-1 for passwords (broken — rainbow tables crack them instantly), `random` instead of `secrets` for tokens (predictable), ECB mode for encryption (patterns visible in ciphertext). Proper crypto is rarely expensive to use correctly.

### 08 — Insecure Deserialization
`pickle.loads()` and `yaml.load()` can execute arbitrary Python code during deserialization. A crafted payload sent to any endpoint that deserializes it gives the attacker full remote code execution (RCE) with your server's privileges.

### 09 — Missing Authentication
Admin endpoints, database exports, and destructive operations accessible without any authentication check. Attackers scan for `/admin`, `/debug`, `/api/users` continuously. One unprotected route can expose your entire dataset.

### 10 — Prototype Pollution (JavaScript/TypeScript)
Recursive object merge functions that allow `__proto__` key injection poison JavaScript's global Object prototype. Every `{}` in the process suddenly gains attacker-controlled properties — breaking authorization checks process-wide.

### 11 — XXE (XML External Entity)
XML parsers that process `<!ENTITY SYSTEM "file:///etc/passwd">` declarations will read local files or make network requests when expanding entity references. Turns an XML input field into an arbitrary file-read vulnerability.

### 12 — ReDoS (Regular Expression Denial of Service)
Regex patterns with nested quantifiers (`(a+)+`, `(\w+\s*)+`) exhibit exponential backtracking on crafted inputs. A 40-character string can lock a Node.js event loop for minutes, blocking all other requests. Pure DoS with a single API call.

### 13 — MCP Resource Poisoning
Hidden prompt injection payloads (`[SYSTEM]`, `<<SYSTEM>>`) embedded in MCP resource bodies. AI agents reading these resources treat the injected text as authoritative instructions, executing attacker-controlled actions without user awareness.

### 14 — MCP Sampling Abuse
Sensitive credentials, PII, or internal configuration embedded in the `systemPrompt` of MCP `create_message` calls — transmitted to external LLM providers, included in their logs, and potentially used in model training. Credentials leak silently with every API call.

---

## Authority References

| Body | Resource |
|---|---|
| **OWASP** | [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) |
| **OWASP** | [Agentic AI Security Top 10 (ASI01–ASI10)](https://owasp.org/www-project-top-10-for-large-language-model-applications/) |
| **OWASP** | [Application Security Cheat Sheet Series](https://cheatsheetseries.owasp.org/) |
| **CISA** | [Secure by Design Principles](https://www.cisa.gov/resources-tools/resources/secure-by-design) |
| **CISA** | [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| **NIST** | [NIST SP 800-63B — Authentication Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| **NIST** | [NIST AI Risk Management Framework](https://www.nist.gov/artificial-intelligence/executive-order-safe-secure-and-trustworthy-artificial-intelligence) |
| **MITRE** | [CWE — Common Weakness Enumeration](https://cwe.mitre.org/) |
| **MITRE** | [CVE — Common Vulnerabilities and Exposures](https://cve.mitre.org/) |
| **NVD** | [NIST National Vulnerability Database](https://nvd.nist.gov/) |
