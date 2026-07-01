# 12 — ReDoS (Regular Expression Denial of Service)

## The Analogy

Some regex patterns work like a confused postal worker who, unable to find an address, tries *every possible route* through the city before admitting defeat. An attacker gives the server a deliberately crafted string that triggers this exhaustive search, freezing your server while the regex engine backtracks exponentially. One request — one line of input — can consume 100% CPU for minutes or hours.

## What an Attacker Does

1. The tool uses `/(a+)+$/` to validate a slug.
2. Attacker sends the string `"aaaaaaaaaaaaaaaaaaaaX"` (20 a's followed by X).
3. The regex engine tries to match the `$` anchor, fails, then backtracks through 2²⁰ = 1,048,576 combinations.
4. The Node.js event loop is blocked — the server stops responding to all other requests.

## Technical Detail

- **CWE-1333**: Inefficient Regular Expression Complexity.
- Root cause: *nested quantifiers* like `(a+)+`, `(\w+)*`, `(a|b)+` where multiple quantifiers can match the same positions in the string, creating ambiguity the backtracking engine must exhaustively explore.
- The evil input structure: the "correct" prefix followed by a character that causes the match to fail at the end, triggering catastrophic backtracking.
- Node.js has no regex timeout by default — a single vulnerable regex can freeze a production server.

## The Fix

- Rewrite regexes to eliminate nested quantifiers: `(a+)+` → `a+`
- Add input length limits *before* running regex: `z.string().max(254)`
- Use a ReDoS analyzer (e.g., `safe-regex`, `vuln-regex-detector`) in CI.
- In Node 22+ or Deno, consider regex timeout via `--experimental-vm-modules` or third-party sandboxing.

## Detector

MCP Sentinel's **ReDoSDetector** extracts regex literals from JS/TS files and Python `re.compile()` calls, then checks for nested quantifier patterns: `(x+)+`, `(x*)+`, `(x+)*`, `(x|y)+`.

## Authoritative References

| Authority | Resource |
|-----------|----------|
| OWASP | [ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS) |
| OWASP Agentic AI | [ASI06 – Excessive Agency / Resource Abuse](https://genai.owasp.org) |
| MITRE | [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html) |
| NIST | [NVD CWE-1333](https://nvd.nist.gov/vuln/search/results?cwe_id=CWE-1333) |
| npm | [safe-regex package](https://www.npmjs.com/package/safe-regex) |
