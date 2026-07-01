# ReDoS — Regular Expression Denial of Service

## What Is This? (Plain English)

Some regular expressions contain a hidden trap: given just the right input, they force the computer to try an astronomically large number of combinations before giving up. It's like asking someone to find a word in a dictionary by checking every possible ordering of the letters — the work grows exponentially. An attacker who knows the pattern can send a short string (40-50 characters) that locks your server's CPU for minutes, making it completely unresponsive to all other users.

## What Does the Attack Look Like?

```python
import re, time
pattern = re.compile(r"(a+)+$")
start = time.time()
pattern.match("a" * 35 + "b")  # Should match instantly — but doesn't
print(f"Took {time.time()-start:.1f}s")  # Prints: "Took 47.3s" (or worse)
```

An attacker sends this 36-character string to your API. Your server hangs, timing out all legitimate requests, until the pattern finally gives up. One request = one CPU core pegged at 100%.

## The Technical Detail

Nested quantifiers like `(a+)+`, `(\w+\s*)+`, or `(x|y)+$` cause exponential backtracking in NFA-based regex engines (Python `re`, JavaScript V8, Java `java.util.regex`). For an input of length `n`, the engine may explore O(2ⁿ) paths before failing. Python 3.11+ added backtracking limits, but Node.js has no built-in protection — a single crafted request can lock the event loop, blocking all MCP tool calls.

## Vulnerable Code

See [`vulnerable.py`](vulnerable.py) and [`vulnerable.ts`](vulnerable.ts)

## Safe Code

See [`safe.py`](safe.py)

## How MCP Sentinel Detects This

`ReDoSDetector` extracts regex literals from JS/TS and `re.compile()` calls from Python, then checks for nested quantifier patterns `(x+)+`, `(x*)+`, `(x|y)+`, emitting `REDOS` at HIGH severity (CWE-1333 / ASI06).

## Official References

- **OWASP**: [OWASP Regular Expression Denial of Service](https://owasp.org/www-community/attacks/ReDoS)
- **CWE**: [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
- **NIST NVD**: [CVE-2022-25912 — simple-git ReDoS](https://nvd.nist.gov/vuln/detail/CVE-2022-25912)
- **NIST NVD**: [CVE-2021-27292 — ua-parser-js ReDoS](https://nvd.nist.gov/vuln/detail/CVE-2021-27292)
