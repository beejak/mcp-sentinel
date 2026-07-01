# 10 — Prototype Pollution

## The Analogy

JavaScript objects inherit properties from a shared ancestor called the *prototype*. Prototype pollution is like changing the blueprint that every house in a city is built from — once you alter the blueprint, every building gets your modification without anyone realizing it. Attackers poison the prototype so that *all* objects suddenly have properties like `isAdmin: true`.

## What an Attacker Does

1. The tool accepts JSON and passes it to a recursive merge function.
2. Attacker sends: `{"__proto__": {"isAdmin": true}}`
3. The merge function loops over keys, hits `__proto__`, and does `target["__proto__"] = {isAdmin: true}`.
4. This mutates `Object.prototype` — the ancestor of *every* object in the Node.js process.
5. Any subsequent check like `if (user.isAdmin)` returns `true` — even for anonymous users.

## Technical Detail

- **CWE-1321**: Improper Control of Property Modification of Object Prototype Attributes.
- Affects any JavaScript/TypeScript code with recursive merge, `Object.assign(target, untrusted)`, or bracket-notation assignment without key filtering.
- Can lead to privilege escalation, RCE (if merged into a config that controls `shell` or `exec`), or DoS.

## The Fix

- Guard recursive merges: `if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;`
- Use `Object.create(null)` for dictionaries — these objects have no prototype to pollute.
- Validate all incoming JSON against a strict schema before processing.
- Use `structuredClone()` (Node 17+) which is prototype-pollution-safe.

## Detector

MCP Sentinel's **PrototypePollutionDetector** flags unguarded recursive merges and `Object.assign(target, JSON.parse(...))` patterns in TypeScript and JavaScript files.

## Authoritative References

| Authority | Resource |
|-----------|----------|
| OWASP | [Prototype Pollution](https://owasp.org/www-community/attacks/Prototype_Pollution) |
| OWASP Agentic AI | [ASI08 – Data Integrity Violations](https://genai.owasp.org) |
| MITRE | [CWE-1321: Prototype Pollution](https://cwe.mitre.org/data/definitions/1321.html) |
| GitHub Advisory | [Multiple npm packages – prototype pollution](https://github.com/advisories?query=prototype+pollution) |
| Snyk | [What is Prototype Pollution?](https://learn.snyk.io/lesson/prototype-pollution/) |
