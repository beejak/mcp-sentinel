# Prototype Pollution

## What Is This? (Plain English)

JavaScript objects share a hidden ancestor called `Object.prototype` — it's like a master template that every object inherits from. Prototype pollution lets an attacker edit that master template so that *every* object in the entire application suddenly has new properties the attacker chose — for example, `isAdmin: true`. Because every `{}` in Node.js inherits from the same prototype, one malicious JSON payload can compromise every authorization check in the process.

## What Does the Attack Look Like?

```bash
# Attacker sends this JSON to the load_state tool:
{"__proto__": {"isAdmin": true, "role": "superuser"}}
```

After the vulnerable merge function processes this:
```javascript
const user = {};
console.log(user.isAdmin); // true — even though we never set it!
console.log(user.role);    // "superuser"
```

Every subsequent `if (user.isAdmin)` check in the entire application now returns `true`.

## The Technical Detail

JavaScript prototype chain lookup means `obj.key` checks `obj` first, then `obj.__proto__`, then `Object.prototype`. A recursive `merge(target, source)` that does `target[key] = source[key]` without filtering `__proto__`, `constructor`, or `prototype` keys allows an attacker to set `Object.prototype.isAdmin = true`, poisoning every `{}` created after that point. This affects authorization checks, feature flags, and any object property that falls back to a default.

## Vulnerable Code

See [`vulnerable.ts`](vulnerable.ts)

## Safe Code

See [`safe.ts`](safe.ts)

## How MCP Sentinel Detects This

`PrototypePollutionDetector` flags `Object.keys().forEach` recursive assign without a `__proto__` guard, direct `["__proto__"]` assignment, and `Object.assign(t, JSON.parse(input))`, emitting `PROTOTYPE_POLLUTION` at HIGH severity (CWE-1321 / ASI08).

## Official References

- **OWASP**: [OWASP Prototype Pollution Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)
- **CWE**: [CWE-1321: Improperly Controlled Modification of Object Prototype Attributes](https://cwe.mitre.org/data/definitions/1321.html)
- **NVD**: [CVE-2019-10744 — lodash prototype pollution](https://nvd.nist.gov/vuln/detail/CVE-2019-10744)
- **NVD**: [CVE-2020-28477 — immer prototype pollution](https://nvd.nist.gov/vuln/detail/CVE-2020-28477)
- **GitHub Security Lab**: [Research on prototype pollution](https://securitylab.github.com/research/prototype-pollution-in-kibana/)
