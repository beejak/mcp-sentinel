# Secret Exposure

## What Is This? (Plain English)

Imagine writing your house key's hiding spot — "under the front doormat" — on a sticky note and mailing it to everyone who has ever read your house blueprints. That's what hardcoded credentials do: anyone who can read the source code (a contractor, a disgruntled employee, someone who finds the code on GitHub) instantly has the keys to your cloud accounts, databases, and APIs. The damage can be enormous — attackers have drained entire AWS accounts within minutes of a key appearing in a public repository.

## What Does the Attack Look Like?

An attacker finds your repository (public GitHub, a leaked archive, or an insider threat). They search for patterns like `AKIA`, `sk-`, `postgresql://`, or `secret`:

```python
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_URL = "postgresql://admin:SuperSecretPass123@db.example.com/prod"
```

They copy the credentials, authenticate to AWS directly, spin up EC2 instances for crypto mining, exfiltrate your entire RDS database, and run up a $50,000 bill — all before you notice. Git history means even deleting the file in a new commit doesn't help; the secret lives forever in `git log`.

## The Technical Detail

Hardcoded credentials are stored in plaintext inside source files. When the repository is shared (cloned, forked, CI/CD pipeline access, code review tools), every recipient gets the credentials. Git history preserves every version of every file, so a secret committed and later deleted is still recoverable via `git log -p`. Automated scanners (GitHub's secret scanning, truffleHog, gitleaks) continuously crawl public repositories and alert — or silently harvest — such credentials within seconds of a push. The CWE-798 ("Use of Hard-coded Credentials") pattern is one of the most commonly exploited weaknesses in real-world breaches.

## Vulnerable Code

See [`vulnerable.py`](vulnerable.py)

## Safe Code

See [`safe.py`](safe.py)

## How MCP Sentinel Detects This

The `SecretsDetector` scans for high-entropy strings and known credential patterns (AWS key prefixes `AKIA`, OpenAI `sk-proj-`, Anthropic `sk-ant-`, JWT secrets, database DSNs) and emits a `SECRET_EXPOSURE` finding with `CRITICAL` severity.

## Official References

- **OWASP**: [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- **NIST / NVD**: [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- **CISA**: [CISA Secure by Design — Eliminate Default Passwords](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- **CWE**: [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
