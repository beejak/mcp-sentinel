# Server-Side Request Forgery (SSRF)

## What Is This? (Plain English)

Imagine asking a trusted company employee to "go pick up a package from this address." Normally that's fine — but if you give them the address of the company's own server room and say "grab the master key cabinet while you're there," you've just used their trusted access to reach somewhere you couldn't go yourself. SSRF works the same way: an attacker tricks a server into making HTTP requests on their behalf, using the server's privileged network position to reach internal services, cloud metadata endpoints, or databases that are invisible to the outside world.

## What Does the Attack Look Like?

```python
@server.tool("fetch_url")
def fetch_url(url: str) -> dict:
    response = requests.get(url, timeout=10)  # no validation
    return {"body": response.text}
```

Attacker provides: `url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/my-role"`. The server (running on AWS EC2) fetches the Instance Metadata Service, which returns temporary AWS credentials — giving the attacker full cloud API access. Other payloads: `http://localhost:6379/` probes Redis; `http://internal-db.corp:5432/` maps the internal network.

## The Technical Detail

SSRF exploits the trust relationship between the server and its internal network. Servers often have access to: cloud instance metadata endpoints (169.254.169.254 on AWS/Azure/GCP), internal microservices not exposed to the internet, and management interfaces (Kubernetes API, internal dashboards). The attack is especially dangerous in cloud environments where the metadata endpoint issues credentials with broad IAM permissions. Common bypasses include: DNS rebinding, open redirects on trusted domains, IPv6 representations of blocked IPv4 addresses, and URL-encoded characters.

## Vulnerable Code

See [`vulnerable.py`](vulnerable.py) and [`vulnerable.ts`](vulnerable.ts)

## Safe Code

See [`safe.py`](safe.py)

## How MCP Sentinel Detects This

The `SSRFDetector` identifies `requests.get(url)`, `httpx.get(url)`, and `fetch(url)` calls where the URL parameter is user-controlled without validated filtering, and emits an `SSRF` finding with `HIGH` severity.

## Official References

- **OWASP**: [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- **NIST / NVD**: [NVD CWE-918 Search](https://nvd.nist.gov/vuln/search/results?query=CWE-918)
- **CISA**: [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **CWE**: [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
