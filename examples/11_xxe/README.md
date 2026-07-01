# XXE — XML External Entity Injection

## What Is This? (Plain English)

XML files can contain "entities" — think of them as macros or variables. The problem is that standard XML parsers allow those macros to load the contents of any file on the server, or make network requests. An attacker sends you a carefully crafted XML invoice with a hidden instruction: "replace this placeholder with the contents of `/etc/passwd`." If your XML parser obediently does so, the attacker now has your server's user database — or your cloud credentials.

## What Does the Attack Look Like?

An attacker submits this XML to `parse_invoice`:
```xml
<?xml version="1.0"?>
<!DOCTYPE invoice [
  <!ENTITY xxe SYSTEM "file:///etc/shadow">
]>
<invoice>
  <amount>&xxe;</amount>
  <vendor>Evil Corp</vendor>
</invoice>
```

The parser expands `&xxe;` by reading `/etc/shadow` and inserting its contents into the `amount` field. The tool returns the hashed passwords of every user on the server.

## The Technical Detail

XML's DTD (Document Type Definition) allows defining `ENTITY` declarations with `SYSTEM` or `PUBLIC` keywords that instruct the parser to fetch the entity value from a URI — `file://`, `http://`, `ftp://`. When the parser expands `&entity;`, it reads the file or makes the network request. Python's stdlib `xml.etree.ElementTree` mitigates this since Python 3.8, but `lxml` and older parsers are fully vulnerable without explicit hardening. The `SSRF` variant uses `http://` URIs to reach internal services.

## Vulnerable Code

See [`vulnerable.py`](vulnerable.py)

## Safe Code

See [`safe.py`](safe.py)

## How MCP Sentinel Detects This

`XXEDetector` flags `xml.etree.ElementTree.fromstring/parse`, `minidom.parseString`, and `lxml.etree` calls without `resolve_entities=False`, emitting `XXE` at HIGH severity (CWE-611 / ASI05). Files importing `defusedxml` are suppressed.

## Official References

- **OWASP**: [OWASP A05:2021 — Security Misconfiguration / XXE](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- **OWASP**: [XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- **CISA**: [CISA Known Exploited Vulnerabilities — XXE](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **CWE**: [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
- **NVD**: [CVE-2019-0197 — Apache XXE](https://nvd.nist.gov/vuln/detail/CVE-2019-0197)
