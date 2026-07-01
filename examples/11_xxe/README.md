# 11 — XML External Entity (XXE) Injection

## The Analogy

XML supports a feature called "entities" — think of them as variables inside an XML document. A safe entity might be `&amp;` expanding to `&`. But an *external* entity points to a file or URL: `<!ENTITY secret SYSTEM "file:///etc/passwd">`. When the XML parser dutifully reads that file and inserts its contents into the document, you've just handed an attacker your server's password list. An attacker is like someone who sneaked an "include my spy camera" clause into a contract you're signing.

## What an Attacker Does

1. The tool accepts an XML string and parses it with Python's stdlib `xml.etree.ElementTree`.
2. Attacker sends:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
   <root>&xxe;</root>
   ```
3. The parser resolves `&xxe;` by reading `/etc/passwd` and inserts it into the document.
4. The tool returns the content — handing over the full password file.

With SSRF-capable parsers, `SYSTEM "http://internal-service/admin"` pivots into internal network access.

## Technical Detail

- **CWE-611**: Improper Restriction of XML External Entity Reference.
- Python's `xml.etree.ElementTree`, `xml.dom.minidom`, and `lxml` (without `resolve_entities=False`) all resolve external entities by default in some configurations.
- The `defusedxml` library patches all Python XML parsers to disable entity expansion, DTD processing, and billion-laughs attacks.

## The Fix

- Replace `import xml.etree.ElementTree` with `import defusedxml.ElementTree`.
- For lxml: `etree.XMLParser(resolve_entities=False, no_network=True)`.
- In JavaScript/TypeScript: DOMParser in Node.js does not resolve external entities by default, but third-party XML parsers may — check their documentation.

## Detector

MCP Sentinel's **XXEDetector** flags stdlib ET/minidom imports without a corresponding `defusedxml` import, lxml parsers without `resolve_entities=False`, and `<!ENTITY SYSTEM` patterns in XML fixtures.

## Authoritative References

| Authority | Resource |
|-----------|----------|
| OWASP | [A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) |
| OWASP | [XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) |
| CISA | [Known Exploited Vulnerabilities (search XXE)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| MITRE | [CWE-611: XXE](https://cwe.mitre.org/data/definitions/611.html) |
| PyPI | [defusedxml](https://pypi.org/project/defusedxml/) |
