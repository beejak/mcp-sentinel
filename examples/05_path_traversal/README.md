# Path Traversal

## What Is This? (Plain English)

Imagine a library where the librarian will fetch any book you name. You're supposed to ask for books in the "Public" section, but you discover that if you say "go back to the staff room, then into the vault, and get the book called 'Master Keys'", the librarian just does it. Path traversal works the same way: an attacker uses `../` (which means "go up one folder") in a filename to escape the intended folder and access files anywhere on the server — including passwords, SSH keys, and configuration secrets.

## What Does the Attack Look Like?

```python
@server.tool("read_file")
def read_file(filename: str) -> dict:
    with open(filename) as f:
        return {"content": f.read()}
```

Attacker provides: `filename = "../../etc/passwd"`. The server opens `/etc/passwd`, returning all system usernames. With `filename = "../../../home/user/.ssh/id_rsa"`, the attacker retrieves the server's private SSH key, enabling full server access.

**Zip Slip** variant: A crafted zip file contains a member named `../../etc/cron.d/backdoor`. When `zipfile.extractall()` processes it without path validation, the file is written to `/etc/cron.d/backdoor`, installing a cron-based backdoor.

## The Technical Detail

The vulnerability arises from using user-controlled input directly in filesystem operations without confirming the resolved path remains within the intended directory. `os.path.join("/base", "../../etc/passwd")` evaluates to `/etc/passwd` — the base is silently discarded. The correct fix is to call `Path.resolve()` on the joined path and then call `.relative_to(base)`, which raises `ValueError` if the path escapes. Zip Slip requires checking each archive member individually because `extractall()` does not validate member paths.

## Vulnerable Code

See [`vulnerable.py`](vulnerable.py)

## Safe Code

See [`safe.py`](safe.py)

## How MCP Sentinel Detects This

The `PathTraversalDetector` identifies unvalidated file operations (`open(filename)`, `os.path.join` with user input, `zipfile.extractall` without member validation) and emits a `PATH_TRAVERSAL` finding with `HIGH` severity.

## Official References

- **OWASP**: [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal) and [File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- **NIST / NVD**: [NVD CWE-22 Search](https://nvd.nist.gov/vuln/search/results?query=CWE-22)
- **CISA**: [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **CWE**: [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html) and [CWE-23: Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)
