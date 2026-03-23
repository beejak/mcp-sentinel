# MCP Sentinel — Session Handoff

**Last Updated:** 2026-03-23
**Current Version:** v0.4.0
**Branch:** `claude/cleanup-codebase-footprint-ZWcWI`
**Test Suite:** 525 passed, 4 xfailed, 0 failed

---

## What Was Done This Session

### New Detectors (v0.4.0)

**`WeakCryptoDetector`** (`src/mcp_sentinel/detectors/weak_crypto.py`)
- 6 pattern categories: `broken_hash`, `insecure_random`, `ecb_mode`, `deprecated_cipher`, `static_iv`, `weak_kdf`
- Covers: Python hashlib, JS crypto.createHash, Java MessageDigest; random/Math.random; AES-ECB; DES/RC4/Blowfish; static IV bytes; PBKDF2/bcrypt low iterations
- 60 tests in `tests/unit/test_weak_crypto.py`

**`InsecureDeserializationDetector`** (`src/mcp_sentinel/detectors/insecure_deserialization.py`)
- 9 pattern categories: `pickle_loads`, `unsafe_yaml`, `marshal_loads`, `eval_deserialization`, `shelve_open`, `jsonpickle`, `java_object_stream`, `php_unserialize`, `node_eval`
- Language-scoped: PHP patterns only on `.php` files; Java patterns only on `.java` files
- 54 tests in `tests/unit/test_insecure_deserialization.py`

### Code Cleanup

| Fix | File | Detail |
|---|---|---|
| Version string corrected | `src/mcp_sentinel/__init__.py` | `"4.1.0"` → `"0.4.0"` |
| XPASS tests promoted | `tests/unit/test_code_injection.py` | Removed stale `@pytest.mark.xfail` from `test_ignore_javascript_comments` and `test_python_fixture_file` — both were unexpectedly passing |
| Legacy scanner updated | `src/mcp_sentinel/core/scanner.py` | `_get_default_detectors()` was stuck at 6 detectors (v0.1); updated to all 12 |

### Test Suite Progress

| Version | Tests | Notes |
|---|---|---|
| v0.1.0 | 248 | 6 detectors |
| v0.2.0 | 334 | +86: SSRF, NetworkBinding, MissingAuth, full-schema ToolPoisoning |
| v0.3.0 | 409 | +75: SupplyChainDetector |
| v0.4.0 | 502 | +93: WeakCrypto, InsecureDeserialization |
| v0.4.0 post-cleanup | **525** | +23: edge case coverage + 2 xpass tests promoted to regular |

---

## Current Codebase State

```
src/mcp_sentinel/
├── __init__.py              ← version: 0.4.0
├── cli/main.py              ← scan command, terminal/json/sarif output
├── core/
│   ├── config.py
│   ├── logger.py
│   ├── cache_manager.py     ← MD5-based scan result cache
│   ├── exceptions.py
│   ├── scanner.py           ← legacy public API; now synced to 12 detectors
│   └── multi_engine_scanner.py  ← primary orchestrator used by CLI
├── detectors/ (12 active)
│   ├── secrets.py
│   ├── code_injection.py
│   ├── prompt_injection.py
│   ├── tool_poisoning.py
│   ├── path_traversal.py
│   ├── config_security.py
│   ├── ssrf.py
│   ├── network_binding.py
│   ├── missing_auth.py
│   ├── supply_chain.py
│   ├── weak_crypto.py       ← new v0.4.0
│   └── insecure_deserialization.py  ← new v0.4.0
├── engines/static/static_engine.py  ← only engine; runs all 12 detectors
├── models/
│   ├── vulnerability.py     ← VulnerabilityType enum with all 16 types
│   └── scan_result.py
└── reporting/generators/sarif_generator.py
```

### Known Stubs (harmless, not blocking)

These files exist but are empty `__init__.py` stubs and don't affect functionality:
- `src/mcp_sentinel/reporting/analytics/__init__.py`
- `src/mcp_sentinel/reporting/templates/__init__.py`
- `src/mcp_sentinel/utils/__init__.py`
- `src/mcp_sentinel/cli/commands/__init__.py`

---

## What's Left: v0.5.0 Roadmap

### Priority 1 — OWASP Agentic AI Top 10 Mapping

Map all 16 vulnerability types to OWASP ASI IDs (ASI01–ASI10). Adds a compliance layer on top of existing detection.

**Work needed:**
1. Research the OWASP Top 10 for Agentic Applications 2026 taxonomy
2. Add `owasp_agentic_ai_id: str` field to `Vulnerability` dataclass in `models/vulnerability.py`
3. Populate the mapping in each detector's `_create_vulnerability()` method
4. Add OWASP ASI ID to SARIF output in `sarif_generator.py` (use `tags` in `properties`)
5. Add compliance summary to terminal output (summary table at end of scan)
6. Update all 12 detector tests to assert `owasp_agentic_ai_id` is non-empty

### Priority 2 — MCP Severity Context Multiplier

MCP servers with filesystem/network access have higher blast radius. Currently all findings are scored context-free.

**Work needed:**
1. Add `mcp_context: dict` to `ScanResult` — populated during file discovery
2. Detect MCP server type from `pyproject.toml`, `package.json`, `mcp.json` declarations
3. In `multi_engine_scanner.py`: if server declares filesystem access, elevate SSRF/PathTraversal/CodeInjection findings by one severity tier
4. Add context note to terminal output showing detected MCP server capabilities

### Priority 3 — Multi-Line Taint Tracking (stdlib AST only)

Four xfail tests in `test_path_traversal.py` document the gap. Cross-line def-use chains for the highest-value patterns.

**Work needed:**
1. In `path_traversal.py`: add a `_taint_analysis_pass(content, file_path)` method using `ast.parse()`
2. Walk the AST to find: `x = request.args.get(...)` → `open(x)` and `os.path.join(base, x)` within the same function scope
3. Limit to single-file, top-level def-use (no interprocedural)
4. The 4 xfail tests should then pass — remove `@pytest.mark.xfail` when they do

### Priority 4 — MCP Sampling Mechanism Audit

Unit 42 (Palo Alto) research identified 3 exploitation vectors via MCP sampling.

**New detector:** `SamplingAuditDetector`
- File: `src/mcp_sentinel/detectors/sampling_audit.py`
- Patterns:
  - Sampling handler that executes received content without sanitization
  - Sampling callback invoking file system or network operations
  - Missing validation of sampling response before use
- Applicable to: `.py`, `.js`, `.ts`

---

## xfail Tests (Still Failing — Documented)

These 4 tests document multi-line taint tracking gaps. They will remain xfail until v0.5.0 taint analysis is implemented.

| Test | File | Why |
|---|---|---|
| `test_detect_open_with_request_param` | `test_path_traversal.py` | `x = request.args.get("f")` … `open(x)` cross-line |
| `test_detect_os_path_join_with_request` | `test_path_traversal.py` | `filename = request.args["f"]` … `os.path.join(base, filename)` |
| `test_detect_java_file_constructor` | `test_path_traversal.py` | Java taint: `String path = request.getParameter("f")` … `new File(path)` |
| `test_nodejs_file_handler` | `test_path_traversal.py` | Node.js: `const f = req.query.file` … `fs.readFileSync(f)` |

---

## Git State

- **Branch:** `claude/cleanup-codebase-footprint-ZWcWI`
- **Latest commit:** all v0.4.0 + cleanup changes committed and pushed
- **PR target:** `master` (protected — needs PR review)

## Quick Smoke Test for Next Session

```bash
# Activate venv if needed
cd /home/user/mcp-sentinel

# Verify tests pass
python -m pytest tests/ --no-cov -q
# Expected: 525 passed, 4 xfailed, 0 failed

# Verify CLI works
mcp-sentinel scan tests/fixtures/ --no-progress

# Verify version
python -c "import mcp_sentinel; print(mcp_sentinel.__version__)"
# Expected: 0.4.0

# Verify all 12 detectors registered
python -c "
from mcp_sentinel.engines.static.static_engine import StaticAnalysisEngine
from mcp_sentinel.core.config import Settings
e = StaticAnalysisEngine(Settings())
print(len(e.detectors), 'detectors')
# Expected: 12 detectors
"
```
