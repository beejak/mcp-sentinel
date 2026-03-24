# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.5.0] - 2026-03-24

Security intelligence upgrade: OWASP Agentic AI Top 10 compliance annotations, a new MCP-specific sampling detector, lightweight taint analysis in the path traversal detector, MCP-context severity calibration, and a structured compliance report.

### Added

**OWASP Agentic AI Top 10 (ASI01–ASI10) mapping (`src/mcp_sentinel/models/owasp_mapping.py`):**
- Every finding is now annotated with `owasp_asi_id` and `owasp_asi_name` automatically via `BaseDetector.detect()`
- `build_compliance_summary()` aggregates findings by ASI category for dashboards and reports
- SARIF output includes `owaspAgenticAITop10` compliance summary in run properties and `owasp_asi_id`/`owasp_asi_name` in each result's properties
- Full ASI rule set added to SARIF `tool.driver.rules`

**New detector — `MCPSamplingDetector`:**
- Detects MCP sampling (`create_message` / `createMessage` / `sampling/createMessage`) across Python, JavaScript, TypeScript
- **Prompt injection via sampling** (HIGH, CWE-77): user-controlled input concatenated or interpolated into sampling message text
- **Sensitive data in sampling** (HIGH, CWE-312): passwords, tokens, API keys, `os.environ`/`process.env` secrets sent to LLM
- **Unconstrained token limits** (LOW, CWE-400): `max_tokens`/`maxTokens` > 100 000 or absent limits
- **Generic sampling call** (MEDIUM, CWE-668): any sampling call for audit awareness
- Maps to OWASP ASI10 (Inadequate Audit and Monitoring)

**Lightweight taint analysis in `PathTraversalDetector`:**
- `_taint_python()`: stdlib `ast.NodeVisitor` def-use chains — detects `x = request.args.get(...)` → `open(x)` and `os.path.join(…, x)`
- `_taint_js()`: regex window — detects `x = req.query.y` → `path.join(…, x)` → `fs.readFile(y)` (one-step propagation)
- `_taint_java()`: regex window — detects `x = request.getParameter(…)` → `new File(…, x)`
- Resolves the 4 previously-xfailed tests; all 42 path traversal tests now pass

**VulnerabilityType enum:**
- Added `MCP_SAMPLING = "mcp_sampling"`

**MCP-specific severity calibration (`src/mcp_sentinel/engines/static/severity_calibrator.py`):**
- `SeverityCalibrator` post-scan pass elevates severity for `CODE_INJECTION`, `PATH_TRAVERSAL`, `SSRF`, `MCP_SAMPLING` when the server declares filesystem or network access
- Additional elevation for `PATH_TRAVERSAL` and `CODE_INJECTION` when sensitive tool operations (`rm`, `delete`, `shell`, `sudo`) are present
- STDIO transport findings annotated with privilege-level context note
- `MCPContextDetector` infers signals from `mcp.json`, `.mcp/config.json`, `package.json`, and `pyproject.toml`

**OWASP compliance report (`src/mcp_sentinel/reporting/generators/compliance_generator.py`):**
- `ComplianceReportGenerator.generate()` produces a structured JSON report keyed by ASI01–ASI10
- Each category entry includes `finding_count`, `max_severity`, per-severity breakdown, `has_detector` flag, and descriptive notes
- `--compliance-file PATH` CLI flag writes the report alongside any output format
- Terminal output now shows an OWASP Agentic AI Top 10 coverage table when findings exist

**`Vulnerability` model auto-annotation:**
- Added `@model_validator(mode='after')` to `Vulnerability` — `owasp_asi_id` and `owasp_asi_name` are now auto-populated at construction time, not just via `BaseDetector.detect()`. This ensures all code paths (direct construction in tests, model_copy, etc.) produce correctly annotated findings.

**New test files:**
- `tests/unit/test_mcp_sampling.py` (26 tests)
- `tests/unit/test_owasp_mapping.py` (16 tests)
- `tests/unit/test_severity_calibrator.py` (35 tests — calibration rules + context detection)
- `tests/unit/test_compliance_generator.py` (25 tests — compliance report structure and tallying)

### Changed
- `BaseDetector.detect()` now auto-annotates all findings with OWASP ASI metadata (still works as before; `model_validator` is a belt-and-suspenders addition)
- Static engine default detector list: 12 → 13 (added `MCPSamplingDetector`)
- `StaticAnalysisEngine.scan_directory()` calls `SeverityCalibrator.calibrate()` after all detectors complete
- SARIF generator: full rule catalogue (13 rules covering all `VulnerabilityType` values), OWASP ASI fields on each result
- CLI `scan` command: added `--compliance-file` option; docstring updated to 13 detectors

### Test results
- **619 passed, 0 xfailed, 0 failed** (up from 571)
- Coverage: ~87%

---

## [0.4.1] - 2026-03-24

### Fixed
- Removed all ruff lint errors (0 remaining): unused imports (`typing.Set`, `EngineType`), deprecated `typing.Dict/List/Set` → built-in `dict/list/set`, import ordering, trailing whitespace on blank lines
- Moved `logger` initialisation after all imports in `static_engine.py` (E402)

### Test results
- **525 passed, 4 xfailed, 0 failed** (unchanged)
- Coverage: ~88%

---

## [0.4.0] - 2026-03-23

Two new detectors covering cryptographic weaknesses and insecure deserialization. Both detector classes focus on patterns that are direct RCE vectors or undermine security guarantees across Python, Java, PHP, and Node.js.

### Added

**New detectors:**
- **`WeakCryptoDetector`** — Catches cryptographic weaknesses that undermine security guarantees. Complements `SecretsDetector` — finds the *use* of bad crypto, not just exposed keys. Patterns: `hashlib.md5()`/`hashlib.sha1()` in security context (HIGH), `random.random()`/`randint()`/`Math.random()` for tokens (HIGH — Mersenne Twister state is recoverable), `AES.MODE_ECB`/`AES/ECB/...` (HIGH — ECB leaks data structure), `DES.new()`/`ARC4.new()`/`Blowfish.new()` (HIGH — broken by modern hardware), hardcoded `iv = b'\x00' * 16` (HIGH — static IV breaks CBC/CTR/GCM), `pbkdf2_hmac` with `iterations` < 10 000 (MEDIUM).
- **`InsecureDeserializationDetector`** — Catches OWASP A8 — deserialization of untrusted data. All findings are direct RCE vectors. Patterns: `pickle.loads(data)` / `cPickle.loads()` (CRITICAL), `yaml.load(stream)` without `SafeLoader` (CRITICAL — `!!python/object:os.system` RCE), `marshal.loads(bytecode)` (CRITICAL), `eval(request.body)` / `eval(data)` used as parser (CRITICAL), `jsonpickle.decode(json_str)` (CRITICAL), `new ObjectInputStream(input)` / `.readObject()` (CRITICAL — Java gadget chain), `unserialize($_POST['data'])` (CRITICAL — PHP magic method chain), `vm.runInContext()` / `vm.runInNewContext()` (CRITICAL — Node.js VM sandbox escape).

**`VulnerabilityType` enum:**
- Added `WEAK_CRYPTO = "weak_crypto"`
- Added `INSECURE_DESERIALIZATION = "insecure_deserialization"`

**Registration:**
- Both new detectors registered in `detectors/__init__.py` and `static_engine.py`
- Default detector count: 10 → 12

**New test files:**
- `tests/unit/test_weak_crypto.py` (60 tests)
- `tests/unit/test_insecure_deserialization.py` (56 tests)

### Test results
- **525 passed, 4 xfailed, 0 failed** (up from 409/4/0)
- Coverage: ~88%

---

## [0.3.0] - 2026-03-23

Supply chain attack detector. Based on documented real-world incidents: the `postmark-mcp` silent BCC attack, npm packages with embedded reverse shells, and PyPI typosquatting of MCP server names.

### Added

**New detectors:**
- **`SupplyChainDetector`** — Detects malicious package patterns targeting MCP server installations. Seven pattern categories:
  - Encoded payload execution (CRITICAL): `eval(base64.b64decode(...))`, `eval(atob(...))`, `exec(compile(...))` — obfuscated code execution
  - Install-time network calls (CRITICAL): HTTP requests inside `setup.py` or npm `postinstall` — data exfiltration at install time
  - Install-time shell execution (HIGH): `cmdclass` in `setup.py`, npm `postinstall`/`prepare` hooks with shell commands
  - Covert data exfiltration (CRITICAL): Outbound HTTP calls containing `os.environ`, file reads, or `process.env`
  - Silent BCC/forward injection (HIGH): Hardcoded BCC addresses in email-sending MCP tools
  - Dependency confusion (MEDIUM): Non-standard `--extra-index-url`, `--index-url`, or `registry=` overrides
  - Known typosquatted packages (HIGH): Package names from real PyPI/npm typosquatting incidents (colourama, crossenv, etc.)

**`VulnerabilityType` enum:**
- Added `SUPPLY_CHAIN = "supply_chain"`

**Registration:**
- `SupplyChainDetector` registered in `detectors/__init__.py` and `static_engine.py`
- Default detector count: 9 → 10

**New test files:**
- `tests/unit/test_supply_chain.py` (75 tests)

### Test results
- **409 passed, 4 xfailed, 0 failed** (up from 334/4/0)
- Coverage: ~87%

---

## [0.2.0] - 2026-03-23

MCP-native attack pattern detectors. Three new detectors grounded in real CVE data and 2025–2026 MCP security research. Enhanced tool poisoning coverage to include full-schema poisoning across all schema fields.

### Added

**New detectors:**
- **`SSRFDetector`** — Server-Side Request Forgery. Detects unvalidated URL variables passed to Python HTTP clients (`requests`, `httpx`, `aiohttp`, `urllib`), JavaScript `fetch`/`axios`, Go `http.Get`/`http.NewRequest`, and Java `URL.openConnection()`. Also detects hardcoded cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`) at CRITICAL severity, and redirect/callback URL parameters (`redirect_uri`, `callback_url`, `webhook_url`). Based on the 30% SSRF exposure rate found in real-world MCP server scans.
- **`NetworkBindingDetector`** — Detects servers binding to `0.0.0.0` (all interfaces) instead of `127.0.0.1`. Covers Python Flask/uvicorn/raw socket, Express/Node.js, Go `net.Listen`/`ListenAndServe` (including the `:port` shorthand which also binds to all interfaces), Java `ServerSocket`, and config files (`.env`, YAML, TOML, ini). Root cause of 8,000+ publicly exposed MCP servers.
- **`MissingAuthDetector`** — Detects routes and endpoints without authentication. Flask/FastAPI routes without `@login_required` or `Depends(get_current_user)`, Express routes without auth middleware, routes with sensitive path segments (`/admin`, `/debug`, `/internal`, etc.), and MCP tool definitions exposing system operations (`exec`, `shell`, `run_command`). Uses ±5/3-line lookback/lookahead window for auth patterns.

**`ToolPoisoningDetector` enhancements (full-schema poisoning — v0.2):**
- Pattern 7: Suspicious tool names — `always_run_first`, `override_*`, `hijack`, `intercept_all`, `__*__` naming
- Pattern 8: Suspicious parameter names — `__instruction__`, `system_prompt`, `hidden_prompt`, `ai_directive`
- Pattern 9: Cross-tool manipulation phrases — "before calling", "always call this tool first", "global rule", "applies to all tools", "this tool takes precedence" — the tool shadowing attack vector
- Pattern 10: Sensitive path targeting — `.env`, `.ssh/`, `~/.aws/credentials`, `/etc/passwd`, `/etc/shadow`, `id_rsa`, `authorized_keys` in tool content — the exact technique used in the GitHub MCP prompt injection data heist; flagged CRITICAL
- Anomalous description length — tool descriptions >500 chars flagged as potential payload embedding (MEDIUM/LOW confidence)

**`VulnerabilityType` enum:**
- Added `SSRF = "ssrf"`
- Added `NETWORK_BINDING = "network_binding"`
- Added `MISSING_AUTH = "missing_auth"`

**Registration:**
- All three new detectors registered in `detectors/__init__.py` and `static_engine.py`
- Default detector count: 6 → 9

**New test files:**
- `tests/unit/test_ssrf_detector.py` (28 tests)
- `tests/unit/test_network_binding.py` (22 tests)
- `tests/unit/test_missing_auth.py` (20 tests)
- `tests/unit/test_tool_poisoning_enhanced.py` (26 tests)

### Changed
- `static_engine.py` docstring updated to list all 9 detectors
- `StaticAnalysisEngine.__init__` docstring: "all 8 default detectors" → "all 9 default detectors"
- `ToolPoisoningDetector` class docstring updated to list 10 patterns
- `_create_vulnerability` in `ToolPoisoningDetector`: CRITICAL CVSS bumped to 9.5 (from 9.1) to reflect sensitive path targeting severity

### Test results
- **334 passed, 4 xfailed, 0 failed** (up from 248/4/0)
- Coverage: 86.47%
- xfail tests unchanged: document multi-line taint patterns requiring semantic analysis

---

## [0.1.0] - 2026-03-23

Major codebase reduction. Removed everything that was over-engineered, stub-only, or created unnecessary attack surface for a security tool. What remains is a focused, auditable static scanner with no external binary dependencies and no network calls.

### Added
- `UNUSED_CODE.md` documenting all removed features and security rationale
- Lightweight stdlib `ast`-based `_detect_shell_true_ast()` in `CodeInjectionDetector` for multi-line `subprocess(shell=True)` detection without any external dependencies

### Removed
- **AI engine** (`engines/ai/`) — sent source code to external LLM APIs; antithetical for a security tool
- **SAST engine** (`engines/sast/`) — Semgrep/Bandit wrappers; external binary dependencies with version drift risk
- **Semantic/CFG engine** (`engines/semantic/`) — over-engineered; stdlib AST covers the critical cases
- **RAG system** (`rag/`) — ChromaDB + sentence-transformers; only served the removed AI engine
- **Remediation system** (`remediation/`) — `DiffBuilder.apply_patch()` wrote AI output directly to source files
- **`fix` CLI command** — automated writes to production code from a security scanner is too dangerous
- **API server** (`api/`) — stub FastAPI server; out of scope for a CLI scanner
- **Integrations, Monitoring, Tasks, Storage** — all empty stubs
- **XSS detector** — generic web vulnerability with low signal-to-noise for MCP servers
- **Supply chain detector** — was stub-only; rebuilt properly in v0.3
- **HTML report generator** — unnecessary dependency surface
- **`--engines` CLI flag** — no longer needed with a single engine
- **~30 pyproject.toml dependencies:** fastapi, uvicorn, sqlalchemy, alembic, asyncpg, anthropic, langchain*, openai, transformers, sentence-transformers, chromadb, boto3, redis, celery, grpcio*, strawberry-graphql, prometheus-client, opentelemetry*, structlog, sentry-sdk, jira, slack-sdk, PyGithub, tree-sitter*, libcst, semgrep, bandit, pandas, plotly, reportlab, jinja2, weasyprint, and others

### Changed
- `EngineType` enum reduced from `{STATIC, SEMANTIC, SAST, AI}` to `{STATIC}` only
- `EngineSettings` reduced to `enable_static: bool` only
- `Settings` stripped to: `environment`, `log_level`, `engines`, `max_workers`, `cache_ttl`
- `_get_default_detectors()` reduced from 8 to 6 detectors
- `multi_engine_scanner.py` simplified to single-engine orchestration
- `cli/main.py` rewritten — removed `fix` command, `--engines`, `--output html`
- `detectors/__init__.py` — exports `ConfigSecurityDetector` and `PathTraversalDetector`; removes `SupplyChainDetector`
- `reporting/generators/__init__.py` — exports `SARIFGenerator` only

### Fixed
- Tests updated to match current detector count (6, not 8)
- Multi-engine scanner progress callback assertion corrected to `EngineType.STATIC`
- Framework detection test: XSS assertion removed (XSSDetector deleted)
- Path traversal: two multi-line taint tests marked `@pytest.mark.xfail`
- Config test fully rewritten (previously imported 5 removed config classes)

### Test results
- **248 passed, 4 xfailed, 0 failed**
- xfail tests document multi-line taint patterns that require semantic analysis

---

## [v1.0.0-beta.4] - 2026-01-24

### Added
- **Advanced Logging System**:
  - Structured JSON logging support for file output.
  - Console logging with `rich` formatting and colors.
  - Log rotation (10MB max size, 5 backups).
  - CLI options `--log-level` and `--log-file`.
- **Enhanced CLI**:
  - Interactive prompts using `questionary` when required arguments are missing.
  - Improved help messages and command structure.
- **Documentation**:
  - Added `TUTORIAL.md` covering CLI and logging features.

### Changed
- Refactored `main.py` to use `setup_logging` before command execution.
- Updated `ScanResult` model to use string status instead of enum for better compatibility.

### Fixed
- Fixed `ScanStatus` import error in tests.
- Improved test coverage for CLI and logging modules.

## [v1.0.0-beta.3] - 2026-01-15

### Added
- Phase 4.3 AI Analysis Engine integration.
- Support for Claude 3.5 Sonnet.
- Cost tracking and budget management.

## [v1.0.0-beta.2] - 2026-01-10

### Added
- Phase 4.2.2 Semantic Analysis improvements.
- JavaScript multi-line comment detection.
- Python fixture detection enhancements.
