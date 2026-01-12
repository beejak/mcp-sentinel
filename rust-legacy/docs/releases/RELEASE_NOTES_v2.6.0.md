# MCP Sentinel v2.6.0 Release Notes

**Use these notes to create the GitHub Release at:**
https://github.com/beejak/MCP_Scanner/releases/new?tag=v2.6.0

---

## 🎯 Summary

Phase 2.6 brings threat intelligence integration, supply chain security, and advanced JavaScript/TypeScript vulnerability detection to MCP Sentinel. This release adds VulnerableMCP API integration, MITRE ATT&CK mapping, NVD feed integration, package confusion detection, enhanced DOM XSS coverage (5x expansion), and Node.js-specific security detectors.

**Key Highlights:**
- 🌐 **Threat Intelligence**: 3 external intelligence sources (VulnerableMCP, MITRE ATT&CK, NVD)
- 📦 **Supply Chain Security**: 11 patterns detecting malicious npm packages
- 🔍 **Enhanced XSS Detection**: Expanded from 1 to 5 DOM-based XSS patterns
- 🟢 **Node.js Security**: Context-aware weak RNG and fs path traversal detection
- ✅ **Integration Testing**: 18 new comprehensive integration tests

---

## ✨ Major Features

### 1. Threat Intelligence Integration

#### VulnerableMCP API Client (200 lines)
- **Real-time Vulnerability Database**: Query VulnerableMCP API for known vulnerabilities
- **CVE Enrichment**: Automatic CVE lookup for detected vulnerabilities
- **Exploit Tracking**: Known exploit availability and maturity assessment
- **Threat Actor Intelligence**: Track threat actors using specific techniques
- **CVSS Scoring**: Aggregate CVSS v3.1 scores from multiple sources
- **Graceful Degradation**: Scanner continues if API unavailable

**Why**: Security teams need context beyond raw findings. Threat intelligence provides CVE mappings, known exploits, and real-world incident data to prioritize remediation efforts.

#### MITRE ATT&CK Mapping (380 lines)
- **9 Vulnerability Types Mapped**: Command injection, SQL injection, XSS, path traversal, SSRF, prototype pollution, code injection, hardcoded secrets, insecure config
- **20+ Techniques Covered**: T1059 (Command Interpreter), T1190 (Exploit Public-Facing), T1189 (Drive-by), T1552 (Unsecured Credentials), and more
- **8 Tactics Addressed**: Initial Access, Execution, Persistence, Defense Evasion, Credential Access, Discovery, Collection, Command and Control
- **Local Mapping**: No external API calls (privacy-preserving)
- **Technique Descriptions**: Complete context for each ATT&CK technique

**Why**: MITRE ATT&CK is the industry standard for describing adversary behavior. Mapping vulnerabilities to ATT&CK helps security teams understand attack lifecycle and prioritize defenses.

#### NVD Feed Integration (280 lines)
- **CVE Lookup by CWE**: Query National Vulnerability Database by CWE identifier
- **CVSS v3.1 Scores**: Extract base scores, severity, attack vector, complexity
- **Real-World Incidents**: Track incidents linked to CVEs
- **Reference Analysis**: Identify exploit databases, security advisories
- **Rate Limit Handling**: 5 req/min (free) or 50 req/min (with API key)
- **Timeout Protection**: 15s timeout prevents hanging

**Why**: NVD is the authoritative source for CVE data. Integration provides standardized vulnerability scoring and real-world incident correlation.

### 2. Package Confusion Detection (400 lines, 11 patterns)

#### Malicious Install Scripts (7 patterns)
- `curl | bash` and `wget | sh` - Remote code execution in install hooks
- `eval()` in scripts - Code injection via package.json
- Netcat usage - Reverse shell establishment
- Base64 obfuscation - Hidden malicious payloads
- `chmod +x` - Executable file creation
- `rm -rf` - Destructive operations
- Suspicious lifecycle hooks - preinstall, postinstall abuse

#### Insecure Dependencies (3 patterns)
- HTTP URLs - Man-in-the-middle vulnerable dependencies
- Git URLs - Bypass npm registry security checks
- Wildcard versions - `*`, `latest` version pinning issues

#### Package Confusion Attack (1 pattern)
- Scoped package detection - Private package patterns on public registry
- Typosquatting indicators - Similar names to popular packages

**Why**: Supply chain attacks via npm packages are a critical threat to Node.js ecosystems. Malicious install scripts can compromise developer machines, steal credentials, and infiltrate CI/CD pipelines.

**5 Unit Tests**: All 11 patterns validated with comprehensive test coverage

### 3. Enhanced DOM XSS Detection (Expanded 1 → 5 patterns)

| Pattern | Severity | Detection Method | Example |
|---------|----------|------------------|---------|
| **innerHTML Assignment** | High | AST-based | `element.innerHTML = userInput` |
| **outerHTML Assignment** | High | AST-based (NEW) | `element.outerHTML = userContent` |
| **document.write()** | High | AST-based (NEW) | `document.write(userContent)` |
| **eval() Calls** | Critical | AST-based (NEW) | `eval(userCode)` |
| **Function Constructor** | Critical | AST-based (NEW) | `new Function(userCode)` |

**500% Expansion**: From 1 pattern in v2.5.0 to 5 comprehensive patterns in v2.6.0

**Why**: DOM-based XSS is harder to detect than reflected XSS. Tree-sitter AST parsing enables comprehensive detection of all DOM manipulation vectors, not just innerHTML.

### 4. Node.js-Specific Security Detection (162 lines)

#### Weak Random Number Generation (84 lines)
- **Context-Aware Detection**: `Math.random()` usage in security-sensitive code
- **Severity Adjustment**: High for tokens/passwords/keys, Medium for general use
- **Keyword Matching**: Detects "token", "password", "secret", "key", "auth", "session", "csrf"
- **Recommendations**: Suggests `crypto.randomBytes()` or `crypto.getRandomValues()`

**Example Detection:**
```javascript
// High severity - security context
const sessionToken = generateToken(Math.random());

// Medium severity - general use
const randomIndex = Math.floor(Math.random() * 10);
```

#### Path Traversal in fs Operations (78 lines)
- **10+ fs Methods Covered**: readFile, readFileSync, writeFile, writeFileSync, appendFile, appendFileSync, readdir, readdirSync, open, openSync
- **Dynamic Path Detection**: Flags variables and concatenation (not string literals)
- **Attack Prevention**: Prevents `../` directory traversal attacks
- **Severity**: High for all fs operations with user-controlled paths

**Example Detection:**
```javascript
// Detected - dynamic path
fs.readFileSync(req.query.file);  // Path traversal vulnerability

// Not flagged - string literal (auditable)
fs.readFileSync('./config.json');
```

**Why**: Node.js has specific security pitfalls (weak RNG, fs path traversal) that require specialized detection. Generic patterns miss context-aware vulnerabilities.

### 5. Comprehensive Integration Test Suite (920 lines, 18 tests)

... (content continues identical to original)