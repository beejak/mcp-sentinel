//! SARIF (Static Analysis Results Interchange Format) output generator
//!
//! Generates SARIF 2.1.0 compliant output for integration with:
//! - GitHub Code Scanning
//! - GitLab Security Dashboard
//! - SonarQube
//! - Visual Studio Code

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::models::{
    scan_result::ScanResult,
    vulnerability::{Severity, Vulnerability, VulnerabilityType},
};

const SARIF_VERSION: &str = "2.1.0";
const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const TOOL_NAME: &str = "MCP Sentinel";
const TOOL_INFO_URI: &str = "https://github.com/yourusername/MCP_Scanner";

/// Generate SARIF 2.1.0 report
pub fn generate(result: &ScanResult) -> Result<String> {
    let sarif = SarifReport {
        version: SARIF_VERSION.to_string(),
        schema: SARIF_SCHEMA.to_string(),
        runs: vec![create_run(result)],
    };

    Ok(serde_json::to_string_pretty(&sarif)?)
}

/// Create a SARIF run object from scan results
fn create_run(result: &ScanResult) -> SarifRun {
    let rules = create_rules(&result.vulnerabilities);
    let results = create_results(&result.vulnerabilities, &result.metadata.scan_target);

    SarifRun {
        tool: SarifTool {
            driver: SarifDriver {
                name: TOOL_NAME.to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                information_uri: Some(TOOL_INFO_URI.to_string()),
                rules,
            },
        },
        results,
    }
}

/// Create SARIF rules from unique vulnerability types
fn create_rules(vulnerabilities: &[Vulnerability]) -> Vec<SarifRule> {
    let mut seen_types = HashSet::new();
    let mut rules = Vec::new();

    for vuln in vulnerabilities {
        if seen_types.insert(&vuln.vuln_type) {
            rules.push(create_rule(&vuln.vuln_type, &vuln.severity));
        }
    }

    // Ensure rules are sorted for deterministic output
    rules.sort_by(|a, b| a.id.cmp(&b.id));
    rules
}

/// Create a SARIF rule from a vulnerability type
fn create_rule(vuln_type: &VulnerabilityType, severity: &Severity) -> SarifRule {
    let id = vuln_type_to_rule_id(vuln_type);
    let name = vuln_type.name();
    let (short_desc, full_desc) = get_rule_descriptions(vuln_type);
    let level = severity_to_sarif_level(severity);

    SarifRule {
        id,
        name: name.to_string(),
        short_description: SarifMessage {
            text: short_desc.to_string(),
        },
        full_description: Some(SarifMessage {
            text: full_desc.to_string(),
        }),
        default_configuration: SarifRuleConfiguration { level },
        properties: Some(SarifRuleProperties {
            tags: vec!["security".to_string(), "mcp".to_string()],
        }),
    }
}

/// Create SARIF results from vulnerabilities
fn create_results(vulnerabilities: &[Vulnerability], scan_target: &str) -> Vec<SarifResult> {
    vulnerabilities
        .iter()
        .map(|vuln| create_result(vuln, scan_target))
        .collect()
}

/// Create a SARIF result from a vulnerability
fn create_result(vuln: &Vulnerability, scan_target: &str) -> SarifResult {
    let rule_id = vuln_type_to_rule_id(&vuln.vuln_type);
    let level = severity_to_sarif_level(&vuln.severity);

    let locations = if let Some(ref loc) = vuln.location {
        let relative_path = make_relative_path(&loc.file, scan_target);

        let mut location = SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: relative_path.clone(),
                },
                region: None,
                context_region: None,
            },
        };

        // Add region if we have line information
        if let Some(line) = loc.line {
            location.physical_location.region = Some(SarifRegion {
                start_line: line,
                start_column: loc.column,
            });
        }

        // Add context snippet if available
        if let Some(ref snippet) = vuln.code_snippet {
            location.physical_location.context_region = Some(SarifContextRegion {
                snippet: SarifSnippet {
                    text: snippet.clone(),
                },
            });
        }

        vec![location]
    } else {
        vec![]
    };

    // Generate a fingerprint for deduplication
    let fingerprint = generate_fingerprint(vuln);

    // Build properties object
    let mut properties = HashMap::new();
    properties.insert("confidence".to_string(), vuln.confidence.to_string());
    if let Some(ref impact) = vuln.impact {
        properties.insert("impact".to_string(), impact.clone());
    }
    if let Some(ref remediation) = vuln.remediation {
        properties.insert("remediation".to_string(), remediation.clone());
    }

    SarifResult {
        rule_id,
        level,
        message: SarifMessage {
            text: vuln.description.clone(),
        },
        locations,
        partial_fingerprints: Some(SarifFingerprints {
            primary_location_line_hash: fingerprint,
        }),
        properties: if properties.is_empty() {
            None
        } else {
            Some(properties)
        },
    }
}

/// Convert vulnerability type to SARIF rule ID (snake_case)
fn vuln_type_to_rule_id(vuln_type: &VulnerabilityType) -> String {
    match vuln_type {
        VulnerabilityType::ToolPoisoning => "tool_poisoning",
        VulnerabilityType::PromptInjection => "prompt_injection",
        VulnerabilityType::SensitiveFileAccess => "sensitive_file_access",
        VulnerabilityType::DataExfiltration => "data_exfiltration",
        VulnerabilityType::ToxicFlow => "toxic_flow",
        VulnerabilityType::RugPull => "rug_pull",
        VulnerabilityType::ShadowTool => "shadow_tool",
        VulnerabilityType::CommandInjection => "command_injection",
        VulnerabilityType::PathTraversal => "path_traversal",
        VulnerabilityType::SqlInjection => "sql_injection",
        VulnerabilityType::UnsafeDeserialization => "unsafe_deserialization",
        VulnerabilityType::HardcodedCredentials => "hardcoded_credentials",
        VulnerabilityType::SecretsLeakage => "secrets_leakage",
        VulnerabilityType::PiiExposure => "pii_exposure",
        VulnerabilityType::CrossOriginEscalation => "cross_origin_escalation",
        VulnerabilityType::BehavioralAnomaly => "behavioral_anomaly",
        VulnerabilityType::SupplyChainAttack => "supply_chain_attack",
    }
    .to_string()
}

/// Map severity to SARIF level
fn severity_to_sarif_level(severity: &Severity) -> String {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
    .to_string()
}

/// Get rule descriptions for a vulnerability type
fn get_rule_descriptions(vuln_type: &VulnerabilityType) -> (&'static str, &'static str) {
    match vuln_type {
        VulnerabilityType::ToolPoisoning => (
            "Detects MCP tool poisoning attacks",
            "Tool poisoning occurs when malicious code manipulates MCP tool definitions to execute unintended actions."
        ),
        VulnerabilityType::PromptInjection => (
            "Detects prompt injection vulnerabilities",
            "Prompt injection allows attackers to manipulate AI behavior by injecting malicious instructions into prompts."
        ),
        VulnerabilityType::SensitiveFileAccess => (
            "Detects access to sensitive files",
            "Identifies code that accesses sensitive files like credentials, SSH keys, or configuration files."
        ),
        VulnerabilityType::CommandInjection => (
            "Detects command injection vulnerabilities",
            "Command injection occurs when untrusted input is used to construct shell commands, allowing arbitrary code execution."
        ),
        VulnerabilityType::HardcodedCredentials => (
            "Detects hardcoded credentials",
            "Hardcoded credentials in source code pose a security risk as they can be exposed through version control or code access."
        ),
        VulnerabilityType::SecretsLeakage => (
            "Detects leaked secrets",
            "Identifies API keys, tokens, passwords, and other secrets that should not be committed to source code."
        ),
        VulnerabilityType::PathTraversal => (
            "Detects path traversal vulnerabilities",
            "Path traversal allows attackers to access files outside the intended directory through manipulated file paths."
        ),
        VulnerabilityType::SqlInjection => (
            "Detects SQL injection vulnerabilities",
            "SQL injection occurs when untrusted input is used in SQL queries without proper sanitization."
        ),
        VulnerabilityType::DataExfiltration => (
            "Detects potential data exfiltration",
            "Identifies patterns that may indicate unauthorized data transmission to external systems."
        ),
        VulnerabilityType::CrossOriginEscalation => (
            "Detects cross-origin security issues",
            "Identifies when MCP servers access resources outside their intended scope or domain."
        ),
        VulnerabilityType::UnsafeDeserialization => (
            "Detects unsafe deserialization",
            "Unsafe deserialization can lead to remote code execution when untrusted data is deserialized."
        ),
        VulnerabilityType::PiiExposure => (
            "Detects PII exposure",
            "Identifies potential exposure of personally identifiable information (PII) in logs or outputs."
        ),
        VulnerabilityType::ToxicFlow => (
            "Detects toxic data flows",
            "Identifies dangerous data flows where untrusted input reaches sensitive operations."
        ),
        VulnerabilityType::RugPull => (
            "Detects MCP rug pull patterns",
            "Identifies patterns where MCP servers may suddenly change behavior or remove functionality."
        ),
        VulnerabilityType::ShadowTool => (
            "Detects shadow tool patterns",
            "Identifies hidden or obfuscated MCP tools that may have malicious intent."
        ),
        VulnerabilityType::BehavioralAnomaly => (
            "Detects behavioral anomalies",
            "Identifies unusual patterns in MCP server behavior that may indicate security issues."
        ),
        VulnerabilityType::SupplyChainAttack => (
            "Detects supply chain attack vectors",
            "Identifies potential supply chain vulnerabilities in dependencies or external resources."
        ),
    }
}

/// Make a file path relative to the scan target
fn make_relative_path(file_path: &str, scan_target: &str) -> String {
    // Remove scan target prefix if present
    if let Some(stripped) = file_path.strip_prefix(scan_target) {
        stripped.trim_start_matches('/').to_string()
    } else {
        file_path.to_string()
    }
}

/// Generate a fingerprint for vulnerability deduplication
fn generate_fingerprint(vuln: &Vulnerability) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();

    // Hash file path + line number for deduplication
    if let Some(ref loc) = vuln.location {
        loc.file.hash(&mut hasher);
        if let Some(line) = loc.line {
            line.hash(&mut hasher);
        }
    }

    // Also hash vulnerability type
    format!("{:?}", vuln.vuln_type).hash(&mut hasher);

    format!("{:x}", hasher.finish())
}

// SARIF data structures

#[derive(Debug, Serialize, Deserialize)]
struct SarifReport {
    version: String,
    #[serde(rename = "$schema")]
    schema: String,
    runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Debug, Serialize, Deserialize)]
struct SarifDriver {
    name: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    information_uri: Option<String>,
    rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SarifRule {
    id: String,
    name: String,
    short_description: SarifMessage,
    #[serde(skip_serializing_if = "Option::is_none")]
    full_description: Option<SarifMessage>,
    default_configuration: SarifRuleConfiguration,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<SarifRuleProperties>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SarifRuleConfiguration {
    level: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SarifRuleProperties {
    tags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SarifResult {
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    partial_fingerprints: Option<SarifFingerprints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize, Deserialize)]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<SarifRegion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    context_region: Option<SarifContextRegion>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SarifRegion {
    start_line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_column: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SarifContextRegion {
    snippet: SarifSnippet,
}

#[derive(Debug, Serialize, Deserialize)]
struct SarifSnippet {
    text: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SarifMessage {
    text: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SarifFingerprints {
    #[serde(rename = "primaryLocationLineHash")]
    primary_location_line_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::vulnerability::Location;

    #[test]
    fn test_vuln_type_to_rule_id() {
        assert_eq!(
            vuln_type_to_rule_id(&VulnerabilityType::CommandInjection),
            "command_injection"
        );
        assert_eq!(
            vuln_type_to_rule_id(&VulnerabilityType::SecretsLeakage),
            "secrets_leakage"
        );
    }

    #[test]
    fn test_severity_to_sarif_level() {
        assert_eq!(severity_to_sarif_level(&Severity::Critical), "error");
        assert_eq!(severity_to_sarif_level(&Severity::High), "error");
        assert_eq!(severity_to_sarif_level(&Severity::Medium), "warning");
        assert_eq!(severity_to_sarif_level(&Severity::Low), "note");
    }

    #[test]
    fn test_make_relative_path() {
        assert_eq!(
            make_relative_path("/path/to/project/src/main.rs", "/path/to/project"),
            "src/main.rs"
        );
        assert_eq!(
            make_relative_path("src/main.rs", "/path/to/project"),
            "src/main.rs"
        );
    }

    #[test]
    fn test_generate_empty_results() {
        let result = ScanResult::new("/test/path".to_string(), vec!["static".to_string()]);
        let sarif = generate(&result).unwrap();
        assert!(sarif.contains(SARIF_VERSION));
        assert!(sarif.contains(TOOL_NAME));
    }

    #[test]
    fn test_generate_with_vulnerability() {
        let mut result = ScanResult::new("/test/path".to_string(), vec!["static".to_string()]);
        let vuln = Vulnerability::new(
            "TEST-001",
            VulnerabilityType::CommandInjection,
            Severity::High,
            "Test vulnerability",
            "This is a test",
        )
        .with_location(Location::new("test.py").with_line(42));

        result.add_vulnerabilities(vec![vuln]);

        let sarif = generate(&result).unwrap();
        assert!(sarif.contains("command_injection"));
        assert!(sarif.contains("error")); // High severity maps to error
        assert!(sarif.contains("test.py"));
    }
}
