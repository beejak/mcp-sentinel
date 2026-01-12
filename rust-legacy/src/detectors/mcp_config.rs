//! MCP Configuration Security Scanner
//!
//! Detects security issues in MCP configuration files (Claude Desktop, Cline, etc.)

use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;

use crate::models::vulnerability::{Location, Severity, Vulnerability, VulnerabilityType};

/// Detect security issues in MCP configuration files
pub fn detect(content: &str, file_path: &str) -> Result<Vec<Vulnerability>> {
    let mut vulnerabilities = Vec::new();

    // Try to parse as JSON
    let config: Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => {
            // Not valid JSON, skip MCP detection
            return Ok(vulnerabilities);
        }
    };

    // Check if this looks like an MCP config
    if !is_mcp_config(&config) {
        return Ok(vulnerabilities);
    }

    // Extract mcpServers object
    if let Some(servers_obj) = config.get("mcpServers").and_then(|v| v.as_object()) {
        for (server_name, server_config) in servers_obj {
            let server_vulns = scan_server_config(server_name, server_config, file_path)?;
            vulnerabilities.extend(server_vulns);
        }
    }

    Ok(vulnerabilities)
}

/// Check if the JSON config looks like an MCP configuration
fn is_mcp_config(config: &Value) -> bool {
    // MCP configs have an "mcpServers" field
    if config.get("mcpServers").is_some() {
        return true;
    }

    // Or if it has MCP-specific fields at root level
    if config.get("command").is_some() || config.get("transport").is_some() {
        return true;
    }

    false
}

/// Scan a single MCP server configuration
fn scan_server_config(
    server_name: &str,
    config: &Value,
    file_path: &str,
) -> Result<Vec<Vulnerability>> {
    let mut vulnerabilities = Vec::new();
    let mut vuln_id_counter = 1;

    // Rule 1: Insecure HTTP Servers
    if let Some(url) = config.get("url").and_then(|v| v.as_str()) {
        if url.starts_with("http://") {
            // Exception for localhost
            if !is_localhost(url) {
                let vuln = Vulnerability::new(
                    format!("MCP-{:03}", vuln_id_counter),
                    VulnerabilityType::CrossOriginEscalation,
                    Severity::High,
                    "Insecure HTTP Protocol in MCP Server",
                    format!(
                        "MCP server '{}' is configured with insecure HTTP protocol: {}",
                        server_name, url
                    ),
                )
                .with_location(Location::new(file_path))
                .with_impact(
                    "HTTP connections can be intercepted, exposing data and credentials to attackers",
                )
                .with_remediation("Use HTTPS (https://) instead of HTTP for MCP server connections")
                .with_confidence(0.95);

                let mut evidence = HashMap::new();
                evidence.insert("server_name".to_string(), serde_json::json!(server_name));
                evidence.insert("url".to_string(), serde_json::json!(url));
                let vuln = vuln.with_evidence(evidence);

                vulnerabilities.push(vuln);
                vuln_id_counter += 1;
            }
        }

        // Rule 2: Untrusted Remote Servers
        if is_untrusted_domain(url) {
            let vuln = Vulnerability::new(
                format!("MCP-{:03}", vuln_id_counter),
                VulnerabilityType::CrossOriginEscalation,
                Severity::Medium,
                "MCP Server from Untrusted Domain",
                format!(
                    "MCP server '{}' connects to potentially untrusted domain: {}",
                    server_name, url
                ),
            )
            .with_location(Location::new(file_path))
            .with_impact("Untrusted MCP servers may expose sensitive data or execute malicious code")
            .with_remediation(
                "Verify the server source before enabling. Consider using only first-party MCP servers.",
            )
            .with_confidence(0.75);

            let mut evidence = HashMap::new();
            evidence.insert("server_name".to_string(), serde_json::json!(server_name));
            evidence.insert("url".to_string(), serde_json::json!(url));
            let vuln = vuln.with_evidence(evidence);

            vulnerabilities.push(vuln);
            vuln_id_counter += 1;
        }
    }

    // Rule 3: Overly Permissive Tool Definitions
    if let Some(tools) = config.get("tools").and_then(|v| v.as_array()) {
        for tool in tools {
            if let Some(allowed_paths) = tool.get("allowedPaths").and_then(|v| v.as_array()) {
                for path in allowed_paths {
                    if let Some(path_str) = path.as_str() {
                        if is_overly_permissive_path(path_str) {
                            let vuln = Vulnerability::new(
                                format!("MCP-{:03}", vuln_id_counter),
                                VulnerabilityType::SensitiveFileAccess,
                                Severity::Medium,
                                "Overly Permissive Tool Access",
                                format!(
                                    "MCP tool in server '{}' has overly broad file access: {}",
                                    server_name, path_str
                                ),
                            )
                            .with_location(Location::new(file_path))
                            .with_impact(
                                "Broad file access permissions may allow unintended file reads or modifications",
                            )
                            .with_remediation(
                                "Restrict tool access to specific directories needed for functionality",
                            )
                            .with_confidence(0.85);

                            let mut evidence = HashMap::new();
                            evidence.insert(
                                "server_name".to_string(),
                                serde_json::json!(server_name),
                            );
                            evidence.insert("path".to_string(), serde_json::json!(path_str));
                            let vuln = vuln.with_evidence(evidence);

                            vulnerabilities.push(vuln);
                            vuln_id_counter += 1;
                        }
                    }
                }
            }
        }
    }

    // Rule 4: Missing Server Verification (low priority)
    if config.get("url").is_some() && config.get("verifySsl").is_none() {
        if let Some(url) = config.get("url").and_then(|v| v.as_str()) {
            if url.starts_with("https://") && !is_localhost(url) {
                let vuln = Vulnerability::new(
                    format!("MCP-{:03}", vuln_id_counter),
                    VulnerabilityType::CrossOriginEscalation,
                    Severity::Low,
                    "Missing SSL Certificate Verification",
                    format!(
                        "MCP server '{}' lacks explicit SSL certificate verification configuration",
                        server_name
                    ),
                )
                .with_location(Location::new(file_path))
                .with_impact("SSL certificate verification may be disabled, allowing man-in-the-middle attacks")
                .with_remediation(
                    "Ensure SSL certificate verification is enabled for remote servers (verifySsl: true)",
                )
                .with_confidence(0.65);

                let mut evidence = HashMap::new();
                evidence.insert("server_name".to_string(), serde_json::json!(server_name));
                let vuln = vuln.with_evidence(evidence);

                vulnerabilities.push(vuln);
                vuln_id_counter += 1;
            }
        }
    }

    // Rule 5: Hardcoded Credentials (use existing secrets detector patterns)
    if let Some(env) = config.get("env").and_then(|v| v.as_object()) {
        for (key, value) in env {
            if let Some(val_str) = value.as_str() {
                if looks_like_credential(key, val_str) {
                    let vuln = Vulnerability::new(
                        format!("MCP-{:03}", vuln_id_counter),
                        VulnerabilityType::HardcodedCredentials,
                        Severity::Critical,
                        "Hardcoded Credentials in MCP Configuration",
                        format!(
                            "MCP server '{}' contains hardcoded credentials in environment variable '{}'",
                            server_name, key
                        ),
                    )
                    .with_location(Location::new(file_path))
                    .with_impact(
                        "Hardcoded credentials can be exposed through version control or file access",
                    )
                    .with_remediation(
                        "Use environment variables or secure secret management instead of hardcoding credentials",
                    )
                    .with_confidence(0.90);

                    let mut evidence = HashMap::new();
                    evidence.insert("server_name".to_string(), serde_json::json!(server_name));
                    evidence.insert("env_var".to_string(), serde_json::json!(key));
                    let vuln = vuln.with_evidence(evidence);

                    vulnerabilities.push(vuln);
                    vuln_id_counter += 1;
                }
            }
        }
    }

    // Rule 6: Executable Commands from Untrusted Locations
    if let Some(command) = config.get("command").and_then(|v| v.as_str()) {
        if is_untrusted_command_path(command) {
            let vuln = Vulnerability::new(
                format!("MCP-{:03}", vuln_id_counter),
                VulnerabilityType::CommandInjection,
                Severity::High,
                "MCP Server Executes Command from Untrusted Location",
                format!(
                    "MCP server '{}' executes command from potentially untrusted location: {}",
                    server_name, command
                ),
            )
            .with_location(Location::new(file_path))
            .with_impact("Executing commands from untrusted locations may allow arbitrary code execution")
            .with_remediation("Use absolute paths to trusted executables only (e.g., /usr/local/bin/)")
            .with_confidence(0.85);

            let mut evidence = HashMap::new();
            evidence.insert("server_name".to_string(), serde_json::json!(server_name));
            evidence.insert("command".to_string(), serde_json::json!(command));
            let vuln = vuln.with_evidence(evidence);

            vulnerabilities.push(vuln);
            vuln_id_counter += 1;
        }
    }

    Ok(vulnerabilities)
}

/// Check if URL is localhost
fn is_localhost(url: &str) -> bool {
    url.contains("localhost")
        || url.contains("127.0.0.1")
        || url.contains("[::1]")
        || url.contains("0.0.0.0")
}

/// Check if domain appears untrusted (heuristic)
fn is_untrusted_domain(url: &str) -> bool {
    // Check for suspicious TLDs or IP addresses
    let suspicious_patterns = [
        // Suspicious TLDs
        ".tk", ".ml", ".ga", ".cf", ".gq", // Free TLDs often used for malicious purposes
        // Raw IP addresses (not localhost)
        "://192.168.", "://10.", "://172.",
    ];

    for pattern in &suspicious_patterns {
        if url.contains(pattern) && !is_localhost(url) {
            return true;
        }
    }

    // Check for raw public IP addresses
    if url.contains("://") {
        let after_protocol = url.split("://").nth(1).unwrap_or("");
        let host = after_protocol.split('/').next().unwrap_or("");
        let host = host.split(':').next().unwrap_or("");

        // Simple IP detection (not localhost)
        if host.chars().filter(|c| *c == '.').count() == 3
            && host
                .chars()
                .all(|c| c.is_numeric() || c == '.')
            && !is_localhost(url)
        {
            return true;
        }
    }

    false
}

/// Check if path is overly permissive
fn is_overly_permissive_path(path: &str) -> bool {
    let dangerous_paths = [
        "*",        // Wildcard
        "/",        // Root
        "/home",    // All home directories
        "/Users",   // All user directories (macOS)
        "C:\\",     // Windows root
        "C:/",      // Windows root (alt syntax)
        "/etc",     // System configs
        "/var",     // System data
        "/root",    // Root user home
    ];

    for dangerous in &dangerous_paths {
        if path == *dangerous || path.starts_with(&format!("{}/*", dangerous)) {
            return true;
        }
    }

    false
}

/// Check if environment variable looks like a credential
fn looks_like_credential(key: &str, value: &str) -> bool {
    let key_lower = key.to_lowercase();
    let credential_keywords = [
        "key", "token", "password", "secret", "api_key", "apikey",
        "auth", "credential", "pwd", "pass",
    ];

    // Check if key name suggests it's a credential
    let key_is_credential = credential_keywords
        .iter()
        .any(|keyword| key_lower.contains(keyword));

    // Check if value looks like a credential (not a reference to env var)
    let value_not_reference = !value.starts_with('$')
        && !value.starts_with("${")
        && value.len() > 8; // Assume credentials are at least 8 chars

    key_is_credential && value_not_reference
}

/// Check if command path is from untrusted location
fn is_untrusted_command_path(command: &str) -> bool {
    // Relative paths are untrusted
    if !command.starts_with('/') && !command.starts_with("C:\\") && !command.starts_with("C:/") {
        // Check if it's a relative path (contains / or \)
        if command.contains('/') || command.contains('\\') {
            return true;
        }
    }

    // Untrusted directories
    let untrusted_dirs = [
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "~/Downloads/",
        "./",
        "../",
    ];

    for dir in &untrusted_dirs {
        if command.starts_with(dir) || command.contains(&format!("/{}", dir)) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_insecure_http() {
        let config = r#"
        {
            "mcpServers": {
                "test-server": {
                    "url": "http://example.com/mcp",
                    "transport": "stdio"
                }
            }
        }
        "#;

        let vulns = detect(config, "config.json").unwrap();
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.title.contains("Insecure HTTP")));
    }

    #[test]
    fn test_localhost_http_allowed() {
        let config = r#"
        {
            "mcpServers": {
                "local-server": {
                    "url": "http://localhost:8080/mcp",
                    "transport": "stdio"
                }
            }
        }
        "#;

        let vulns = detect(config, "config.json").unwrap();
        assert!(vulns
            .iter()
            .all(|v| !v.title.contains("Insecure HTTP")));
    }

    #[test]
    fn test_detect_hardcoded_credentials() {
        let config = r#"
        {
            "mcpServers": {
                "test-server": {
                    "command": "mcp-server",
                    "env": {
                        "API_KEY": "sk-1234567890abcdefghijklmnopqrstuvwxyz"
                    }
                }
            }
        }
        "#;

        let vulns = detect(config, "config.json").unwrap();
        assert!(vulns
            .iter()
            .any(|v| v.title.contains("Hardcoded Credentials")));
    }

    #[test]
    fn test_detect_overly_permissive_path() {
        let config = r#"
        {
            "mcpServers": {
                "test-server": {
                    "command": "mcp-server",
                    "tools": [
                        {
                            "allowedPaths": ["/", "/home", "*"]
                        }
                    ]
                }
            }
        }
        "#;

        let vulns = detect(config, "config.json").unwrap();
        assert!(vulns
            .iter()
            .any(|v| v.title.contains("Overly Permissive")));
    }

    #[test]
    fn test_detect_untrusted_command_path() {
        let config = r#"
        {
            "mcpServers": {
                "test-server": {
                    "command": "/tmp/suspicious-script.sh"
                }
            }
        }
        "#;

        let vulns = detect(config, "config.json").unwrap();
        assert!(vulns
            .iter()
            .any(|v| v.title.contains("Untrusted Location")));
    }

    #[test]
    fn test_non_mcp_json_ignored() {
        let config = r#"
        {
            "name": "my-app",
            "version": "1.0.0"
        }
        "#;

        let vulns = detect(config, "package.json").unwrap();
        assert!(vulns.is_empty());
    }

    #[test]
    fn test_is_localhost() {
        assert!(is_localhost("http://localhost:8080"));
        assert!(is_localhost("http://127.0.0.1:8080"));
        assert!(is_localhost("http://[::1]:8080"));
        assert!(!is_localhost("http://example.com"));
    }

    #[test]
    fn test_is_overly_permissive_path() {
        assert!(is_overly_permissive_path("*"));
        assert!(is_overly_permissive_path("/"));
        assert!(is_overly_permissive_path("/home"));
        assert!(is_overly_permissive_path("/Users"));
        assert!(!is_overly_permissive_path("/home/user/projects"));
    }
}
