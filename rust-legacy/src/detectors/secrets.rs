//! Secrets detection

use anyhow::Result;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

use crate::models::vulnerability::{Location, Severity, Vulnerability, VulnerabilityType};

/// Secret pattern definition
struct SecretPattern {
    name: &'static str,
    regex: Regex,
    description: &'static str,
}

/// All secret patterns we scan for
static SECRET_PATTERNS: Lazy<Vec<SecretPattern>> = Lazy::new(|| {
    vec![
        // AWS Access Keys
        SecretPattern {
            name: "AWS Access Key ID",
            regex: Regex::new(r#"(?i)(AKIA[A-Z0-9]{16})"#).unwrap(),
            description: "AWS Access Key ID detected",
        },
        SecretPattern {
            name: "AWS Secret Access Key",
            regex: Regex::new(r#"(?i)(ASIA[A-Z0-9]{16})"#).unwrap(),
            description: "AWS Session Token detected",
        },
        // OpenAI API Keys
        SecretPattern {
            name: "OpenAI API Key",
            regex: Regex::new(r#"(sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})"#).unwrap(),
            description: "OpenAI API key detected",
        },
        SecretPattern {
            name: "OpenAI API Key (Legacy)",
            regex: Regex::new(r#"(sk-[a-zA-Z0-9]{48})"#).unwrap(),
            description: "OpenAI API key (legacy format) detected",
        },
        // Anthropic API Keys
        SecretPattern {
            name: "Anthropic API Key",
            regex: Regex::new(r#"(sk-ant-[a-zA-Z0-9-]{95})"#).unwrap(),
            description: "Anthropic (Claude) API key detected",
        },
        // JWT Tokens
        SecretPattern {
            name: "JWT Token",
            regex: Regex::new(r#"(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"#).unwrap(),
            description: "JWT token detected",
        },
        // Private Keys
        SecretPattern {
            name: "RSA Private Key",
            regex: Regex::new(r#"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"#).unwrap(),
            description: "Private key detected",
        },
        // Database Connection Strings
        SecretPattern {
            name: "PostgreSQL Connection String",
            regex: Regex::new(r#"postgres://[^:]+:[^@]+@[^/]+/\S+"#).unwrap(),
            description: "PostgreSQL connection string with credentials detected",
        },
        SecretPattern {
            name: "MySQL Connection String",
            regex: Regex::new(r#"mysql://[^:]+:[^@]+@[^/]+/\S+"#).unwrap(),
            description: "MySQL connection string with credentials detected",
        },
        // GitHub Tokens
        SecretPattern {
            name: "GitHub Token",
            regex: Regex::new(r#"(ghp_[a-zA-Z0-9]{36})"#).unwrap(),
            description: "GitHub Personal Access Token detected",
        },
        SecretPattern {
            name: "GitHub OAuth Token",
            regex: Regex::new(r#"(gho_[a-zA-Z0-9]{36})"#).unwrap(),
            description: "GitHub OAuth Token detected",
        },
        // Generic API Keys (high entropy strings)
        SecretPattern {
            name: "Generic API Key",
            regex: Regex::new(r#"(?i)(api[_-]?key|apikey|api[_-]?secret)['"\s]*[:=]\s*['"]?([a-zA-Z0-9_\-]{32,})['"]?"#).unwrap(),
            description: "Generic API key detected",
        },
        // Slack Tokens
        SecretPattern {
            name: "Slack Token",
            regex: Regex::new(r#"(xox[pborsa]-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-z0-9]{32})"#).unwrap(),
            description: "Slack token detected",
        },
        // Google API Keys
        SecretPattern {
            name: "Google API Key",
            regex: Regex::new(r#"AIza[0-9A-Za-z_-]{35}"#).unwrap(),
            description: "Google API key detected",
        },
        // Generic Passwords in Code
        SecretPattern {
            name: "Hardcoded Password",
            regex: Regex::new(r#"(?i)(password|passwd|pwd)['"\s]*[:=]\s*['"]([^'"\s]{8,})['"]"#).unwrap(),
            description: "Hardcoded password detected",
        },
    ]
});

/// Detect exposed secrets in code
pub fn detect(content: &str, file_path: &str) -> Result<Vec<Vulnerability>> {
    let mut vulnerabilities = Vec::new();
    let mut id_counter = 1;

    for (line_num, line) in content.lines().enumerate() {
        for pattern in SECRET_PATTERNS.iter() {
            if let Some(captures) = pattern.regex.captures(line) {
                // Get the matched secret (first capture group or entire match)
                let secret_text = captures
                    .get(1)
                    .or_else(|| captures.get(0))
                    .map(|m| m.as_str())
                    .unwrap_or("");

                // Redact the secret in the description
                let redacted = redact_secret(secret_text);

                let vuln = Vulnerability::new(
                    format!("SEC-{:03}", id_counter),
                    VulnerabilityType::SecretsLeakage,
                    Severity::Critical,
                    format!("{} Found", pattern.name),
                    pattern.description.to_string(),
                )
                .with_location(
                    Location::new(file_path)
                        .with_line(line_num + 1)
                        .with_column(line.find(secret_text).unwrap_or(0) + 1),
                )
                .with_impact(format!(
                    "Exposed {} can be used for unauthorized access",
                    pattern.name
                ))
                .with_remediation(format!(
                    "Remove {} from source code and use environment variables or secure secret management",
                    pattern.name
                ))
                .with_code_snippet(format!("{}\n{}", line, format!("Secret: {}", redacted)))
                .with_confidence(0.95);

                // Add evidence
                let mut evidence = HashMap::new();
                evidence.insert(
                    "secret_type".to_string(),
                    serde_json::json!(pattern.name),
                );
                evidence.insert(
                    "redacted_value".to_string(),
                    serde_json::json!(redacted),
                );
                let vuln = vuln.with_evidence(evidence);

                vulnerabilities.push(vuln);
                id_counter += 1;
            }
        }
    }

    Ok(vulnerabilities)
}

/// Redact a secret for safe display
fn redact_secret(secret: &str) -> String {
    if secret.len() <= 8 {
        "*".repeat(secret.len())
    } else {
        let prefix_len = 4.min(secret.len() / 4);
        let suffix_len = 4.min(secret.len() / 4);
        let prefix = &secret[..prefix_len];
        let suffix = &secret[secret.len() - suffix_len..];
        format!("{}...{}", prefix, suffix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_aws_key() {
        let content = r#"
            AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
            AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        "#;

        let vulns = detect(content, "test.py").unwrap();
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.title.contains("AWS")));
    }

    #[test]
    fn test_detect_openai_key() {
        let content = r#"
            OPENAI_API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890"
        "#;

        let vulns = detect(content, "test.py").unwrap();
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.title.contains("OpenAI")));
    }

    #[test]
    fn test_detect_private_key() {
        let content = r#"
            -----BEGIN RSA PRIVATE KEY-----
            MIIEpAIBAAKCAQEA...
        "#;

        let vulns = detect(content, "test.py").unwrap();
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.title.contains("Private Key")));
    }

    #[test]
    fn test_redact_secret() {
        let short = redact_secret("short");
        assert!(short.contains("*"));
        assert_eq!(redact_secret("AKIAIOSFODNN7EXAMPLE"), "AKIA...MPLE");
        assert_eq!(redact_secret("verylongsecretkey12345678"), "very...5678");
    }
}

