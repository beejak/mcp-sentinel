//! Code-level vulnerability detection

use anyhow::Result;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

use crate::models::vulnerability::{Location, Severity, Vulnerability, VulnerabilityType};

/// Command injection pattern definition
struct CommandInjectionPattern {
    name: &'static str,
    language: &'static str,
    regex: Regex,
    severity: Severity,
    description: &'static str,
}

/// Patterns for command injection vulnerabilities
static COMMAND_INJECTION_PATTERNS: Lazy<Vec<CommandInjectionPattern>> = Lazy::new(|| {
    vec![
        // Python
        CommandInjectionPattern {
            name: "os.system() usage",
            language: "Python",
            regex: Regex::new(r#"os\.system\s*\("#).unwrap(),
            severity: Severity::Critical,
            description: "Using os.system() with user input can lead to command injection",
        },
        CommandInjectionPattern {
            name: "subprocess.call() with shell=True",
            language: "Python",
            regex: Regex::new(r#"subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True"#).unwrap(),
            severity: Severity::Critical,
            description: "Using subprocess with shell=True can lead to command injection",
        },
        CommandInjectionPattern {
            name: "eval() usage",
            language: "Python",
            regex: Regex::new(r#"\beval\s*\("#).unwrap(),
            severity: Severity::High,
            description: "Using eval() with user input can lead to code injection",
        },
        CommandInjectionPattern {
            name: "exec() usage",
            language: "Python",
            regex: Regex::new(r#"\bexec\s*\("#).unwrap(),
            severity: Severity::High,
            description: "Using exec() with user input can lead to code injection",
        },
        // JavaScript/TypeScript
        CommandInjectionPattern {
            name: "child_process.exec() usage",
            language: "JavaScript/TypeScript",
            regex: Regex::new(r#"child_process\.exec\s*\("#).unwrap(),
            severity: Severity::Critical,
            description: "Using child_process.exec() can lead to command injection",
        },
        CommandInjectionPattern {
            name: "eval() usage",
            language: "JavaScript/TypeScript",
            regex: Regex::new(r#"\beval\s*\("#).unwrap(),
            severity: Severity::High,
            description: "Using eval() with user input can lead to code injection",
        },
        CommandInjectionPattern {
            name: "Function constructor",
            language: "JavaScript/TypeScript",
            regex: Regex::new(r#"new\s+Function\s*\("#).unwrap(),
            severity: Severity::High,
            description: "Using Function constructor can lead to code injection",
        },
    ]
});

/// Patterns for sensitive file access
struct SensitiveFilePattern {
    name: &'static str,
    regex: Regex,
    severity: Severity,
    description: &'static str,
}

static SENSITIVE_FILE_PATTERNS: Lazy<Vec<SensitiveFilePattern>> = Lazy::new(|| {
    vec![
        // SSH Keys
        SensitiveFilePattern {
            name: "SSH Private Key Access",
            regex: Regex::new(r#"['"](~?/?\.ssh/id_(rsa|ed25519|ecdsa|dsa))['""]#).unwrap(),
            severity: Severity::Critical,
            description: "Accessing SSH private keys without user permission",
        },
        SensitiveFilePattern {
            name: "SSH Known Hosts Access",
            regex: Regex::new(r#"['"](~?/?\.ssh/known_hosts)['""]#).unwrap(),
            severity: Severity::High,
            description: "Accessing SSH known_hosts file",
        },
        // AWS Credentials
        SensitiveFilePattern {
            name: "AWS Credentials Access",
            regex: Regex::new(r#"['"](~?/?\.aws/credentials)['""]#).unwrap(),
            severity: Severity::Critical,
            description: "Accessing AWS credentials file",
        },
        SensitiveFilePattern {
            name: "AWS Config Access",
            regex: Regex::new(r#"['"](~?/?\.aws/config)['""]#).unwrap(),
            severity: Severity::High,
            description: "Accessing AWS configuration file",
        },
        // GCP Credentials
        SensitiveFilePattern {
            name: "GCP Credentials Access",
            regex: Regex::new(r#"['"](~?/?\.config/gcloud/[^'"]*)['""]#).unwrap(),
            severity: Severity::Critical,
            description: "Accessing Google Cloud credentials",
        },
        // Environment Files
        SensitiveFilePattern {
            name: ".env File Access",
            regex: Regex::new(r#"['"]\.env(\.local|\.production)?['""]#).unwrap(),
            severity: Severity::High,
            description: "Accessing environment variable files that may contain secrets",
        },
        // Shell RC Files (can contain secrets)
        SensitiveFilePattern {
            name: "Shell RC File Access",
            regex: Regex::new(r#"['"](~?/?\.bashrc|~?/?\.zshrc|~?/?\.profile)['""]#).unwrap(),
            severity: Severity::Medium,
            description: "Accessing shell configuration files that may contain secrets",
        },
        // Browser Data
        SensitiveFilePattern {
            name: "Browser Cookie Access",
            regex: Regex::new(r#"['"](.*/(Chrome|Firefox|Safari)/.*[Cc]ookies?.*)['""]#).unwrap(),
            severity: Severity::Critical,
            description: "Accessing browser cookies without user permission",
        },
    ]
});

/// Detect command injection vulnerabilities
pub fn detect_command_injection(content: &str, file_path: &str) -> Result<Vec<Vulnerability>> {
    let mut vulnerabilities = Vec::new();
    let mut id_counter = 1;

    for (line_num, line) in content.lines().enumerate() {
        for pattern in COMMAND_INJECTION_PATTERNS.iter() {
            if pattern.regex.is_match(line) {
                let vuln = Vulnerability::new(
                    format!("CMD-{:03}", id_counter),
                    VulnerabilityType::CommandInjection,
                    pattern.severity,
                    format!("Command Injection: {}", pattern.name),
                    pattern.description.to_string(),
                )
                .with_location(Location::new(file_path).with_line(line_num + 1))
                .with_impact("Attackers can execute arbitrary system commands")
                .with_remediation(format!(
                    "Use safe alternatives:\n\
                     - Python: Use subprocess.run() with array arguments and shell=False\n\
                     - JavaScript: Use child_process.execFile() or spawn() with array arguments\n\
                     - Always validate and sanitize user input"
                ))
                .with_code_snippet(line.trim().to_string())
                .with_confidence(0.85);

                // Add evidence
                let mut evidence = HashMap::new();
                evidence.insert("language".to_string(), serde_json::json!(pattern.language));
                evidence.insert("pattern".to_string(), serde_json::json!(pattern.name));
                let vuln = vuln.with_evidence(evidence);

                vulnerabilities.push(vuln);
                id_counter += 1;
            }
        }
    }

    Ok(vulnerabilities)
}

/// Detect sensitive file access
pub fn detect_sensitive_file_access(
    content: &str,
    file_path: &str,
) -> Result<Vec<Vulnerability>> {
    let mut vulnerabilities = Vec::new();
    let mut id_counter = 1;

    for (line_num, line) in content.lines().enumerate() {
        for pattern in SENSITIVE_FILE_PATTERNS.iter() {
            if let Some(captures) = pattern.regex.captures(line) {
                let file_accessed = captures.get(1).map(|m| m.as_str()).unwrap_or("unknown");

                let vuln = Vulnerability::new(
                    format!("FILE-{:03}", id_counter),
                    VulnerabilityType::SensitiveFileAccess,
                    pattern.severity,
                    format!("Sensitive File Access: {}", pattern.name),
                    pattern.description.to_string(),
                )
                .with_location(Location::new(file_path).with_line(line_num + 1))
                .with_impact(format!(
                    "Unauthorized access to {} can expose sensitive credentials",
                    file_accessed
                ))
                .with_remediation(
                    "Request explicit user permission before accessing sensitive files.\n\
                     Use MCP prompts to ask for user consent."
                        .to_string(),
                )
                .with_code_snippet(line.trim().to_string())
                .with_confidence(0.90);

                // Add evidence
                let mut evidence = HashMap::new();
                evidence.insert(
                    "file_accessed".to_string(),
                    serde_json::json!(file_accessed),
                );
                let vuln = vuln.with_evidence(evidence);

                vulnerabilities.push(vuln);
                id_counter += 1;
            }
        }
    }

    Ok(vulnerabilities)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_command_injection_python() {
        let content = r#"
            import os
            import subprocess

            def dangerous_func(user_input):
                os.system(f"echo {user_input}")
                subprocess.call(user_input, shell=True)
                eval(user_input)
        "#;

        let vulns = detect_command_injection(content, "test.py").unwrap();
        assert!(vulns.len() >= 3);
        assert!(vulns.iter().any(|v| v.title.contains("os.system")));
        assert!(vulns.iter().any(|v| v.title.contains("shell=True")));
        assert!(vulns.iter().any(|v| v.title.contains("eval")));
    }

    #[test]
    fn test_detect_command_injection_javascript() {
        let content = r#"
            const { exec } = require('child_process');

            function dangerous(userInput) {
                exec(userInput);
                eval(userInput);
                new Function(userInput)();
            }
        "#;

        let vulns = detect_command_injection(content, "test.js").unwrap();
        assert!(vulns.len() >= 3);
    }

    #[test]
    fn test_detect_sensitive_file_access() {
        let content = r#"
            import os

            ssh_key = open("~/.ssh/id_rsa").read()
            aws_creds = open("~/.aws/credentials").read()
            env_vars = open(".env").read()
        "#;

        let vulns = detect_sensitive_file_access(content, "test.py").unwrap();
        assert!(vulns.len() >= 3);
        assert!(vulns.iter().any(|v| v.title.contains("SSH")));
        assert!(vulns.iter().any(|v| v.title.contains("AWS")));
        assert!(vulns.iter().any(|v| v.title.contains(".env")));
    }

    #[test]
    fn test_no_false_positives() {
        let content = r#"
            # Safe usage
            subprocess.run(["ls", "-la"], shell=False)
            subprocess.run(["echo", "hello"])
        "#;

        let vulns = detect_command_injection(content, "test.py").unwrap();
        // Should not detect the safe shell=False usage
        assert!(vulns.is_empty());
    }
}
