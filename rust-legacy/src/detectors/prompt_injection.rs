//! Prompt injection detection

use anyhow::Result;
use regex::Regex;
use once_cell::sync::Lazy;

use crate::models::vulnerability::{Location, Severity, Vulnerability, VulnerabilityType};

/// Prompt injection patterns
static INJECTION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r#"(?i)(you are now|act as|pretend to be)\s+\w+"#).unwrap(),
        Regex::new(r#"(?i)system\s+prompt|system\s+message"#).unwrap(),
        Regex::new(r#"(?i)role:\s*(assistant|system|user)"#).unwrap(),
        Regex::new(r#"(?i)jailbreak|dan mode|developer mode"#).unwrap(),
    ]
});

/// Detect prompt injection attempts
pub fn detect(content: &str) -> Result<Vec<Vulnerability>> {
    let mut vulnerabilities = Vec::new();
    let mut id_counter = 1;

    for (line_num, line) in content.lines().enumerate() {
        for pattern in INJECTION_PATTERNS.iter() {
            if pattern.is_match(line) {
                vulnerabilities.push(
                    Vulnerability::new(
                        format!("INJECT-{:03}", id_counter),
                        VulnerabilityType::PromptInjection,
                        Severity::High,
                        "Prompt Injection Detected",
                        "Content contains potential prompt injection patterns",
                    )
                    .with_location(Location::new("content").with_line(line_num + 1))
                    .with_impact("May manipulate LLM to bypass safety measures")
                    .with_remediation("Remove prompt manipulation instructions")
                    .with_code_snippet(line.to_string())
                    .with_confidence(0.75),
                );
                id_counter += 1;
            }
        }
    }

    Ok(vulnerabilities)
}
