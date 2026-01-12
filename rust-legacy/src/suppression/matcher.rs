//! Suppression Pattern Matching
//!
//! Matches vulnerabilities against suppression patterns.

use super::parser::{Suppression, SuppressionPattern};
use crate::models::Vulnerability;
use anyhow::Result;
use glob::Pattern as GlobPattern;
use regex::Regex;
use tracing::debug;

/// Pattern matcher for suppressions
pub struct SuppressionMatcher {
    /// Cache of compiled glob patterns
    glob_cache: std::collections::HashMap<String, GlobPattern>,

    /// Cache of compiled regex patterns
    regex_cache: std::collections::HashMap<String, Regex>,
}

impl SuppressionMatcher {
    /// Create a new matcher
    pub fn new() -> Self {
        Self {
            glob_cache: std::collections::HashMap::new(),
            regex_cache: std::collections::HashMap::new(),
        }
    }

    /// Check if a suppression matches a vulnerability
    ///
    /// # Arguments
    ///
    /// * `suppression` - Suppression rule to check
    /// * `vuln` - Vulnerability to match against
    ///
    /// # Returns
    ///
    /// true if all patterns in the suppression match the vulnerability
    pub fn matches(&self, suppression: &Suppression, vuln: &Vulnerability) -> Result<bool> {
        // All patterns must match (AND logic)
        for pattern in &suppression.patterns {
            if !self.matches_pattern(pattern, vuln)? {
                return Ok(false);
            }
        }

        debug!("Suppression {} matches vulnerability", suppression.id);
        Ok(true)
    }

    /// Check if a single pattern matches a vulnerability
    fn matches_pattern(&self, pattern: &SuppressionPattern, vuln: &Vulnerability) -> Result<bool> {
        match pattern {
            SuppressionPattern::Glob(glob_str) => {
                let pattern = GlobPattern::new(glob_str)?;
                Ok(pattern.matches(&vuln.location.file))
            }

            SuppressionPattern::File(file_path) => {
                Ok(vuln.location.file == *file_path
                    || vuln.location.file.ends_with(file_path))
            }

            SuppressionPattern::Line(line_number) => {
                Ok(vuln.location.line == *line_number)
            }

            SuppressionPattern::VulnType(type_str) => {
                let vuln_type_name = vuln.vuln_type.name().to_lowercase();
                let pattern_name = type_str.to_lowercase();

                Ok(vuln_type_name.contains(&pattern_name)
                    || pattern_name.contains(&vuln_type_name))
            }

            SuppressionPattern::Severity(severity_str) => {
                let vuln_severity = format!("{:?}", vuln.severity).to_lowercase();
                let pattern_severity = severity_str.to_lowercase();

                Ok(vuln_severity == pattern_severity)
            }

            SuppressionPattern::Description(regex_str) => {
                let regex = Regex::new(regex_str)?;
                Ok(regex.is_match(&vuln.description))
            }

            SuppressionPattern::VulnId(id) => {
                // Generate vulnerability ID (same as baseline system)
                let vuln_id = self.generate_vuln_id(vuln);
                Ok(vuln_id == *id)
            }
        }
    }

    /// Generate a deterministic ID for a vulnerability
    fn generate_vuln_id(&self, vuln: &Vulnerability) -> String {
        use sha2::{Digest, Sha256};

        let id_source = format!(
            "{}:{}:{}:{}",
            vuln.vuln_type.name(),
            vuln.location.file,
            vuln.location.line,
            vuln.description
        );

        format!("{:x}", Sha256::digest(id_source.as_bytes()))
    }
}

impl Default for SuppressionMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        vulnerability::{Severity, VulnerabilityLocation},
        VulnerabilityType,
    };

    fn make_test_vuln() -> Vulnerability {
        Vulnerability {
            vuln_type: VulnerabilityType::SecretsLeakage,
            severity: Severity::Critical,
            description: "API key exposed".to_string(),
            location: VulnerabilityLocation {
                file: "src/config.py".to_string(),
                line: 42,
                column: 10,
            },
            code_snippet: None,
            confidence: 0.9,
            impact: None,
            remediation: None,
        }
    }

    #[test]
    fn test_match_file_pattern() {
        let matcher = SuppressionMatcher::new();
        let vuln = make_test_vuln();

        let pattern = SuppressionPattern::File("src/config.py".to_string());
        assert!(matcher.matches_pattern(&pattern, &vuln).unwrap());

        let pattern_suffix = SuppressionPattern::File("config.py".to_string());
        assert!(matcher.matches_pattern(&pattern_suffix, &vuln).unwrap());

        let pattern_no_match = SuppressionPattern::File("other.py".to_string());
        assert!(!matcher.matches_pattern(&pattern_no_match, &vuln).unwrap());
    }

    #[test]
    fn test_match_glob_pattern() {
        let matcher = SuppressionMatcher::new();
        let vuln = make_test_vuln();

        let pattern = SuppressionPattern::Glob("src/**/*.py".to_string());
        assert!(matcher.matches_pattern(&pattern, &vuln).unwrap());

        let pattern_no_match = SuppressionPattern::Glob("tests/**/*.py".to_string());
        assert!(!matcher.matches_pattern(&pattern_no_match, &vuln).unwrap());
    }

    #[test]
    fn test_match_line_pattern() {
        let matcher = SuppressionMatcher::new();
        let vuln = make_test_vuln();

        let pattern = SuppressionPattern::Line(42);
        assert!(matcher.matches_pattern(&pattern, &vuln).unwrap());

        let pattern_no_match = SuppressionPattern::Line(100);
        assert!(!matcher.matches_pattern(&pattern_no_match, &vuln).unwrap());
    }

    #[test]
    fn test_match_vuln_type_pattern() {
        let matcher = SuppressionMatcher::new();
        let vuln = make_test_vuln();

        let pattern = SuppressionPattern::VulnType("secrets".to_string());
        assert!(matcher.matches_pattern(&pattern, &vuln).unwrap());

        let pattern_full = SuppressionPattern::VulnType("secrets_leakage".to_string());
        assert!(matcher.matches_pattern(&pattern_full, &vuln).unwrap());

        let pattern_no_match = SuppressionPattern::VulnType("command_injection".to_string());
        assert!(!matcher.matches_pattern(&pattern_no_match, &vuln).unwrap());
    }

    #[test]
    fn test_match_severity_pattern() {
        let matcher = SuppressionMatcher::new();
        let vuln = make_test_vuln();

        let pattern = SuppressionPattern::Severity("critical".to_string());
        assert!(matcher.matches_pattern(&pattern, &vuln).unwrap());

        let pattern_no_match = SuppressionPattern::Severity("low".to_string());
        assert!(!matcher.matches_pattern(&pattern_no_match, &vuln).unwrap());
    }

    #[test]
    fn test_match_description_pattern() {
        let matcher = SuppressionMatcher::new();
        let vuln = make_test_vuln();

        let pattern = SuppressionPattern::Description("API key".to_string());
        assert!(matcher.matches_pattern(&pattern, &vuln).unwrap());

        let pattern_regex = SuppressionPattern::Description(r"API\s+key".to_string());
        assert!(matcher.matches_pattern(&pattern_regex, &vuln).unwrap());

        let pattern_no_match = SuppressionPattern::Description("password".to_string());
        assert!(!matcher.matches_pattern(&pattern_no_match, &vuln).unwrap());
    }

    #[test]
    fn test_multiple_patterns_all_must_match() {
        let matcher = SuppressionMatcher::new();
        let vuln = make_test_vuln();

        let suppression = Suppression {
            id: "SUP-001".to_string(),
            reason: "Test".to_string(),
            author: "".to_string(),
            date: "".to_string(),
            expires: None,
            patterns: vec![
                SuppressionPattern::File("config.py".to_string()),
                SuppressionPattern::VulnType("secrets".to_string()),
            ],
        };

        assert!(matcher.matches(&suppression, &vuln).unwrap());

        // If one pattern doesn't match, whole suppression doesn't match
        let suppression_no_match = Suppression {
            id: "SUP-002".to_string(),
            reason: "Test".to_string(),
            author: "".to_string(),
            date: "".to_string(),
            expires: None,
            patterns: vec![
                SuppressionPattern::File("config.py".to_string()),
                SuppressionPattern::VulnType("command_injection".to_string()),
            ],
        };

        assert!(!matcher.matches(&suppression_no_match, &vuln).unwrap());
    }
}
