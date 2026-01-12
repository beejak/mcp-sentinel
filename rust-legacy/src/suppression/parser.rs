//! Suppression Configuration Parser
//!
//! Parses YAML suppression configuration files.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tracing::debug;

/// Suppression configuration file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionConfig {
    /// Configuration version
    pub version: String,

    /// List of suppressions
    pub suppressions: Vec<Suppression>,
}

/// Individual suppression rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suppression {
    /// Unique suppression ID
    pub id: String,

    /// Human-readable reason for suppression
    pub reason: String,

    /// Author email or username
    #[serde(default)]
    pub author: String,

    /// Date created (ISO 8601)
    #[serde(default)]
    pub date: String,

    /// Optional expiration date (ISO 8601)
    #[serde(default)]
    pub expires: Option<String>,

    /// List of patterns to match
    pub patterns: Vec<SuppressionPattern>,
}

impl Suppression {
    /// Check if this suppression has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_str) = &self.expires {
            if let Ok(expires) = DateTime::parse_from_rfc3339(expires_str) {
                let now = Utc::now();
                return expires.with_timezone(&Utc) < now;
            }
        }
        false
    }

    /// Validate the suppression
    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            anyhow::bail!("Suppression ID cannot be empty");
        }

        if self.reason.is_empty() {
            anyhow::bail!("Suppression reason cannot be empty (ID: {})", self.id);
        }

        if self.patterns.is_empty() {
            anyhow::bail!("Suppression must have at least one pattern (ID: {})", self.id);
        }

        // Validate expiration date format
        if let Some(expires) = &self.expires {
            DateTime::parse_from_rfc3339(expires).context(format!(
                "Invalid expiration date format in suppression {}: {}",
                self.id, expires
            ))?;
        }

        Ok(())
    }
}

/// Pattern matching type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
#[serde(rename_all = "snake_case")]
pub enum SuppressionPattern {
    /// Match by file path (glob pattern)
    Glob(String),

    /// Match by exact file path
    File(String),

    /// Match by line number in file
    Line(usize),

    /// Match by vulnerability type
    VulnType(String),

    /// Match by severity
    Severity(String),

    /// Match by description (regex)
    Description(String),

    /// Match by vulnerability ID (hash)
    VulnId(String),
}

/// Load suppression configuration from file
pub fn load_suppression_config<P: AsRef<Path>>(path: P) -> Result<SuppressionConfig> {
    let path = path.as_ref();

    let content = fs::read_to_string(path).context(format!(
        "Failed to read suppression config: {}",
        path.display()
    ))?;

    let config: SuppressionConfig = serde_yaml::from_str(&content).context(format!(
        "Failed to parse suppression config: {}",
        path.display()
    ))?;

    // Validate all suppressions
    for suppression in &config.suppressions {
        suppression.validate().context(format!(
            "Invalid suppression in config: {}",
            path.display()
        ))?;
    }

    debug!(
        "Loaded {} suppressions from {}",
        config.suppressions.len(),
        path.display()
    );

    Ok(config)
}

/// Save suppression configuration to file
pub fn save_suppression_config<P: AsRef<Path>>(
    config: &SuppressionConfig,
    path: P,
) -> Result<()> {
    let yaml = serde_yaml::to_string(config).context("Failed to serialize suppression config")?;

    fs::write(path.as_ref(), yaml).context(format!(
        "Failed to write suppression config: {}",
        path.as_ref().display()
    ))?;

    debug!(
        "Saved {} suppressions to {}",
        config.suppressions.len(),
        path.as_ref().display()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suppression_validation() {
        let valid = Suppression {
            id: "SUP-001".to_string(),
            reason: "Test suppression".to_string(),
            author: "test@example.com".to_string(),
            date: "2025-01-15".to_string(),
            expires: None,
            patterns: vec![SuppressionPattern::VulnType("secrets".to_string())],
        };

        assert!(valid.validate().is_ok());

        let invalid_empty_id = Suppression {
            id: "".to_string(),
            reason: "Test".to_string(),
            author: "".to_string(),
            date: "".to_string(),
            expires: None,
            patterns: vec![SuppressionPattern::VulnType("secrets".to_string())],
        };

        assert!(invalid_empty_id.validate().is_err());

        let invalid_no_patterns = Suppression {
            id: "SUP-001".to_string(),
            reason: "Test".to_string(),
            author: "".to_string(),
            date: "".to_string(),
            expires: None,
            patterns: vec![],
        };

        assert!(invalid_no_patterns.validate().is_err());
    }

    #[test]
    fn test_suppression_expiration() {
        // Expired suppression
        let expired = Suppression {
            id: "SUP-001".to_string(),
            reason: "Test".to_string(),
            author: "".to_string(),
            date: "".to_string(),
            expires: Some("2020-01-01T00:00:00Z".to_string()),
            patterns: vec![],
        };

        assert!(expired.is_expired());

        // Not expired
        let not_expired = Suppression {
            id: "SUP-002".to_string(),
            reason: "Test".to_string(),
            author: "".to_string(),
            date: "".to_string(),
            expires: Some("2030-01-01T00:00:00Z".to_string()),
            patterns: vec![],
        };

        assert!(!not_expired.is_expired());

        // No expiration
        let no_expiration = Suppression {
            id: "SUP-003".to_string(),
            reason: "Test".to_string(),
            author: "".to_string(),
            date: "".to_string(),
            expires: None,
            patterns: vec![],
        };

        assert!(!no_expiration.is_expired());
    }

    #[test]
    fn test_pattern_deserialization() {
        let yaml = r#"
version: "1.0"
suppressions:
  - id: "SUP-001"
    reason: "Test"
    patterns:
      - type: "glob"
        value: "tests/**/*.py"
      - type: "vuln_type"
        value: "secrets"
"#;

        let config: SuppressionConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.suppressions.len(), 1);
        assert_eq!(config.suppressions[0].patterns.len(), 2);
    }
}
