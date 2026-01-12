//! Configuration Management
//!
//! Provides configuration loading with precedence: CLI > Project > User > Default

use anyhow::Result;
use crate::models::vulnerability::Severity;

/// Main configuration struct (simplified for testing)
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// Maximum severity level to ignore
    pub max_severity_to_ignore: Severity,

    /// Enable Semgrep integration
    pub enable_semgrep: bool,

    /// Enable AI analysis
    pub enable_ai_analysis: bool,

    // Additional fields can be added as needed
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_severity_to_ignore: Severity::Low,
            enable_semgrep: false,
            enable_ai_analysis: false,
        }
    }
}

impl Config {
    /// Merge configurations with precedence: CLI > Project > User > Default
    ///
    /// # Arguments
    ///
    /// * `default` - Default configuration
    /// * `project` - Optional project-level configuration
    /// * `cli` - CLI-provided overrides (highest priority)
    ///
    /// # Returns
    ///
    /// Merged configuration with proper precedence
    pub fn merge_with_precedence(
        default: Config,
        project: Option<Config>,
        cli: Config,
    ) -> Result<Config> {
        // Start with default
        let mut merged = default;

        // Apply project config if present
        if let Some(proj) = project {
            // Only override fields that differ from default
            // This is a simplified merge - in production you'd have more sophisticated logic
            merged.max_severity_to_ignore = proj.max_severity_to_ignore;
            merged.enable_semgrep = proj.enable_semgrep;
            merged.enable_ai_analysis = proj.enable_ai_analysis;
        }

        // Apply CLI overrides (highest priority)
        // CLI values always win
        merged.max_severity_to_ignore = cli.max_severity_to_ignore;
        merged.enable_semgrep = cli.enable_semgrep;
        merged.enable_ai_analysis = cli.enable_ai_analysis;

        Ok(merged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.max_severity_to_ignore, Severity::Low);
        assert!(!config.enable_semgrep);
        assert!(!config.enable_ai_analysis);
    }

    #[test]
    fn test_merge_with_precedence() {
        let default = Config {
            max_severity_to_ignore: Severity::Low,
            enable_semgrep: false,
            enable_ai_analysis: false,
        };

        let project = Config {
            max_severity_to_ignore: Severity::Medium,
            enable_semgrep: false,
            enable_ai_analysis: false,
        };

        let cli = Config {
            max_severity_to_ignore: Severity::Info,
            enable_semgrep: true,
            enable_ai_analysis: false,
        };

        let merged = Config::merge_with_precedence(default, Some(project), cli).unwrap();

        // CLI should win
        assert_eq!(merged.max_severity_to_ignore, Severity::Info);
        assert_eq!(merged.enable_semgrep, true);
    }
}
