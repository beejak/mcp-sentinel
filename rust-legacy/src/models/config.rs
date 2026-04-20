//! Configuration data model

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::vulnerability::Severity;

/// LLM provider configuration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "lowercase")]
pub enum LlmConfig {
    OpenAI {
        api_key: String,
        model: String,
    },
    Anthropic {
        api_key: String,
        model: String,
    },
    Ollama {
        base_url: String,
        model: String,
    },
}

/// Scanning configuration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Scanning mode
    pub mode: ScanMode,

    /// Minimum severity to report
    pub min_severity: Severity,

    /// LLM configuration for AI analysis
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm: Option<LlmConfig>,

    /// Enable tree-sitter parsing
    pub enable_tree_sitter: bool,

    /// Enable Semgrep analysis
    pub enable_semgrep: bool,

    /// Maximum file size to scan (in bytes)
    pub max_file_size: usize,

    /// File patterns to exclude (gitignore syntax)
    pub exclude_patterns: Vec<String>,

    /// Number of parallel workers
    pub parallel_workers: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    Quick,
    Deep,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            mode: ScanMode::Quick,
            min_severity: Severity::Low,
            llm: None,
            enable_tree_sitter: true,
            enable_semgrep: false, // External dependency, off by default
            max_file_size: 10 * 1024 * 1024, // 10MB
            exclude_patterns: vec![
                "node_modules/".to_string(),
                ".git/".to_string(),
                "target/".to_string(),
                "dist/".to_string(),
                "build/".to_string(),
                "*.min.js".to_string(),
                "*.map".to_string(),
            ],
            parallel_workers: num_cpus::get(),
        }
    }
}

/// Main application configuration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppConfig {
    pub version: String,

    /// Default LLM configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm: Option<LlmConfig>,

    /// Default scan configuration
    pub scan: ScanConfigDefaults,

    /// Proxy configuration
    pub proxy: ProxyConfig,

    /// Whitelist path
    pub whitelist_path: PathBuf,

    /// Cache directory
    pub cache_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanConfigDefaults {
    pub default_mode: ScanMode,
    pub min_severity: Severity,
    pub fail_on: Severity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub port: u16,
    pub log_traffic: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guardrails_path: Option<PathBuf>,
}

impl Default for AppConfig {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let config_dir = home.join(".mcp-sentinel");

        Self {
            version: "1.0".to_string(),
            llm: None,
            scan: ScanConfigDefaults {
                default_mode: ScanMode::Quick,
                min_severity: Severity::Medium,
                fail_on: Severity::High,
            },
            proxy: ProxyConfig {
                port: 8080,
                log_traffic: true,
                guardrails_path: Some(config_dir.join("guardrails.yaml")),
            },
            whitelist_path: config_dir.join("whitelist.json"),
            cache_path: config_dir.join("cache"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_scan_config() {
        let config = ScanConfig::default();
        assert_eq!(config.mode, ScanMode::Quick);
        assert!(config.enable_tree_sitter);
        assert!(!config.enable_semgrep);
        assert!(config.parallel_workers > 0);
    }

    #[test]
    fn test_default_app_config() {
        let config = AppConfig::default();
        assert_eq!(config.scan.default_mode, ScanMode::Quick);
        assert_eq!(config.proxy.port, 8080);
    }
}
