//! Configuration file loading utilities

use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use tracing::{debug, warn};

use crate::models::config::{AppConfig, ScanConfig};

/// Default paths for configuration files
const USER_CONFIG_PATH: &str = ".mcp-sentinel/config.yaml";
const PROJECT_CONFIG_NAME: &str = ".mcp-sentinel.yaml";

/// Load scan configuration from file or use defaults
///
/// Priority order:
/// 1. Explicit path provided via --config flag
/// 2. Project config: ./.mcp-sentinel.yaml
/// 3. User config: ~/.mcp-sentinel/config.yaml
/// 4. Built-in defaults
pub fn load_scan_config(explicit_path: Option<String>) -> Result<ScanConfig> {
    // Try explicit path first
    if let Some(path) = explicit_path {
        debug!("Loading scan config from explicit path: {}", path);
        return load_scan_config_from_file(&path);
    }

    // Try project config
    let project_config = PathBuf::from(PROJECT_CONFIG_NAME);
    if project_config.exists() {
        debug!("Loading scan config from project config: {}", PROJECT_CONFIG_NAME);
        match load_scan_config_from_file(PROJECT_CONFIG_NAME) {
            Ok(config) => return Ok(config),
            Err(e) => {
                warn!("Failed to load project config, trying user config: {}", e);
            }
        }
    }

    // Try user config
    if let Some(home) = dirs::home_dir() {
        let user_config = home.join(USER_CONFIG_PATH);
        if user_config.exists() {
            debug!("Loading scan config from user config: {:?}", user_config);
            match load_scan_config_from_file(user_config.to_str().unwrap()) {
                Ok(config) => return Ok(config),
                Err(e) => {
                    warn!("Failed to load user config, using defaults: {}", e);
                }
            }
        }
    }

    // Use defaults silently (this is expected behavior)
    debug!("No config file found, using default scan configuration");
    Ok(ScanConfig::default())
}

/// Load AppConfig from file or use defaults
///
/// Priority order:
/// 1. Explicit path provided
/// 2. User config: ~/.mcp-sentinel/config.yaml
/// 3. Built-in defaults
pub fn load_app_config(explicit_path: Option<String>) -> Result<AppConfig> {
    // Try explicit path first
    if let Some(path) = explicit_path {
        debug!("Loading app config from explicit path: {}", path);
        return load_app_config_from_file(&path)
            .with_context(|| format!("Failed to load config from '{}'", path));
    }

    // Try user config
    if let Some(home) = dirs::home_dir() {
        let user_config = home.join(USER_CONFIG_PATH);
        if user_config.exists() {
            debug!("Loading app config from user config: {:?}", user_config);
            match load_app_config_from_file(user_config.to_str().unwrap()) {
                Ok(config) => return Ok(config),
                Err(e) => {
                    warn!("Failed to load user config, using defaults: {}", e);
                }
            }
        }
    }

    // Use defaults
    debug!("No config file found, using default app configuration");
    Ok(AppConfig::default())
}

/// Save AppConfig to file
pub fn save_app_config(config: &AppConfig, explicit_path: Option<String>) -> Result<()> {
    let path = if let Some(p) = explicit_path {
        PathBuf::from(p)
    } else {
        // Default to user config path
        let home = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
        let config_path = home.join(USER_CONFIG_PATH);

        // Create parent directory if it doesn't exist
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory: {:?}", parent))?;
        }

        config_path
    };

    let yaml = serde_yaml::to_string(config)
        .with_context(|| "Failed to serialize configuration to YAML")?;

    fs::write(&path, yaml)
        .with_context(|| format!("Failed to write config file to {:?}", path))?;

    debug!("Saved app config to: {:?}", path);
    Ok(())
}

/// Load ScanConfig from a specific file
fn load_scan_config_from_file(path: &str) -> Result<ScanConfig> {
    // Read file with detailed error handling
    let contents = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            // Provide specific error message based on error kind
            let reason = match e.kind() {
                std::io::ErrorKind::NotFound => "File not found",
                std::io::ErrorKind::PermissionDenied => "Permission denied",
                std::io::ErrorKind::InvalidData => "File contains invalid UTF-8",
                _ => "I/O error",
            };
            anyhow::bail!("Failed to load config from '{}': {}", path, reason);
        }
    };

    // Handle empty config file
    if contents.trim().is_empty() {
        debug!("Config file '{}' is empty, using defaults", path);
        return Ok(ScanConfig::default());
    }

    // Try to parse as AppConfig first (which contains scan config)
    if let Ok(app_config) = serde_yaml::from_str::<AppConfig>(&contents) {
        // Convert AppConfig scan defaults to ScanConfig
        let mut scan_config = ScanConfig::default();
        scan_config.mode = app_config.scan.default_mode;
        scan_config.min_severity = app_config.scan.min_severity;
        return Ok(scan_config);
    }

    // Fall back to parsing as ScanConfig directly
    match serde_yaml::from_str::<ScanConfig>(&contents) {
        Ok(config) => Ok(config),
        Err(e) => {
            // Extract line number from serde_yaml error if available
            let error_msg = format!("{}", e);
            let line_info = if error_msg.contains("line") {
                error_msg.clone()
            } else {
                format!("Invalid YAML syntax: {}", error_msg)
            };
            anyhow::bail!("Failed to load config from '{}': {}", path, line_info);
        }
    }
}

/// Load AppConfig from a specific file
fn load_app_config_from_file(path: &str) -> Result<AppConfig> {
    // Read file with detailed error handling
    let contents = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            // Provide specific error message based on error kind
            let reason = match e.kind() {
                std::io::ErrorKind::NotFound => "File not found",
                std::io::ErrorKind::PermissionDenied => "Permission denied",
                std::io::ErrorKind::InvalidData => "File contains invalid UTF-8",
                _ => "I/O error",
            };
            anyhow::bail!("Failed to load config from '{}': {}", path, reason);
        }
    };

    // Handle empty config file
    if contents.trim().is_empty() {
        debug!("Config file '{}' is empty, using defaults", path);
        return Ok(AppConfig::default());
    }

    // Parse YAML with detailed error reporting
    match serde_yaml::from_str::<AppConfig>(&contents) {
        Ok(config) => Ok(config),
        Err(e) => {
            // Extract line number from serde_yaml error if available
            let error_msg = format!("{}", e);
            let line_info = if error_msg.contains("line") {
                error_msg.clone()
            } else {
                format!("Invalid YAML syntax: {}", error_msg)
            };
            anyhow::bail!("Failed to load config from '{}': {}", path, line_info);
        }
    }
}

/// Validate ScanConfig values
pub fn validate_scan_config(config: &ScanConfig) -> Result<()> {
    // Validate max_file_size
    if config.max_file_size == 0 {
        anyhow::bail!(
            "Invalid configuration value for 'max_file_size': must be greater than 0"
        );
    }

    // Validate parallel_workers
    if config.parallel_workers == 0 {
        anyhow::bail!(
            "Invalid configuration value for 'parallel_workers': must be at least 1"
        );
    }

    // Warn about potentially invalid exclude patterns but don't fail
    for (idx, pattern) in config.exclude_patterns.iter().enumerate() {
        if pattern.is_empty() {
            warn!(
                "Invalid configuration value for 'exclude_patterns[{}]': pattern is empty",
                idx
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_load_default_scan_config() {
        let config = load_scan_config(None).unwrap();
        assert_eq!(config.mode, crate::models::config::ScanMode::Quick);
    }

    #[test]
    fn test_load_scan_config_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test_config.yaml");

        let yaml_content = r#"
mode: deep
min_severity: high
enable_tree_sitter: true
enable_semgrep: false
max_file_size: 5242880
exclude_patterns:
  - "node_modules/"
  - ".git/"
parallel_workers: 4
"#;

        fs::write(&config_path, yaml_content).unwrap();

        let config = load_scan_config_from_file(config_path.to_str().unwrap()).unwrap();
        assert_eq!(config.mode, crate::models::config::ScanMode::Deep);
        assert_eq!(config.parallel_workers, 4);
    }

    #[test]
    fn test_validate_scan_config() {
        let mut config = ScanConfig::default();
        assert!(validate_scan_config(&config).is_ok());

        config.max_file_size = 0;
        assert!(validate_scan_config(&config).is_err());

        config.max_file_size = 1024;
        config.parallel_workers = 0;
        assert!(validate_scan_config(&config).is_err());
    }

    #[test]
    fn test_save_and_load_app_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("app_config.yaml");

        let config = AppConfig::default();
        save_app_config(&config, Some(config_path.to_str().unwrap().to_string())).unwrap();

        let loaded_config = load_app_config_from_file(config_path.to_str().unwrap()).unwrap();
        assert_eq!(loaded_config.version, config.version);
    }
}
