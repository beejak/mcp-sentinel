//! Scan command implementation

use std::path::PathBuf;
use tracing::{debug, error, info, warn};

use super::errors::{SentinelError, SentinelResult};
use super::types::{LlmProvider, OutputFormat, ScanMode, SeverityLevel};
use crate::models::config::ScanConfig;
use crate::scanner::Scanner;

#[allow(clippy::too_many_arguments)]
pub async fn execute(
    target: String,
    mode: ScanMode,
    _llm_provider: Option<LlmProvider>,
    _llm_model: Option<String>,
    _llm_api_key: Option<String>,
    output: OutputFormat,
    output_file: Option<String>,
    severity: SeverityLevel,
    fail_on: Option<SeverityLevel>,
    config_path: Option<String>,
) -> SentinelResult<()> {
    info!("📂 Scanning: {}", target);
    debug!("Mode: {:?}", mode);
    debug!("Output format: {:?}", output);

    // Load configuration from file
    let mut config = match crate::utils::config::load_scan_config(config_path.clone()) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            return Err(SentinelError::scan_error(format!(
                "Failed to load configuration: {}",
                e
            )));
        }
    };

    // Validate configuration
    if let Err(e) = crate::utils::config::validate_scan_config(&config) {
        error!("Invalid configuration: {}", e);
        return Err(SentinelError::scan_error(format!(
            "Invalid configuration: {}",
            e
        )));
    }

    // CLI arguments override config file values
    // Mode override
    config.mode = match mode {
        ScanMode::Quick => crate::models::config::ScanMode::Quick,
        ScanMode::Deep => crate::models::config::ScanMode::Deep,
    };

    // Severity override
    config.min_severity = match severity {
        SeverityLevel::Low => crate::models::vulnerability::Severity::Low,
        SeverityLevel::Medium => crate::models::vulnerability::Severity::Medium,
        SeverityLevel::High => crate::models::vulnerability::Severity::High,
        SeverityLevel::Critical => crate::models::vulnerability::Severity::Critical,
    };

    debug!("Loaded config: mode={:?}, min_severity={:?}, workers={}",
           config.mode, config.min_severity, config.parallel_workers);

    // Parse target path
    let target_path = PathBuf::from(&target);

    // Check if target exists
    if !target_path.exists() {
        error!("Target path does not exist: '{}'", target);
        return Err(SentinelError::scan_error(format!(
            "Target path does not exist: '{}'\nPlease provide a valid directory path.",
            target
        )));
    }

    if !target_path.is_dir() {
        error!("Target must be a directory: '{}'", target);
        return Err(SentinelError::scan_error(format!(
            "Target must be a directory, but '{}' is a file.\nPlease provide a directory to scan.",
            target
        )));
    }

    // Create scanner with loaded configuration
    let scanner = Scanner::new(config);

    // Run scan
    let result = match scanner.scan_directory(&target_path).await {
        Ok(r) => r,
        Err(e) => {
            error!("Scan failed for '{}': {}", target, e);
            return Err(SentinelError::scan_error(format!(
                "Failed to scan directory '{}': {}",
                target, e
            )));
        }
    };

    // Output results
    match output {
        OutputFormat::Terminal => {
            if let Err(e) = crate::output::terminal::render(&result) {
                error!("Failed to render terminal output: {}", e);
                return Err(SentinelError::scan_error(format!(
                    "Failed to render terminal output: {}",
                    e
                )));
            }
        }
        OutputFormat::Json => {
            let json = match crate::output::json::generate(&result) {
                Ok(j) => j,
                Err(e) => {
                    error!("Failed to generate JSON report: {}", e);
                    return Err(SentinelError::scan_error(format!(
                        "Failed to generate JSON report: {}",
                        e
                    )));
                }
            };

            if let Some(file_path) = &output_file {
                if let Err(e) = std::fs::write(file_path, &json) {
                    error!("Failed to write report to '{}': {}", file_path, e);
                    return Err(SentinelError::scan_error(format!(
                        "Failed to write report to '{}': {}",
                        file_path, e
                    )));
                }
                info!("Report saved to: {}", file_path);
                println!("✅ Report saved to: {}", file_path);
            } else {
                println!("{}", json);
            }
        }
        OutputFormat::Sarif => {
            let sarif = match crate::output::sarif::generate(&result) {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to generate SARIF report: {}", e);
                    return Err(SentinelError::scan_error(format!(
                        "Failed to generate SARIF report: {}",
                        e
                    )));
                }
            };

            if let Some(file_path) = &output_file {
                if let Err(e) = std::fs::write(file_path, &sarif) {
                    error!("Failed to write SARIF report to '{}': {}", file_path, e);
                    return Err(SentinelError::scan_error(format!(
                        "Failed to write SARIF report to '{}': {}",
                        file_path, e
                    )));
                }
                info!("SARIF report saved to: {}", file_path);
                println!("✅ SARIF report saved to: {}", file_path);
            } else {
                println!("{}", sarif);
            }
        }
        OutputFormat::Html | OutputFormat::Pdf => {
            error!("Output format {:?} not yet implemented", output);
            return Err(SentinelError::scan_error(format!(
                "Output format {:?} not yet implemented",
                output
            )));
        }
    }

    // Check fail_on threshold
    if let Some(threshold) = fail_on {
        let threshold_severity = match threshold {
            SeverityLevel::Low => crate::models::vulnerability::Severity::Low,
            SeverityLevel::Medium => crate::models::vulnerability::Severity::Medium,
            SeverityLevel::High => crate::models::vulnerability::Severity::High,
            SeverityLevel::Critical => crate::models::vulnerability::Severity::Critical,
        };

        if result.has_issues_at_level(threshold_severity) {
            warn!(
                "Vulnerabilities found at or above {:?} threshold: {} critical, {} high",
                threshold, result.summary.critical, result.summary.high
            );
            return Err(SentinelError::vulnerabilities_found(format!(
                "Found vulnerabilities at or above {:?} level",
                threshold
            )));
        }
    }

    // Scan completed successfully with no issues or issues below threshold
    Ok(())
}
