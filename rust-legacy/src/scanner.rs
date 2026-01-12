//! Main scanner API

use anyhow::{Context, Result};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::io::IsTerminal;
use std::path::Path;
use std::time::Instant;
use tracing::{debug, error, info, warn};

use crate::models::{config::ScanConfig, scan_result::ScanResult};

/// Main scanner struct
pub struct Scanner {
    config: ScanConfig,
}

impl Scanner {
    /// Create a new scanner with the given configuration
    pub fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    /// Scan a directory
    pub async fn scan_directory(&self, path: impl AsRef<Path>) -> Result<ScanResult> {
        let path = path.as_ref();
        info!("Scanning directory: {}", path.display());

        let start = Instant::now();

        // Create result
        let mut result = ScanResult::new(
            path.to_string_lossy().to_string(),
            vec!["static".to_string()],
        );

        // Phase 1: Discover files
        debug!("Discovering files in {}...", path.display());
        let files = match crate::utils::file::discover_files(path, &self.config.exclude_patterns) {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to discover files in {}: {}", path.display(), e);
                return Err(e).context("Failed to discover files");
            }
        };
        info!("Found {} files to scan", files.len());

        if files.is_empty() {
            warn!("No scannable files found in {}. Looking for: .py, .js, .ts, .jsx, .tsx, .json, .yaml", path.display());
        }

        // Determine if we should show progress indicators
        let show_progress = self.should_show_progress(files.len());

        // Setup progress indicators if needed
        let (multi_progress, progress_bar, spinner) = if show_progress {
            let mp = MultiProgress::new();

            // Main progress bar
            let pb = mp.add(ProgressBar::new(files.len() as u64));
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{bar:40.cyan/blue}] {pos}/{len} files ({eta})")
                    .unwrap_or_else(|_| ProgressStyle::default_bar())
                    .progress_chars("=>-"),
            );

            // Spinner for current file
            let sp = mp.add(ProgressBar::new_spinner());
            sp.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .unwrap_or_else(|_| ProgressStyle::default_spinner()),
            );

            (Some(mp), Some(pb), Some(sp))
        } else {
            (None, None, None)
        };

        // Phase 2: Scan each file
        for (idx, file) in files.iter().enumerate() {
            // Update progress indicators
            if let Some(ref spinner) = spinner {
                spinner.set_message(format!("Scanning {}", file.display()));
            }

            debug!("Scanning file: {}", file.display());
            let vulns = match self.scan_file(file).await {
                Ok(v) => v,
                Err(e) => {
                    // Clear progress indicators before showing error
                    if let Some(ref pb) = progress_bar {
                        pb.finish_and_clear();
                    }
                    if let Some(ref sp) = spinner {
                        sp.finish_and_clear();
                    }
                    return Err(e);
                }
            };
            result.add_vulnerabilities(vulns);

            // Update progress bar
            if let Some(ref pb) = progress_bar {
                pb.set_position((idx + 1) as u64);
            }
        }

        // Finish progress indicators
        if let Some(ref pb) = progress_bar {
            pb.finish_and_clear();
        }
        if let Some(ref sp) = spinner {
            sp.finish_and_clear();
        }

        // Set scan duration
        let duration = start.elapsed();
        result.set_duration(duration.as_millis() as u64);

        info!(
            "Scan complete: {} issues found in {}ms",
            result.summary.total_issues, result.metadata.scan_duration_ms
        );

        Ok(result)
    }

    /// Determine if progress indicators should be displayed
    fn should_show_progress(&self, file_count: usize) -> bool {
        // Don't show for very small scans
        if file_count <= 5 {
            return false;
        }

        // Check if stdout is a TTY
        if !std::io::stdout().is_terminal() {
            return false;
        }

        // Check NO_COLOR environment variable
        if std::env::var("NO_COLOR").unwrap_or_default() == "1" {
            return false;
        }

        // Check MCP_SENTINEL_NO_PROGRESS environment variable
        if std::env::var("MCP_SENTINEL_NO_PROGRESS").unwrap_or_default() == "1" {
            return false;
        }

        // Check if running in CI environment
        if std::env::var("CI").unwrap_or_default() == "true" {
            return false;
        }

        true
    }

    /// Scan a single file
    async fn scan_file(&self, path: &Path) -> Result<Vec<crate::models::Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Read file content
        let content = match crate::utils::file::read_file(path) {
            Ok(c) => c,
            Err(e) => {
                // Common scenarios: binary files, permission denied, invalid UTF-8
                debug!("Skipping file {}: {}", path.display(), e);
                return Ok(vulnerabilities);
            }
        };

        let file_path = path.to_string_lossy().to_string();

        // Run all detectors
        debug!("Running detectors on {}", file_path);

        // 1. Secrets detection
        match crate::detectors::secrets::detect(&content, &file_path) {
            Ok(vulns) => {
                if !vulns.is_empty() {
                    debug!("Secrets detector found {} issues in {}", vulns.len(), file_path);
                }
                vulnerabilities.extend(vulns)
            },
            Err(e) => warn!("Secrets detector failed on {}: {}", file_path, e),
        }

        // 2. Command injection detection
        match crate::detectors::code_vulns::detect_command_injection(&content, &file_path) {
            Ok(vulns) => {
                if !vulns.is_empty() {
                    debug!("Command injection detector found {} issues in {}", vulns.len(), file_path);
                }
                vulnerabilities.extend(vulns)
            },
            Err(e) => warn!("Command injection detector failed on {}: {}", file_path, e),
        }

        // 3. Sensitive file access detection
        match crate::detectors::code_vulns::detect_sensitive_file_access(&content, &file_path) {
            Ok(vulns) => {
                if !vulns.is_empty() {
                    debug!("Sensitive file detector found {} issues in {}", vulns.len(), file_path);
                }
                vulnerabilities.extend(vulns)
            },
            Err(e) => warn!("Sensitive file detector failed on {}: {}", file_path, e),
        }

        // 4. Tool poisoning detection
        match crate::detectors::tool_poisoning::detect(&content) {
            Ok(vulns) => {
                if !vulns.is_empty() {
                    debug!("Tool poisoning detector found {} issues in {}", vulns.len(), file_path);
                }
                vulnerabilities.extend(vulns)
            },
            Err(e) => warn!("Tool poisoning detector failed on {}: {}", file_path, e),
        }

        // 5. Prompt injection detection
        match crate::detectors::prompt_injection::detect(&content) {
            Ok(vulns) => {
                if !vulns.is_empty() {
                    debug!("Prompt injection detector found {} issues in {}", vulns.len(), file_path);
                }
                vulnerabilities.extend(vulns)
            },
            Err(e) => warn!("Prompt injection detector failed on {}: {}", file_path, e),
        }

        // 6. MCP configuration security detection
        if Self::is_mcp_config_file(path) {
            match crate::detectors::mcp_config::detect(&content, &file_path) {
                Ok(vulns) => {
                    if !vulns.is_empty() {
                        debug!("MCP config detector found {} issues in {}", vulns.len(), file_path);
                    }
                    vulnerabilities.extend(vulns)
                },
                Err(e) => warn!("MCP config detector failed on {}: {}", file_path, e),
            }
        }

        Ok(vulnerabilities)
    }

    /// Check if file appears to be an MCP configuration file
    fn is_mcp_config_file(path: &Path) -> bool {
        let file_name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        let path_str = path.to_string_lossy();

        // Check if file name contains "mcp" AND has .json extension
        if file_name.to_lowercase().contains("mcp") && file_name.ends_with(".json") {
            return true;
        }

        // Check if it's config.json in MCP-related directories
        if file_name == "config.json" {
            if path_str.contains("/.claude/")
                || path_str.contains("/.cline/")
                || path_str.contains("/.mcp/")
                || path_str.contains("\\.claude\\")
                || path_str.contains("\\.cline\\")
                || path_str.contains("\\.mcp\\")
            {
                return true;
            }
        }

        // Check if path contains MCP-related directories
        if path_str.contains("/.claude/")
            || path_str.contains("/.cline/")
            || path_str.contains("/.mcp/")
            || path_str.contains("\\.claude\\")
            || path_str.contains("\\.cline\\")
            || path_str.contains("\\.mcp\\")
        {
            if file_name.ends_with(".json") {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scanner_creation() {
        let config = ScanConfig::default();
        let _scanner = Scanner::new(config);
    }
}
