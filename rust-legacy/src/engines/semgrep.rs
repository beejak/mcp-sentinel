//! Semgrep Integration Engine - Industry-Standard SAST with 1000+ Rules
//!
//! ## Phase 2.5 - Advanced Analysis
//!
//! This module integrates with Semgrep (https://semgrep.dev), an open-source
//! static analysis tool with 1000+ community rules covering:
//! - Security vulnerabilities (OWASP Top 10)
//! - Code quality issues
//! - Best practice violations
//! - Framework-specific patterns (Django, Flask, Express, React, etc.)
//!
//! ## Why Semgrep?
//!
//! **Complementary to Our Detection**:
//! - **Breadth**: 1000+ rules vs our focused MCP security rules
//! - **Community**: Constantly updated with new vulnerability patterns
//! - **Language Coverage**: 30+ languages with deep framework support
//! - **Industry Standard**: Used by Google, Snowflake, Netflix, Slack
//!
//! **What We Add**:
//! - MCP-specific security patterns (tool poisoning, prompt injection)
//! - AI-powered semantic analysis
//! - Runtime monitoring (Phase 3)
//! - Custom rule filtering for MCP relevance
//!
//! ## Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────┐
//! │        Semgrep Integration Flow            │
//! ├────────────────────────────────────────────┤
//! │                                            │
//! │  1. Check Semgrep Installed               │
//! │  2. Execute: semgrep --json               │
//! │  3. Parse JSON Output                      │
//! │  4. Filter MCP-Relevant Rules             │
//! │  5. Convert to Our Vulnerability Format   │
//! │  6. Merge with Other Detectors            │
//! │                                            │
//! └────────────────────────────────────────────┘
//! ```
//!
//! ## Example Usage
//!
//! ```no_run
//! use mcp_sentinel::engines::semgrep::SemgrepEngine;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let engine = SemgrepEngine::new()?;
//!
//! // Check if Semgrep is available
//! if !engine.is_available()? {
//!     println!("Semgrep not installed - skipping Semgrep analysis");
//!     return Ok(());
//! }
//!
//! // Scan a directory
//! let vulnerabilities = engine.scan_directory("/path/to/mcp-server").await?;
//! println!("Found {} issues via Semgrep", vulnerabilities.len());
//! # Ok(())
//! # }
//! ```

use crate::models::{
    location::Location,
    vulnerability::{Severity, Vulnerability, VulnerabilityType},
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::process::Command as AsyncCommand;
use tracing::{debug, info, warn};

/// Semgrep integration engine.
///
/// ## Why external process?
///
/// Semgrep is a Python tool distributed via pip/homebrew. Running as
/// external process allows:
/// - No Python FFI complexity
/// - User controls Semgrep version
/// - Easy updates (pip install --upgrade semgrep)
/// - Standard JSON communication
pub struct SemgrepEngine {
    /// Path to semgrep binary (auto-detected or user-specified)
    semgrep_path: PathBuf,

    /// Rule filtering config
    filter_config: RuleFilterConfig,
}

/// Configuration for filtering Semgrep rules.
///
/// ## Why filtering?
///
/// Semgrep has 1000+ rules. Not all are relevant to MCP servers:
/// - Focus on security rules (not style/correctness)
/// - Prioritize injection, auth, crypto, secrets
/// - Reduce noise for faster scans
#[derive(Debug, Clone)]
pub struct RuleFilterConfig {
    /// Only include security rules (skip style/correctness)
    pub security_only: bool,

    /// Minimum severity to include
    pub min_severity: SemgrepSeverity,

    /// Specific rule IDs to include (empty = all)
    pub include_rules: Vec<String>,

    /// Rule IDs to exclude
    pub exclude_rules: Vec<String>,

    /// Only include rules matching these categories
    pub include_categories: Vec<String>,
}

impl Default for RuleFilterConfig {
    fn default() -> Self {
        Self {
            security_only: true,
            min_severity: SemgrepSeverity::Warning,
            include_rules: Vec::new(),
            exclude_rules: Vec::new(),
            include_categories: vec![
                "security".to_string(),
                "injection".to_string(),
                "crypto".to_string(),
                "secrets".to_string(),
            ],
        }
    }
}

impl SemgrepEngine {
    /// Create a new Semgrep engine.
    ///
    /// ## Auto-detection
    ///
    /// Searches for `semgrep` in PATH. If not found, returns error
    /// with installation instructions.
    pub fn new() -> Result<Self> {
        Self::with_config(RuleFilterConfig::default())
    }

    /// Create engine with custom filter configuration.
    pub fn with_config(filter_config: RuleFilterConfig) -> Result<Self> {
        info!("Initializing Semgrep integration engine");
        let semgrep_path = Self::find_semgrep_binary()?;
        info!("Semgrep binary found at: {}", semgrep_path.display());
        debug!("Filter config: security_only={}, min_severity={:?}",
            filter_config.security_only, filter_config.min_severity);

        Ok(Self {
            semgrep_path,
            filter_config,
        })
    }

    /// Check if Semgrep is available on the system.
    ///
    /// ## Why this matters
    ///
    /// Semgrep is optional. We gracefully degrade if not installed:
    /// - Log warning
    /// - Continue with other detectors
    /// - Don't block scanning
    pub fn is_available(&self) -> Result<bool> {
        debug!("Checking if Semgrep is available");
        let output = Command::new(&self.semgrep_path)
            .arg("--version")
            .output();

        match output {
            Ok(output) if output.status.success() => {
                let version = String::from_utf8_lossy(&output.stdout);
                info!("Semgrep is available: {}", version.trim());
                Ok(true)
            },
            _ => {
                warn!("Semgrep not available - skipping Semgrep analysis");
                Ok(false)
            },
        }
    }

    /// Get Semgrep version string.
    pub fn version(&self) -> Result<String> {
        let output = Command::new(&self.semgrep_path)
            .arg("--version")
            .output()
            .context("Failed to execute semgrep --version")?;

        if !output.status.success() {
            anyhow::bail!("Semgrep --version failed");
        }

        let version = String::from_utf8_lossy(&output.stdout);
        Ok(version.trim().to_string())
    }

    /// Scan a directory with Semgrep.
    ///
    /// ## Execution Strategy
    ///
    /// 1. Run: `semgrep --config=auto --json <directory>`
    /// 2. Parse JSON output
    /// 3. Filter rules based on config
    /// 4. Convert to our vulnerability format
    ///
    /// ## Performance
    ///
    /// Semgrep is fast but not instant:
    /// - ~1-5 seconds for small projects (100 files)
    /// - ~10-30 seconds for medium projects (1000 files)
    /// - Runs in parallel with our other detectors
    pub async fn scan_directory(&self, directory: impl AsRef<Path>) -> Result<Vec<Vulnerability>> {
        let directory = directory.as_ref();
        info!("Running Semgrep scan on directory: {}", directory.display());
        debug!("Semgrep command: semgrep --config=auto --json --quiet {:?}", directory);
        let start = std::time::Instant::now();

        // Build semgrep command
        let mut cmd = AsyncCommand::new(&self.semgrep_path);
        cmd.arg("--config=auto")  // Use Semgrep registry rules
            .arg("--json")        // JSON output for parsing
            .arg("--quiet")       // Suppress progress output
            .arg(directory);

        // Execute
        let output = cmd
            .output()
            .await
            .context("Failed to execute semgrep")?;

        // Parse output (Semgrep returns 0 even with findings)
        let stdout = String::from_utf8_lossy(&output.stdout);
        let semgrep_output: SemgrepOutput = serde_json::from_str(&stdout)
            .context("Failed to parse semgrep JSON output")?;

        debug!("Semgrep raw findings: {} results, {} errors",
            semgrep_output.results.len(), semgrep_output.errors.len());

        // Filter and convert results
        let vulnerabilities = self.convert_results(&semgrep_output)?;

        info!(
            "Semgrep scan completed in {:?}, found {} vulnerabilities (filtered from {} raw findings)",
            start.elapsed(),
            vulnerabilities.len(),
            semgrep_output.results.len()
        );

        Ok(vulnerabilities)
    }

    /// Scan specific files with Semgrep.
    ///
    /// ## Use case
    ///
    /// Diff-aware scanning: only scan changed files for faster feedback.
    pub async fn scan_files(&self, files: &[PathBuf]) -> Result<Vec<Vulnerability>> {
        if files.is_empty() {
            return Ok(Vec::new());
        }

        let mut cmd = AsyncCommand::new(&self.semgrep_path);
        cmd.arg("--config=auto")
            .arg("--json")
            .arg("--quiet");

        // Add each file as argument
        for file in files {
            cmd.arg(file);
        }

        let output = cmd
            .output()
            .await
            .context("Failed to execute semgrep")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let semgrep_output: SemgrepOutput = serde_json::from_str(&stdout)
            .context("Failed to parse semgrep JSON output")?;

        let vulnerabilities = self.convert_results(&semgrep_output)?;

        Ok(vulnerabilities)
    }

    /// Convert Semgrep results to our vulnerability format.
    ///
    /// ## Filtering Logic
    ///
    /// 1. Check severity threshold
    /// 2. Check rule categories (security vs style)
    /// 3. Apply include/exclude lists
    /// 4. Convert to our format with enhanced metadata
    fn convert_results(&self, output: &SemgrepOutput) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        for result in &output.results {
            // Apply filters
            if !self.should_include_result(result) {
                continue;
            }

            // Convert to our format
            let vuln = self.convert_semgrep_result(result)?;
            vulnerabilities.push(vuln);
        }

        Ok(vulnerabilities)
    }

    /// Check if a Semgrep result should be included.
    fn should_include_result(&self, result: &SemgrepResult) -> bool {
        // Severity filter
        let severity_level = match &result.extra.severity {
            Some(sev) => sev,
            None => &SemgrepSeverity::Info,
        };

        if severity_level < &self.filter_config.min_severity {
            return false;
        }

        // Security-only filter
        if self.filter_config.security_only {
            if let Some(categories) = &result.extra.metadata.category {
                if !categories.contains(&"security".to_string()) {
                    return false;
                }
            }
        }

        // Include list (if specified)
        if !self.filter_config.include_rules.is_empty() {
            if !self.filter_config.include_rules.contains(&result.check_id) {
                return false;
            }
        }

        // Exclude list
        if self.filter_config.exclude_rules.contains(&result.check_id) {
            return false;
        }

        true
    }

    /// Convert a single Semgrep result to our vulnerability format.
    fn convert_semgrep_result(&self, result: &SemgrepResult) -> Result<Vulnerability> {
        // Map Semgrep severity to our severity
        let severity = self.map_severity(&result.extra.severity);

        // Map Semgrep check_id to our vulnerability type
        let vuln_type = self.map_vulnerability_type(&result.check_id);

        // Extract location
        let location = Location {
            file: result.path.clone(),
            line: Some(result.start.line),
            column: Some(result.start.col),
        };

        // Build code snippet (Semgrep provides full match text)
        let code_snippet = if !result.extra.lines.is_empty() {
            Some(result.extra.lines.clone())
        } else {
            None
        };

        // Build vulnerability
        let vuln = Vulnerability {
            id: format!("SEMGREP-{}", result.check_id),
            title: result.extra.message.clone(),
            description: format!(
                "{}\n\nDetected by Semgrep rule: {}",
                result.extra.message, result.check_id
            ),
            severity,
            vuln_type,
            location: Some(location),
            code_snippet,
            impact: result.extra.metadata.impact.clone(),
            remediation: result.extra.metadata.fix.clone(),
            confidence: self.map_confidence(&result.extra.metadata.confidence),
            evidence: Some(format!("Semgrep rule: {}", result.check_id)),
        };

        Ok(vuln)
    }

    /// Map Semgrep severity to our severity.
    fn map_severity(&self, semgrep_severity: &Option<SemgrepSeverity>) -> Severity {
        match semgrep_severity {
            Some(SemgrepSeverity::Error) => Severity::Critical,
            Some(SemgrepSeverity::Warning) => Severity::High,
            Some(SemgrepSeverity::Info) => Severity::Medium,
            None => Severity::Low,
        }
    }

    /// Map Semgrep check_id to our vulnerability type.
    ///
    /// ## Mapping Strategy
    ///
    /// Semgrep rule IDs often contain vulnerability type:
    /// - "python.lang.security.injection.sql" → SqlInjection
    /// - "javascript.express.security.xss" → XssVulnerability
    /// - "generic.secrets.api-key" → SecretExposure
    fn map_vulnerability_type(&self, check_id: &str) -> VulnerabilityType {
        let id_lower = check_id.to_lowercase();

        if id_lower.contains("sql") || id_lower.contains("injection.sql") {
            VulnerabilityType::SqlInjection
        } else if id_lower.contains("command") || id_lower.contains("injection.command") {
            VulnerabilityType::CommandInjection
        } else if id_lower.contains("xss") || id_lower.contains("cross-site") {
            VulnerabilityType::XssVulnerability
        } else if id_lower.contains("path-traversal") || id_lower.contains("directory-traversal") {
            VulnerabilityType::PathTraversal
        } else if id_lower.contains("deserial") {
            VulnerabilityType::UnsafeDeserialization
        } else if id_lower.contains("secret") || id_lower.contains("hardcoded") || id_lower.contains("api-key") {
            VulnerabilityType::HardcodedCredentials
        } else if id_lower.contains("crypto") || id_lower.contains("weak-hash") {
            VulnerabilityType::SecretsLeakage
        } else {
            VulnerabilityType::BehavioralAnomaly  // Generic catch-all
        }
    }

    /// Map Semgrep confidence to our confidence score.
    fn map_confidence(&self, confidence: &Option<String>) -> f32 {
        match confidence.as_deref() {
            Some("HIGH") => 0.90,
            Some("MEDIUM") => 0.75,
            Some("LOW") => 0.60,
            _ => 0.70,  // Default
        }
    }

    /// Find Semgrep binary in PATH.
    fn find_semgrep_binary() -> Result<PathBuf> {
        // Try common locations
        let candidates = vec![
            "semgrep",                    // In PATH
            "/usr/local/bin/semgrep",     // Homebrew on macOS
            "/usr/bin/semgrep",           // Linux system install
            "/opt/homebrew/bin/semgrep",  // Homebrew on Apple Silicon
        ];

        for candidate in candidates {
            if let Ok(output) = Command::new(candidate).arg("--version").output() {
                if output.status.success() {
                    return Ok(PathBuf::from(candidate));
                }
            }
        }

        anyhow::bail!(
            "Semgrep not found. Install with: pip install semgrep\n\
             Or visit: https://semgrep.dev/docs/getting-started/"
        )
    }
}

//
// Semgrep JSON Output Structures
//

#[derive(Debug, Deserialize, Serialize)]
struct SemgrepOutput {
    results: Vec<SemgrepResult>,
    errors: Vec<SemgrepError>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SemgrepResult {
    check_id: String,
    path: String,
    start: SemgrepPosition,
    end: SemgrepPosition,
    extra: SemgrepExtra,
}

#[derive(Debug, Deserialize, Serialize)]
struct SemgrepPosition {
    line: usize,
    col: usize,
}

#[derive(Debug, Deserialize, Serialize)]
struct SemgrepExtra {
    message: String,
    severity: Option<SemgrepSeverity>,
    metadata: SemgrepMetadata,
    lines: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, PartialOrd, Eq, Ord)]
#[serde(rename_all = "UPPERCASE")]
enum SemgrepSeverity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Deserialize, Serialize)]
struct SemgrepMetadata {
    #[serde(default)]
    category: Option<Vec<String>>,

    #[serde(default)]
    confidence: Option<String>,

    #[serde(default)]
    impact: Option<String>,

    #[serde(default)]
    fix: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SemgrepError {
    message: String,
    path: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test Semgrep engine creation.
    ///
    /// Why: Ensures engine initialization succeeds when Semgrep is installed.
    /// Gracefully handles case where Semgrep is not installed.
    #[test]
    fn test_semgrep_engine_creation() {
        // This test will pass if Semgrep is installed, skip if not
        match SemgrepEngine::new() {
            Ok(engine) => {
                // Semgrep is installed
                assert!(engine.is_available().unwrap());
            }
            Err(_) => {
                // Semgrep not installed - acceptable for dev environments
                // In production, Semgrep should be available
                println!("Semgrep not installed - skipping test");
            }
        }
    }

    /// Test severity mapping.
    ///
    /// Why: Correct severity mapping ensures CI/CD pipeline behavior is correct.
    /// Critical/High should block builds, Medium/Low should warn.
    #[test]
    fn test_severity_mapping() {
        let engine = SemgrepEngine::new().unwrap_or_else(|_| {
            SemgrepEngine::with_config(RuleFilterConfig::default()).unwrap()
        });

        assert_eq!(
            engine.map_severity(&Some(SemgrepSeverity::Error)),
            Severity::Critical
        );
        assert_eq!(
            engine.map_severity(&Some(SemgrepSeverity::Warning)),
            Severity::High
        );
        assert_eq!(
            engine.map_severity(&Some(SemgrepSeverity::Info)),
            Severity::Medium
        );
        assert_eq!(engine.map_severity(&None), Severity::Low);
    }

    /// Test vulnerability type mapping.
    ///
    /// Why: Ensures Semgrep findings are categorized correctly in our system.
    /// Proper categorization enables accurate reporting and filtering.
    #[test]
    fn test_vulnerability_type_mapping() {
        let engine = SemgrepEngine::new().unwrap_or_else(|_| {
            SemgrepEngine::with_config(RuleFilterConfig::default()).unwrap()
        });

        assert_eq!(
            engine.map_vulnerability_type("python.lang.security.injection.sql-injection"),
            VulnerabilityType::SqlInjection
        );

        assert_eq!(
            engine.map_vulnerability_type("javascript.express.security.xss.direct"),
            VulnerabilityType::XssVulnerability
        );

        assert_eq!(
            engine.map_vulnerability_type("generic.secrets.security.detected-hardcoded-secret"),
            VulnerabilityType::HardcodedCredentials
        );

        assert_eq!(
            engine.map_vulnerability_type("go.lang.security.injection.command-injection"),
            VulnerabilityType::CommandInjection
        );
    }

    /// Test filter configuration.
    ///
    /// Why: Rule filtering reduces scan time and noise by focusing on
    /// security-relevant findings.
    #[test]
    fn test_filter_config() {
        let mut config = RuleFilterConfig::default();
        assert!(config.security_only);
        assert!(config.include_categories.contains(&"security".to_string()));

        // Test custom config
        config.min_severity = SemgrepSeverity::Error;
        config.exclude_rules.push("test-rule-1".to_string());

        let engine = SemgrepEngine::with_config(config).unwrap_or_else(|_| {
            SemgrepEngine::with_config(RuleFilterConfig::default()).unwrap()
        });

        assert_eq!(
            engine.filter_config.min_severity,
            SemgrepSeverity::Error
        );
    }
}
