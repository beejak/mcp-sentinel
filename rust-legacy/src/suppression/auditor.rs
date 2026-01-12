//! Suppression Audit Logging
//!
//! Logs all suppressed vulnerabilities for audit and compliance purposes.

use super::parser::Suppression;
use crate::models::Vulnerability;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::debug;

/// Audit log entry for a suppressed vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditEntry {
    /// Timestamp of suppression
    timestamp: chrono::DateTime<chrono::Utc>,

    /// Suppression ID that matched
    suppression_id: String,

    /// Suppression reason
    reason: String,

    /// Vulnerability type
    vuln_type: String,

    /// Vulnerability severity
    severity: String,

    /// File path
    file_path: String,

    /// Line number
    line_number: usize,

    /// Vulnerability description
    description: String,
}

/// Audit logger for suppressions
pub struct SuppressionAuditor {
    /// Path to audit log file
    log_path: PathBuf,
}

impl SuppressionAuditor {
    /// Create a new auditor
    ///
    /// # Returns
    ///
    /// Initialized auditor
    ///
    /// # Errors
    ///
    /// - Failed to create log directory
    pub fn new() -> Result<Self> {
        let log_path = Self::default_log_path()?;

        // Ensure directory exists
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent).context(format!(
                "Failed to create audit log directory: {}",
                parent.display()
            ))?;
        }

        debug!("Suppression auditor initialized: {}", log_path.display());

        Ok(Self { log_path })
    }

    /// Create auditor with custom log path
    pub fn with_log_path(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        Ok(Self { log_path: path })
    }

    /// Create a disabled auditor (no logging, graceful degradation)
    ///
    /// This is used when audit logging cannot be initialized (e.g., no home directory,
    /// no write permissions). The auditor will accept log calls but won't write anything.
    pub fn disabled() -> Self {
        // Use /dev/null on Unix, nul on Windows
        #[cfg(unix)]
        let null_path = PathBuf::from("/dev/null");
        #[cfg(windows)]
        let null_path = PathBuf::from("nul");
        #[cfg(not(any(unix, windows)))]
        let null_path = PathBuf::from(".mcp-sentinel-audit-disabled.log");

        Self { log_path: null_path }
    }

    /// Get default log path (~/.mcp-sentinel/suppressions.log)
    fn default_log_path() -> Result<PathBuf> {
        let home = dirs::home_dir().context("Failed to determine home directory")?;
        Ok(home
            .join(".mcp-sentinel")
            .join("logs")
            .join("suppressions.log"))
    }

    /// Log a suppression
    ///
    /// # Arguments
    ///
    /// * `suppression` - Suppression rule that matched
    /// * `vuln` - Vulnerability that was suppressed
    ///
    /// # Errors
    ///
    /// - Failed to write to log file
    pub fn log_suppression(&self, suppression: &Suppression, vuln: &Vulnerability) -> Result<()> {
        let entry = AuditEntry {
            timestamp: chrono::Utc::now(),
            suppression_id: suppression.id.clone(),
            reason: suppression.reason.clone(),
            vuln_type: vuln.vuln_type.name().to_string(),
            severity: format!("{:?}", vuln.severity),
            file_path: vuln.location.file.clone(),
            line_number: vuln.location.line,
            description: vuln.description.clone(),
        };

        self.write_entry(&entry)?;

        debug!(
            "Logged suppression: {} for {}:{}",
            suppression.id, vuln.location.file, vuln.location.line
        );

        Ok(())
    }

    /// Write entry to log file
    fn write_entry(&self, entry: &AuditEntry) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .context(format!(
                "Failed to open audit log: {}",
                self.log_path.display()
            ))?;

        let json = serde_json::to_string(entry).context("Failed to serialize audit entry")?;

        writeln!(file, "{}", json).context("Failed to write to audit log")?;

        Ok(())
    }

    /// Read all audit entries
    pub fn read_entries(&self) -> Result<Vec<AuditEntry>> {
        if !self.log_path.exists() {
            return Ok(vec![]);
        }

        let content = std::fs::read_to_string(&self.log_path).context(format!(
            "Failed to read audit log: {}",
            self.log_path.display()
        ))?;

        let mut entries = Vec::new();

        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<AuditEntry>(line) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    tracing::warn!("Failed to parse audit entry: {}", e);
                }
            }
        }

        Ok(entries)
    }

    /// Get audit statistics
    pub fn get_stats(&self) -> Result<AuditStats> {
        let entries = self.read_entries()?;

        let mut by_suppression_id: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut by_vuln_type: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        for entry in &entries {
            *by_suppression_id
                .entry(entry.suppression_id.clone())
                .or_insert(0) += 1;
            *by_vuln_type.entry(entry.vuln_type.clone()).or_insert(0) += 1;
        }

        Ok(AuditStats {
            total_suppressions: entries.len(),
            by_suppression_id,
            by_vuln_type,
        })
    }

    /// Clear audit log
    pub fn clear(&self) -> Result<()> {
        if self.log_path.exists() {
            std::fs::remove_file(&self.log_path).context(format!(
                "Failed to clear audit log: {}",
                self.log_path.display()
            ))?;
        }

        debug!("Cleared audit log");

        Ok(())
    }
}

/// Audit statistics
#[derive(Debug, Clone)]
pub struct AuditStats {
    /// Total number of suppressions logged
    pub total_suppressions: usize,

    /// Count by suppression ID
    pub by_suppression_id: std::collections::HashMap<String, usize>,

    /// Count by vulnerability type
    pub by_vuln_type: std::collections::HashMap<String, usize>,
}

impl AuditStats {
    /// Format as human-readable string
    pub fn format(&self) -> String {
        let mut output = format!("Total suppressions logged: {}\n", self.total_suppressions);

        if !self.by_suppression_id.is_empty() {
            output.push_str("\nBy Suppression ID:\n");
            let mut sorted: Vec<_> = self.by_suppression_id.iter().collect();
            sorted.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
            for (id, count) in sorted.iter().take(10) {
                output.push_str(&format!("  {}: {} times\n", id, count));
            }
        }

        if !self.by_vuln_type.is_empty() {
            output.push_str("\nBy Vulnerability Type:\n");
            let mut sorted: Vec<_> = self.by_vuln_type.iter().collect();
            sorted.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
            for (vuln_type, count) in sorted {
                output.push_str(&format!("  {}: {} times\n", vuln_type, count));
            }
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_stats_format() {
        let mut by_suppression_id = std::collections::HashMap::new();
        by_suppression_id.insert("SUP-001".to_string(), 5);
        by_suppression_id.insert("SUP-002".to_string(), 3);

        let mut by_vuln_type = std::collections::HashMap::new();
        by_vuln_type.insert("secrets".to_string(), 6);
        by_vuln_type.insert("command_injection".to_string(), 2);

        let stats = AuditStats {
            total_suppressions: 8,
            by_suppression_id,
            by_vuln_type,
        };

        let formatted = stats.format();
        assert!(formatted.contains("Total suppressions logged: 8"));
        assert!(formatted.contains("SUP-001: 5 times"));
        assert!(formatted.contains("secrets: 6 times"));
    }
}
