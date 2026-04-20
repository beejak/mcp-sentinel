//! Scan result data model

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::vulnerability::{Severity, Vulnerability};

/// Summary statistics for scan results
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_issues: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub risk_score: u8, // 0-100
}

impl ScanSummary {
    /// Create a summary from a list of vulnerabilities
    pub fn from_vulnerabilities(vulnerabilities: &[Vulnerability]) -> Self {
        let critical = vulnerabilities
            .iter()
            .filter(|v| v.severity == Severity::Critical)
            .count();
        let high = vulnerabilities
            .iter()
            .filter(|v| v.severity == Severity::High)
            .count();
        let medium = vulnerabilities
            .iter()
            .filter(|v| v.severity == Severity::Medium)
            .count();
        let low = vulnerabilities
            .iter()
            .filter(|v| v.severity == Severity::Low)
            .count();

        // Risk score calculation: weighted by severity
        // Critical: 40 points, High: 20 points, Medium: 5 points, Low: 1 point
        // Capped at 100
        let risk_score = ((critical * 40 + high * 20 + medium * 5 + low).min(100)) as u8;

        Self {
            total_issues: vulnerabilities.len(),
            critical,
            high,
            medium,
            low,
            risk_score,
        }
    }
}

/// Metadata about the scan
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub scan_duration_ms: u64,
    pub engines_used: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_model: Option<String>,
}

/// Complete scan result
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanResult {
    /// Version of MCP Sentinel that performed the scan
    pub version: String,

    /// Unique scan identifier
    pub scan_id: String,

    /// Timestamp when scan started
    pub timestamp: DateTime<Utc>,

    /// Target that was scanned (path, URL, etc.)
    pub target: String,

    /// Engines used for scanning
    pub engines: Vec<String>,

    /// Summary statistics
    pub summary: ScanSummary,

    /// List of detected vulnerabilities
    pub vulnerabilities: Vec<Vulnerability>,

    /// Scan metadata
    pub metadata: ScanMetadata,
}

impl ScanResult {
    /// Create a new scan result
    pub fn new(target: impl Into<String>, engines: Vec<String>) -> Self {
        Self {
            version: crate::VERSION.to_string(),
            scan_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            target: target.into(),
            engines,
            summary: ScanSummary {
                total_issues: 0,
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                risk_score: 0,
            },
            vulnerabilities: Vec::new(),
            metadata: ScanMetadata {
                scan_duration_ms: 0,
                engines_used: Vec::new(),
                llm_provider: None,
                llm_model: None,
            },
        }
    }

    /// Add a vulnerability to the result
    pub fn add_vulnerability(&mut self, vuln: Vulnerability) {
        self.vulnerabilities.push(vuln);
        self.update_summary();
    }

    /// Add multiple vulnerabilities
    pub fn add_vulnerabilities(&mut self, vulns: Vec<Vulnerability>) {
        self.vulnerabilities.extend(vulns);
        self.update_summary();
    }

    /// Update summary statistics based on current vulnerabilities
    fn update_summary(&mut self) {
        self.summary = ScanSummary::from_vulnerabilities(&self.vulnerabilities);
    }

    /// Filter vulnerabilities by minimum severity
    pub fn filter_by_severity(&self, min_severity: Severity) -> Vec<&Vulnerability> {
        self.vulnerabilities
            .iter()
            .filter(|v| v.severity >= min_severity)
            .collect()
    }

    /// Check if scan found any issues at or above a severity level
    pub fn has_issues_at_level(&self, min_severity: Severity) -> bool {
        self.vulnerabilities
            .iter()
            .any(|v| v.severity >= min_severity)
    }

    /// Set scan duration
    pub fn set_duration(&mut self, duration_ms: u64) {
        self.metadata.scan_duration_ms = duration_ms;
    }

    /// Set LLM provider info
    pub fn set_llm_info(&mut self, provider: impl Into<String>, model: impl Into<String>) {
        self.metadata.llm_provider = Some(provider.into());
        self.metadata.llm_model = Some(model.into());
    }

    /// Get severity badge text
    pub fn severity_badge(&self) -> &'static str {
        match self.summary.risk_score {
            90..=100 => "🔴 CRITICAL",
            70..=89 => "🟠 HIGH",
            40..=69 => "🟡 MEDIUM",
            _ => "🔵 LOW",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::vulnerability::{Vulnerability, VulnerabilityType};

    #[test]
    fn test_scan_summary_calculation() {
        let vulns = vec![
            Vulnerability::new(
                "C-001",
                VulnerabilityType::CommandInjection,
                Severity::Critical,
                "Test",
                "Desc",
            ),
            Vulnerability::new(
                "H-001",
                VulnerabilityType::CommandInjection,
                Severity::High,
                "Test",
                "Desc",
            ),
            Vulnerability::new(
                "M-001",
                VulnerabilityType::CommandInjection,
                Severity::Medium,
                "Test",
                "Desc",
            ),
        ];

        let summary = ScanSummary::from_vulnerabilities(&vulns);
        assert_eq!(summary.total_issues, 3);
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.medium, 1);
        assert_eq!(summary.low, 0);
        // 1*40 + 1*20 + 1*5 = 65
        assert_eq!(summary.risk_score, 65);
    }

    #[test]
    fn test_scan_result_add_vulnerabilities() {
        let mut result = ScanResult::new("test-target", vec!["static".to_string()]);

        result.add_vulnerability(Vulnerability::new(
            "C-001",
            VulnerabilityType::CommandInjection,
            Severity::Critical,
            "Test",
            "Desc",
        ));

        assert_eq!(result.vulnerabilities.len(), 1);
        assert_eq!(result.summary.total_issues, 1);
        assert_eq!(result.summary.critical, 1);
    }

    #[test]
    fn test_filter_by_severity() {
        let mut result = ScanResult::new("test-target", vec!["static".to_string()]);

        result.add_vulnerability(Vulnerability::new(
            "C-001",
            VulnerabilityType::CommandInjection,
            Severity::Critical,
            "Test",
            "Desc",
        ));
        result.add_vulnerability(Vulnerability::new(
            "L-001",
            VulnerabilityType::CommandInjection,
            Severity::Low,
            "Test",
            "Desc",
        ));

        let high_and_above = result.filter_by_severity(Severity::High);
        assert_eq!(high_and_above.len(), 1);

        let all = result.filter_by_severity(Severity::Low);
        assert_eq!(all.len(), 2);
    }
}
