//! AI Analysis Finding Model
//!
//! This module defines the structure for vulnerability findings produced
//! by LLM-powered analysis engines.

use serde::{Deserialize, Serialize};
use crate::models::{Severity, VulnerabilityType};

/// AI analysis finding
///
/// Represents a security vulnerability or insight discovered through
/// LLM-powered code analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIFinding {
    /// Vulnerability type detected
    pub vuln_type: VulnerabilityType,

    /// Severity level
    pub severity: Severity,

    /// Confidence score (0.0 to 1.0)
    ///
    /// - 0.9-1.0: High confidence (clear vulnerability)
    /// - 0.7-0.9: Medium confidence (likely issue)
    /// - 0.5-0.7: Low confidence (possible issue)
    /// - <0.5: Very low confidence (investigate further)
    pub confidence: f64,

    /// Human-readable description
    pub description: String,

    /// Detailed explanation of the vulnerability
    pub explanation: String,

    /// Remediation guidance
    pub remediation: String,

    /// Affected code snippet
    pub code_snippet: Option<String>,

    /// File path
    pub file_path: String,

    /// Line number
    pub line_number: Option<usize>,

    /// Column number
    pub column: Option<usize>,

    /// LLM provider used for analysis
    pub provider: String,

    /// Model used
    pub model: String,

    /// Analysis context
    pub context: AnalysisMetadata,

    /// Additional insights or notes
    pub insights: Vec<String>,

    /// False positive likelihood (0.0 to 1.0)
    ///
    /// Lower is better - indicates how likely this is a false positive
    pub false_positive_likelihood: f64,

    /// Impact assessment
    pub impact: Option<ImpactAssessment>,
}

/// Analysis metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisMetadata {
    /// Programming language
    pub language: String,

    /// Function or class context
    pub scope: Option<String>,

    /// Timestamp of analysis
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Analysis duration in milliseconds
    pub duration_ms: u64,

    /// Tokens used (for cost tracking)
    pub tokens_used: Option<usize>,

    /// Cost in USD
    pub cost_usd: Option<f64>,
}

/// Impact assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactAssessment {
    /// Confidentiality impact
    pub confidentiality: ImpactLevel,

    /// Integrity impact
    pub integrity: ImpactLevel,

    /// Availability impact
    pub availability: ImpactLevel,

    /// Business impact description
    pub business_impact: Option<String>,
}

/// Impact level
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ImpactLevel {
    /// No impact
    None,
    /// Low impact
    Low,
    /// Medium impact
    Medium,
    /// High impact
    High,
}

impl AIFinding {
    /// Check if this finding meets a minimum confidence threshold
    pub fn meets_confidence(&self, threshold: f64) -> bool {
        self.confidence >= threshold
    }

    /// Check if this is likely a false positive
    pub fn is_likely_false_positive(&self) -> bool {
        self.false_positive_likelihood > 0.7
    }

    /// Get a short summary of the finding
    pub fn summary(&self) -> String {
        format!(
            "{} ({:?}) at {}:{} - Confidence: {:.0}%",
            self.vuln_type,
            self.severity,
            self.file_path,
            self.line_number.map_or("?".to_string(), |l| l.to_string()),
            self.confidence * 100.0
        )
    }

    /// Convert to a standard Vulnerability for reporting
    pub fn to_vulnerability(&self) -> crate::models::Vulnerability {
        crate::models::Vulnerability {
            id: uuid::Uuid::new_v4().to_string(),
            vuln_type: self.vuln_type.clone(),
            severity: self.severity,
            title: format!("{} (AI-detected)", self.vuln_type),
            description: self.description.clone(),
            location: crate::models::VulnerabilityLocation {
                file: self.file_path.clone(),
                line: self.line_number,
                column: self.column,
            },
            code_snippet: self.code_snippet.clone(),
            remediation: Some(self.remediation.clone()),
            confidence: Some(self.confidence),
            cwe_id: None, // Will be added by CWE mapper
            owasp_id: None, // Will be added by OWASP mapper
            impact: None,
            discovered_by: format!("AI Analysis ({})", self.provider),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_threshold() {
        let finding = AIFinding {
            vuln_type: VulnerabilityType::CommandInjection,
            severity: Severity::High,
            confidence: 0.85,
            description: "Test".to_string(),
            explanation: "Test".to_string(),
            remediation: "Test".to_string(),
            code_snippet: None,
            file_path: "test.py".to_string(),
            line_number: Some(10),
            column: None,
            provider: "test".to_string(),
            model: "test-model".to_string(),
            context: AnalysisMetadata {
                language: "python".to_string(),
                scope: None,
                timestamp: chrono::Utc::now(),
                duration_ms: 100,
                tokens_used: Some(50),
                cost_usd: Some(0.001),
            },
            insights: vec![],
            false_positive_likelihood: 0.1,
            impact: None,
        };

        assert!(finding.meets_confidence(0.8));
        assert!(!finding.meets_confidence(0.9));
        assert!(!finding.is_likely_false_positive());
    }

    #[test]
    fn test_to_vulnerability() {
        let finding = AIFinding {
            vuln_type: VulnerabilityType::SecretsLeakage,
            severity: Severity::Critical,
            confidence: 0.95,
            description: "API key exposed".to_string(),
            explanation: "Found hardcoded API key".to_string(),
            remediation: "Use environment variables".to_string(),
            code_snippet: Some("api_key = 'sk-123'".to_string()),
            file_path: "config.py".to_string(),
            line_number: Some(5),
            column: Some(10),
            provider: "openai".to_string(),
            model: "gpt-4".to_string(),
            context: AnalysisMetadata {
                language: "python".to_string(),
                scope: Some("Config".to_string()),
                timestamp: chrono::Utc::now(),
                duration_ms: 200,
                tokens_used: Some(100),
                cost_usd: Some(0.002),
            },
            insights: vec!["High risk of credential theft".to_string()],
            false_positive_likelihood: 0.05,
            impact: Some(ImpactAssessment {
                confidentiality: ImpactLevel::High,
                integrity: ImpactLevel::Medium,
                availability: ImpactLevel::Low,
                business_impact: Some("API access compromise".to_string()),
            }),
        };

        let vuln = finding.to_vulnerability();
        assert_eq!(vuln.severity, Severity::Critical);
        assert_eq!(vuln.location.file, "config.py");
        assert_eq!(vuln.location.line, Some(5));
    }
}
