//! Common CLI types and enums

#[derive(Clone, Debug)]
pub enum ScanMode {
    Quick,
    Deep,
}

#[derive(Clone, Debug)]
pub enum LlmProvider {
    Openai,
    Anthropic,
    Local,
}

#[derive(Clone, Debug)]
pub enum OutputFormat {
    Terminal,
    Json,
    Html,
    Pdf,
    Sarif,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeverityLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl From<crate::models::vulnerability::Severity> for SeverityLevel {
    fn from(severity: crate::models::vulnerability::Severity) -> Self {
        match severity {
            crate::models::vulnerability::Severity::Low => SeverityLevel::Low,
            crate::models::vulnerability::Severity::Medium => SeverityLevel::Medium,
            crate::models::vulnerability::Severity::High => SeverityLevel::High,
            crate::models::vulnerability::Severity::Critical => SeverityLevel::Critical,
        }
    }
}

impl From<SeverityLevel> for crate::models::vulnerability::Severity {
    fn from(level: SeverityLevel) -> Self {
        match level {
            SeverityLevel::Low => crate::models::vulnerability::Severity::Low,
            SeverityLevel::Medium => crate::models::vulnerability::Severity::Medium,
            SeverityLevel::High => crate::models::vulnerability::Severity::High,
            SeverityLevel::Critical => crate::models::vulnerability::Severity::Critical,
        }
    }
}
