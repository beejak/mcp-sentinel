//! Exit code handling for CLI commands

use std::fmt;
use std::process::ExitCode;

/// Exit codes for the MCP Sentinel CLI
///
/// These codes allow CI/CD pipelines to distinguish between different types of failures:
/// - 0: Success (no vulnerabilities found or all below threshold)
/// - 1: Vulnerabilities found at or above the specified threshold
/// - 2: Scan error (target not found, invalid config, scan failure)
/// - 3: Usage error (invalid arguments - handled by Clap)
#[derive(Debug)]
pub enum SentinelError {
    /// Successful scan with no issues (exit code 0)
    Success,

    /// Vulnerabilities found at or above threshold (exit code 1)
    VulnerabilitiesFound { message: String },

    /// Scan failed due to an error (exit code 2)
    ScanError { message: String },

    /// Invalid usage or arguments (exit code 3)
    UsageError { message: String },
}

impl SentinelError {
    /// Get the exit code for this error
    pub fn exit_code(&self) -> u8 {
        match self {
            SentinelError::Success => 0,
            SentinelError::VulnerabilitiesFound { .. } => 1,
            SentinelError::ScanError { .. } => 2,
            SentinelError::UsageError { .. } => 3,
        }
    }

    /// Convert to ExitCode for use with main()
    pub fn to_exit_code(&self) -> ExitCode {
        ExitCode::from(self.exit_code())
    }

    /// Create a VulnerabilitiesFound error
    pub fn vulnerabilities_found(message: impl Into<String>) -> Self {
        SentinelError::VulnerabilitiesFound {
            message: message.into(),
        }
    }

    /// Create a ScanError
    pub fn scan_error(message: impl Into<String>) -> Self {
        SentinelError::ScanError {
            message: message.into(),
        }
    }

    /// Create a UsageError
    pub fn usage_error(message: impl Into<String>) -> Self {
        SentinelError::UsageError {
            message: message.into(),
        }
    }
}

impl fmt::Display for SentinelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SentinelError::Success => write!(f, "Success"),
            SentinelError::VulnerabilitiesFound { message } => write!(f, "{}", message),
            SentinelError::ScanError { message } => write!(f, "Scan error: {}", message),
            SentinelError::UsageError { message } => write!(f, "Usage error: {}", message),
        }
    }
}

impl std::error::Error for SentinelError {}

/// Result type that uses SentinelError
pub type SentinelResult<T = ()> = Result<T, SentinelError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_codes() {
        assert_eq!(SentinelError::Success.exit_code(), 0);
        assert_eq!(
            SentinelError::vulnerabilities_found("test").exit_code(),
            1
        );
        assert_eq!(SentinelError::scan_error("test").exit_code(), 2);
        assert_eq!(SentinelError::usage_error("test").exit_code(), 3);
    }

    #[test]
    fn test_error_display() {
        let err = SentinelError::vulnerabilities_found("Found 5 critical issues");
        assert_eq!(err.to_string(), "Found 5 critical issues");

        let err = SentinelError::scan_error("Target not found");
        assert_eq!(err.to_string(), "Scan error: Target not found");
    }
}
