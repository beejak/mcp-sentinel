//! Data models for MCP Sentinel

pub mod config;
pub mod mcp_protocol;
pub mod scan_result;
pub mod vulnerability;

// Re-export commonly used types
pub use config::ScanConfig;
pub use scan_result::ScanResult;
pub use vulnerability::{Severity, Vulnerability, VulnerabilityType};
