//! Command-line interface implementations for all mcp-sentinel commands

pub mod audit;
pub mod errors;
pub mod init;
pub mod monitor;
pub mod proxy;
pub mod rules;
pub mod scan;
pub mod types;
pub mod whitelist;

// Re-export common types
pub use errors::{SentinelError, SentinelResult};
pub use types::{LlmProvider, OutputFormat, ScanMode, SeverityLevel};
