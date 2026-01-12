//! MCP Sentinel - The Ultimate Security Scanner for MCP Servers
//!
//! This library provides comprehensive security scanning for Model Context Protocol (MCP) servers
//! through three complementary engines:
//! - Static Analysis: Code-level vulnerability detection
//! - Runtime Proxy: Real-time traffic monitoring
//! - AI Analysis: Contextual risk assessment using LLMs
//!
//! # Quick Start
//!
//! ```no_run
//! use mcp_sentinel::scanner::Scanner;
//! use mcp_sentinel::models::ScanConfig;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = ScanConfig::default();
//!     let scanner = Scanner::new(config);
//!     let results = scanner.scan_directory("./mcp-server").await?;
//!     println!("Found {} vulnerabilities", results.vulnerabilities.len());
//!     Ok(())
//! }
//! ```

pub mod cli;
pub mod config;
pub mod detectors;
pub mod engines;
pub mod models;
pub mod output;
pub mod providers;
pub mod storage;
pub mod suppression;
pub mod threat_intel;
pub mod utils;

// Re-export common types
pub use models::{
    config::ScanConfig,
    scan_result::ScanResult,
    vulnerability::{Severity, Vulnerability},
};

// Core scanner API
pub mod scanner;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = env!("CARGO_PKG_NAME");
