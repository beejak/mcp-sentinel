//! Vulnerability detectors

pub mod code_vulns;
pub mod mcp_config;
pub mod mcp_tools;  // Phase 2.5: Tool description analysis
pub mod package_confusion;  // Phase 2.6: npm package confusion and malicious install scripts
pub mod prompt_injection;
pub mod secrets;
pub mod tool_poisoning;

// Phase 3+ detectors
// pub mod pii;
// pub mod toxic_flows;
// pub mod anomalies;
