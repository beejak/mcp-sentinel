//! JSON output generator

use anyhow::Result;

use crate::models::scan_result::ScanResult;

/// Generate JSON report
pub fn generate(_result: &ScanResult) -> Result<String> {
    // Phase 1 implementation
    Ok(serde_json::to_string_pretty(_result)?)
}
