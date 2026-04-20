//! Baseline Storage System
//!
//! Manages baseline scan results for comparison across scans. Enables tracking
//! of NEW, FIXED, CHANGED, and UNCHANGED vulnerabilities over time.
//!
//! # Features
//!
//! - Compressed storage (gzip) for efficient disk usage
//! - SHA-256 hashing for file identity
//! - Baseline comparison with detailed diff
//! - Automatic baseline creation and updates
//! - Configurable storage location
//!
//! # Storage Format
//!
//! Baselines are stored in `~/.mcp-sentinel/baselines/` by default:
//! - `{project_hash}_baseline.json.gz` - Compressed baseline data
//! - `{project_hash}_metadata.json` - Baseline metadata
//!
//! # Usage
//!
//! ```rust
//! use mcp_sentinel::storage::baseline::BaselineManager;
//! use mcp_sentinel::models::ScanResult;
//!
//! # fn main() -> anyhow::Result<()> {
//! let manager = BaselineManager::new()?;
//!
//! // First scan - create baseline
//! let result = scan_project()?;
//! manager.save_baseline("my-project", &result, None)?;
//!
//! // Second scan - compare against baseline
//! let new_result = scan_project()?;
//! let comparison = manager.compare_with_baseline("my-project", &new_result)?;
//!
//! println!("NEW: {}", comparison.new_vulnerabilities.len());
//! println!("FIXED: {}", comparison.fixed_vulnerabilities.len());
//! # Ok(())
//! # }
//! ```

use crate::models::vulnerability::{Severity, Vulnerability};
use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Baseline scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    /// Project identifier
    pub project_id: String,

    /// Timestamp of baseline scan
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Vulnerabilities in the baseline
    pub vulnerabilities: Vec<BaselineVulnerability>,

    /// File hashes (path -> SHA-256 hash)
    pub file_hashes: HashMap<String, String>,

    /// Scan configuration fingerprint
    pub config_fingerprint: String,
}

/// Simplified vulnerability for baseline storage
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct BaselineVulnerability {
    /// Vulnerability ID (deterministic hash)
    pub id: String,

    /// Vulnerability type
    pub vuln_type: String,

    /// Severity
    pub severity: String,

    /// File path (relative)
    pub file_path: String,

    /// Line number
    pub line_number: Option<usize>,

    /// Description
    pub description: String,

    /// File content hash (to detect file changes)
    pub file_hash: String,
}

impl BaselineVulnerability {
    /// Create from a full Vulnerability
    pub fn from_vulnerability(vuln: &Vulnerability, file_hash: &str) -> Self {
        // Generate deterministic ID from vulnerability details
        let id_source = format!(
            "{}:{}:{}:{}",
            vuln.vuln_type.name(),
            vuln.location.file,
            vuln.location.line,
            vuln.description
        );

        let id = format!("{:x}", Sha256::digest(id_source.as_bytes()));

        Self {
            id,
            vuln_type: vuln.vuln_type.name().to_string(),
            severity: format!("{:?}", vuln.severity),
            file_path: vuln.location.file.clone(),
            line_number: Some(vuln.location.line),
            description: vuln.description.clone(),
            file_hash: file_hash.to_string(),
        }
    }
}

/// Baseline comparison result
#[derive(Debug, Clone)]
pub struct BaselineComparison {
    /// Newly detected vulnerabilities
    pub new_vulnerabilities: Vec<Vulnerability>,

    /// Fixed vulnerabilities (in baseline but not in current)
    pub fixed_vulnerabilities: Vec<BaselineVulnerability>,

    /// Changed vulnerabilities (file changed, vuln still present)
    pub changed_vulnerabilities: Vec<(BaselineVulnerability, Vulnerability)>,

    /// Unchanged vulnerabilities
    pub unchanged_vulnerabilities: Vec<Vulnerability>,

    /// Summary statistics
    pub summary: ComparisonSummary,
}

/// Comparison summary statistics
#[derive(Debug, Clone)]
pub struct ComparisonSummary {
    pub total_current: usize,
    pub total_baseline: usize,
    pub new_count: usize,
    pub fixed_count: usize,
    pub changed_count: usize,
    pub unchanged_count: usize,
}

/// Baseline manager for storage and comparison
pub struct BaselineManager {
    /// Base directory for baseline storage
    storage_dir: PathBuf,
}

impl BaselineManager {
    /// Create a new baseline manager
    ///
    /// # Returns
    ///
    /// Initialized manager with default storage directory
    ///
    /// # Errors
    ///
    /// - Failed to create storage directory
    /// - Invalid home directory
    pub fn new() -> Result<Self> {
        let storage_dir = Self::default_storage_dir()?;
        fs::create_dir_all(&storage_dir).context(format!(
            "Failed to create baseline storage directory: {}",
            storage_dir.display()
        ))?;

        debug!("Baseline manager initialized: {}", storage_dir.display());

        Ok(Self { storage_dir })
    }

    /// Create manager with custom storage directory
    pub fn with_storage_dir(dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&dir).context(format!(
            "Failed to create baseline storage directory: {}",
            dir.display()
        ))?;

        Ok(Self { storage_dir: dir })
    }

    /// Get default storage directory (~/.mcp-sentinel/baselines/)
    fn default_storage_dir() -> Result<PathBuf> {
        let home = dirs::home_dir().context("Failed to determine home directory")?;
        Ok(home.join(".mcp-sentinel").join("baselines"))
    }

    /// Save baseline for a project
    ///
    /// # Arguments
    ///
    /// * `project_id` - Unique project identifier
    /// * `vulnerabilities` - List of vulnerabilities
    /// * `file_hashes` - Map of file paths to content hashes
    /// * `config_fingerprint` - Optional fingerprint of scan configuration (for comparison validity)
    ///
    /// # Returns
    ///
    /// Path to saved baseline file
    ///
    /// # Errors
    ///
    /// - Failed to write baseline file
    /// - Serialization failed
    pub fn save_baseline(
        &self,
        project_id: &str,
        vulnerabilities: &[Vulnerability],
        file_hashes: HashMap<String, String>,
        config_fingerprint: Option<String>,
    ) -> Result<PathBuf> {
        info!("Saving baseline for project: {}", project_id);

        // Generate config fingerprint if not provided
        let fingerprint = config_fingerprint.unwrap_or_else(|| {
            // Default fingerprint based on vulnerability count and types
            // This ensures baselines with different detection capabilities are distinguished
            let mut fingerprint_input = String::new();
            fingerprint_input.push_str(&format!("vuln_count:{}", vulnerabilities.len()));

            // Include unique vulnerability types in fingerprint
            let mut types: Vec<String> = vulnerabilities
                .iter()
                .map(|v| v.vuln_type.name().to_string())
                .collect();
            types.sort();
            types.dedup();
            for vtype in types {
                fingerprint_input.push_str(&format!(";type:{}", vtype));
            }

            format!("{:x}", Sha256::digest(fingerprint_input.as_bytes()))
        });

        // Convert vulnerabilities to baseline format
        let baseline_vulns: Vec<BaselineVulnerability> = vulnerabilities
            .iter()
            .map(|v| {
                let file_hash = file_hashes
                    .get(&v.location.file)
                    .map(|s| s.as_str())
                    .unwrap_or("unknown");
                BaselineVulnerability::from_vulnerability(v, file_hash)
            })
            .collect();

        let baseline = Baseline {
            project_id: project_id.to_string(),
            timestamp: chrono::Utc::now(),
            vulnerabilities: baseline_vulns,
            file_hashes,
            config_fingerprint: fingerprint,
        };

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&baseline)
            .context("Failed to serialize baseline")?;

        // Compress with gzip
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(json.as_bytes())
            .context("Failed to compress baseline")?;
        let compressed = encoder.finish().context("Failed to finish compression")?;

        // Write to file
        let baseline_path = self.baseline_path(project_id);
        fs::write(&baseline_path, compressed).context(format!(
            "Failed to write baseline to: {}",
            baseline_path.display()
        ))?;

        info!(
            "Baseline saved: {} ({} vulnerabilities, {} bytes compressed)",
            baseline_path.display(),
            baseline.vulnerabilities.len(),
            compressed.len()
        );

        Ok(baseline_path)
    }

    /// Load baseline for a project
    ///
    /// # Arguments
    ///
    /// * `project_id` - Project identifier
    ///
    /// # Returns
    ///
    /// Loaded baseline, or None if not found
    ///
    /// # Errors
    ///
    /// - Failed to read baseline file
    /// - Decompression failed
    /// - Deserialization failed
    pub fn load_baseline(&self, project_id: &str) -> Result<Option<Baseline>> {
        let baseline_path = self.baseline_path(project_id);

        if !baseline_path.exists() {
            debug!("No baseline found for project: {}", project_id);
            return Ok(None);
        }

        info!("Loading baseline from: {}", baseline_path.display());

        // Read compressed file
        let compressed = fs::read(&baseline_path).context(format!(
            "Failed to read baseline from: {}",
            baseline_path.display()
        ))?;

        // Decompress
        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut json = String::new();
        decoder.read_to_string(&mut json)
            .context("Failed to decompress baseline")?;

        // Deserialize
        let baseline: Baseline = serde_json::from_str(&json)
            .context("Failed to deserialize baseline")?;

        debug!(
            "Baseline loaded: {} vulnerabilities from {}",
            baseline.vulnerabilities.len(),
            baseline.timestamp.format("%Y-%m-%d %H:%M:%S")
        );

        Ok(Some(baseline))
    }

    /// Compare current scan with baseline
    ///
    /// # Arguments
    ///
    /// * `project_id` - Project identifier
    /// * `current_vulnerabilities` - Current scan results
    /// * `current_file_hashes` - Current file hashes
    ///
    /// # Returns
    ///
    /// Comparison result with NEW/FIXED/CHANGED/UNCHANGED lists
    ///
    /// # Errors
    ///
    /// - Failed to load baseline
    pub fn compare_with_baseline(
        &self,
        project_id: &str,
        current_vulnerabilities: &[Vulnerability],
        current_file_hashes: &HashMap<String, String>,
    ) -> Result<BaselineComparison> {
        let baseline = match self.load_baseline(project_id)? {
            Some(b) => b,
            None => {
                // No baseline exists, all vulnerabilities are "new"
                return Ok(BaselineComparison {
                    new_vulnerabilities: current_vulnerabilities.to_vec(),
                    fixed_vulnerabilities: vec![],
                    changed_vulnerabilities: vec![],
                    unchanged_vulnerabilities: vec![],
                    summary: ComparisonSummary {
                        total_current: current_vulnerabilities.len(),
                        total_baseline: 0,
                        new_count: current_vulnerabilities.len(),
                        fixed_count: 0,
                        changed_count: 0,
                        unchanged_count: 0,
                    },
                });
            }
        };

        info!("Comparing current scan with baseline");

        // Convert current vulnerabilities to baseline format for comparison
        let current_baseline_vulns: Vec<BaselineVulnerability> = current_vulnerabilities
            .iter()
            .map(|v| {
                let file_hash = current_file_hashes
                    .get(&v.location.file)
                    .map(|s| s.as_str())
                    .unwrap_or("unknown");
                BaselineVulnerability::from_vulnerability(v, file_hash)
            })
            .collect();

        // Create maps for efficient lookup
        let baseline_map: HashMap<String, &BaselineVulnerability> =
            baseline.vulnerabilities.iter().map(|v| (v.id.clone(), v)).collect();
        let current_map: HashMap<String, usize> =
            current_baseline_vulns.iter().enumerate().map(|(i, v)| (v.id.clone(), i)).collect();

        // Classify vulnerabilities
        let mut new_vulnerabilities = Vec::new();
        let mut fixed_vulnerabilities = Vec::new();
        let mut changed_vulnerabilities = Vec::new();
        let mut unchanged_vulnerabilities = Vec::new();

        // Check current vulnerabilities against baseline
        for (i, current_vuln) in current_vulnerabilities.iter().enumerate() {
            let current_baseline = &current_baseline_vulns[i];

            if let Some(baseline_vuln) = baseline_map.get(&current_baseline.id) {
                // Vulnerability exists in baseline
                if baseline_vuln.file_hash != current_baseline.file_hash {
                    // File changed, vulnerability still present
                    changed_vulnerabilities.push(((*baseline_vuln).clone(), current_vuln.clone()));
                } else {
                    // Unchanged
                    unchanged_vulnerabilities.push(current_vuln.clone());
                }
            } else {
                // New vulnerability
                new_vulnerabilities.push(current_vuln.clone());
            }
        }

        // Check for fixed vulnerabilities (in baseline but not in current)
        for baseline_vuln in &baseline.vulnerabilities {
            if !current_map.contains_key(&baseline_vuln.id) {
                fixed_vulnerabilities.push(baseline_vuln.clone());
            }
        }

        let summary = ComparisonSummary {
            total_current: current_vulnerabilities.len(),
            total_baseline: baseline.vulnerabilities.len(),
            new_count: new_vulnerabilities.len(),
            fixed_count: fixed_vulnerabilities.len(),
            changed_count: changed_vulnerabilities.len(),
            unchanged_count: unchanged_vulnerabilities.len(),
        };

        info!(
            "Comparison complete: {} NEW, {} FIXED, {} CHANGED, {} UNCHANGED",
            summary.new_count, summary.fixed_count, summary.changed_count, summary.unchanged_count
        );

        Ok(BaselineComparison {
            new_vulnerabilities,
            fixed_vulnerabilities,
            changed_vulnerabilities,
            unchanged_vulnerabilities,
            summary,
        })
    }

    /// Delete baseline for a project
    pub fn delete_baseline(&self, project_id: &str) -> Result<()> {
        let baseline_path = self.baseline_path(project_id);

        if baseline_path.exists() {
            fs::remove_file(&baseline_path).context(format!(
                "Failed to delete baseline: {}",
                baseline_path.display()
            ))?;
            info!("Baseline deleted: {}", baseline_path.display());
        } else {
            warn!("No baseline to delete for project: {}", project_id);
        }

        Ok(())
    }

    /// Get path to baseline file
    fn baseline_path(&self, project_id: &str) -> PathBuf {
        let filename = format!("{}_baseline.json.gz", Self::hash_project_id(project_id));
        self.storage_dir.join(filename)
    }

    /// Hash project ID for filesystem safety
    fn hash_project_id(project_id: &str) -> String {
        format!("{:x}", Sha256::digest(project_id.as_bytes()))
    }

    /// Generate a configuration fingerprint for baseline comparison
    ///
    /// # Purpose
    ///
    /// Config fingerprints ensure baseline comparisons are valid. If scan configuration
    /// changes (e.g., different engines enabled, severity thresholds), the fingerprint
    /// will differ, warning users that the comparison may not be apples-to-apples.
    ///
    /// # Arguments
    ///
    /// * `config_params` - Key-value pairs describing scan configuration
    ///
    /// # Example
    ///
    /// ```
    /// use std::collections::HashMap;
    /// use mcp_sentinel::storage::baseline::BaselineManager;
    ///
    /// let mut config = HashMap::new();
    /// config.insert("mode".to_string(), "deep".to_string());
    /// config.insert("engines".to_string(), "static,semantic,semgrep,ai".to_string());
    /// config.insert("min_severity".to_string(), "medium".to_string());
    ///
    /// let fingerprint = BaselineManager::generate_config_fingerprint(&config);
    /// // fingerprint is a SHA-256 hash of sorted config params
    /// ```
    ///
    /// # Returns
    ///
    /// SHA-256 hash of configuration parameters (hex string, 64 characters)
    pub fn generate_config_fingerprint(config_params: &HashMap<String, String>) -> String {
        let mut sorted_params: Vec<(&String, &String)> = config_params.iter().collect();
        sorted_params.sort_by_key(|(k, _)| k.as_str());

        let mut fingerprint_input = String::new();
        for (key, value) in sorted_params {
            fingerprint_input.push_str(&format!("{}={};", key, value));
        }

        format!("{:x}", Sha256::digest(fingerprint_input.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::VulnerabilityType;

    #[test]
    fn test_baseline_vulnerability_id() {
        use crate::models::vulnerability::VulnerabilityLocation;

        let vuln1 = Vulnerability {
            vuln_type: VulnerabilityType::SecretsLeakage,
            severity: Severity::Critical,
            description: "API key exposed".to_string(),
            location: VulnerabilityLocation {
                file: "config.py".to_string(),
                line: 10,
                column: 5,
            },
            code_snippet: None,
            confidence: 0.9,
            impact: None,
            remediation: None,
        };

        let baseline1 = BaselineVulnerability::from_vulnerability(&vuln1, "hash123");
        let baseline2 = BaselineVulnerability::from_vulnerability(&vuln1, "hash456");

        // Same vulnerability should have same ID regardless of file hash
        assert_eq!(baseline1.id, baseline2.id);
    }

    #[test]
    fn test_hash_project_id() {
        let hash1 = BaselineManager::hash_project_id("my-project");
        let hash2 = BaselineManager::hash_project_id("my-project");
        let hash3 = BaselineManager::hash_project_id("other-project");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 64); // SHA-256 hex string length
    }

    #[test]
    fn test_baseline_serialization() {
        let baseline = Baseline {
            project_id: "test".to_string(),
            timestamp: chrono::Utc::now(),
            vulnerabilities: vec![],
            file_hashes: HashMap::new(),
            config_fingerprint: String::new(),
        };

        let json = serde_json::to_string(&baseline).unwrap();
        let deserialized: Baseline = serde_json::from_str(&json).unwrap();

        assert_eq!(baseline.project_id, deserialized.project_id);
    }
}
