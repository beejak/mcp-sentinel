//! Threat Intelligence Integration
//!
//! Provides integration with external threat intelligence sources:
//! - VulnerableMCP: Real-time MCP server vulnerability database
//! - MITRE ATT&CK: Adversary tactics and techniques mapping
//! - NVD: National Vulnerability Database for CVE enrichment

pub mod vulnerable_mcp;
pub mod mitre_attack;
pub mod nvd;

use crate::models::vulnerability::Vulnerability;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Threat intelligence enrichment data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligence {
    /// MITRE ATT&CK techniques
    pub attack_techniques: Vec<AttackTechnique>,

    /// CVE identifiers
    pub cves: Vec<String>,

    /// Known exploits
    pub exploits: Vec<ExploitInfo>,

    /// Threat actors known to use this technique
    pub threat_actors: Vec<String>,

    /// Real-world incidents
    pub incidents: Vec<IncidentInfo>,
}

/// MITRE ATT&CK technique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTechnique {
    /// Technique ID (e.g., T1059.001)
    pub id: String,

    /// Technique name
    pub name: String,

    /// Tactic (e.g., Execution, Persistence)
    pub tactic: String,

    /// Description
    pub description: String,
}

/// Exploit information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitInfo {
    /// Exploit name/title
    pub name: String,

    /// Exploit source (e.g., Exploit-DB, Metasploit)
    pub source: String,

    /// Exploit availability (public/private)
    pub availability: String,

    /// Maturity level
    pub maturity: String,
}

/// Security incident information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentInfo {
    /// Incident date
    pub date: String,

    /// Description
    pub description: String,

    /// Impact
    pub impact: String,

    /// Source/reference
    pub source: String,
}

/// Threat intelligence enrichment service
pub struct ThreatIntelService {
    vulnerable_mcp: vulnerable_mcp::VulnerableMcpClient,
    mitre: mitre_attack::MitreAttackMapper,
    nvd: nvd::NvdClient,
}

impl ThreatIntelService {
    /// Create a new threat intelligence service
    pub fn new() -> Result<Self> {
        info!("Initializing threat intelligence service (VulnerableMCP, MITRE ATT&CK, NVD)");

        Ok(Self {
            vulnerable_mcp: vulnerable_mcp::VulnerableMcpClient::new()?,
            mitre: mitre_attack::MitreAttackMapper::new()?,
            nvd: nvd::NvdClient::new()?,
        })
    }

    /// Enrich vulnerability with threat intelligence
    pub async fn enrich(&self, vulnerability: &Vulnerability) -> Result<ThreatIntelligence> {
        debug!("Enriching vulnerability {} with threat intelligence", vulnerability.id);

        let mut intel = ThreatIntelligence {
            attack_techniques: vec![],
            cves: vec![],
            exploits: vec![],
            threat_actors: vec![],
            incidents: vec![],
        };

        // Get MITRE ATT&CK mapping
        match self.mitre.map_vulnerability(vulnerability) {
            Ok(techniques) => {
                debug!("Mapped {} MITRE ATT&CK techniques for {}", techniques.len(), vulnerability.id);
                intel.attack_techniques = techniques;
            }
            Err(e) => {
                warn!("Failed to map MITRE ATT&CK techniques: {}", e);
            }
        }

        // Check VulnerableMCP database
        match self.vulnerable_mcp.check_vulnerability(vulnerability).await {
            Ok(mcp_intel) => {
                debug!("VulnerableMCP found {} CVEs for {}", mcp_intel.cves.len(), vulnerability.id);
                intel.cves.extend(mcp_intel.cves);
                intel.exploits.extend(mcp_intel.exploits);
                intel.threat_actors.extend(mcp_intel.threat_actors);
            }
            Err(e) => {
                warn!("VulnerableMCP query failed: {}", e);
            }
        }

        // Enrich with NVD data if CWE exists
        if let Some(cwe_id) = vulnerability.cwe_id {
            match self.nvd.get_cve_by_cwe(cwe_id).await {
                Ok(nvd_intel) => {
                    debug!("NVD found {} CVEs for CWE-{}", nvd_intel.cves.len(), cwe_id);
                    intel.cves.extend(nvd_intel.cves);
                    intel.incidents.extend(nvd_intel.incidents);
                }
                Err(e) => {
                    warn!("NVD query failed for CWE-{}: {}", cwe_id, e);
                }
            }
        }

        info!(
            "Enriched {} with {} techniques, {} CVEs, {} exploits",
            vulnerability.id,
            intel.attack_techniques.len(),
            intel.cves.len(),
            intel.exploits.len()
        );

        Ok(intel)
    }

    /// Batch enrich multiple vulnerabilities
    pub async fn enrich_batch(&self, vulnerabilities: &[Vulnerability]) -> Result<Vec<ThreatIntelligence>> {
        info!("Batch enriching {} vulnerabilities with threat intelligence", vulnerabilities.len());

        let mut results = Vec::new();
        let mut enriched_count = 0;
        let mut failed_count = 0;

        for vuln in vulnerabilities {
            match self.enrich(vuln).await {
                Ok(intel) => {
                    results.push(intel);
                    enriched_count += 1;
                }
                Err(e) => {
                    warn!("Failed to enrich vulnerability {}: {}", vuln.id, e);
                    failed_count += 1;
                    // If enrichment fails, return empty intel
                    results.push(ThreatIntelligence {
                        attack_techniques: vec![],
                        cves: vec![],
                        exploits: vec![],
                        threat_actors: vec![],
                        incidents: vec![],
                    });
                }
            }
        }

        info!("Batch enrichment complete: {} succeeded, {} failed", enriched_count, failed_count);

        Ok(results)
    }
}

impl Default for ThreatIntelService {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| {
            // Fallback if initialization fails
            Self {
                vulnerable_mcp: vulnerable_mcp::VulnerableMcpClient::default(),
                mitre: mitre_attack::MitreAttackMapper::default(),
                nvd: nvd::NvdClient::default(),
            }
        })
    }
}
