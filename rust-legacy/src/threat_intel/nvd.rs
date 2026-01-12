//! National Vulnerability Database (NVD) Integration
//!
//! Integrates with the NVD API to enrich vulnerabilities with CVE data,
//! CVSS scores, and real-world incident information.

use anyhow::{Context, Result};
use tracing::{debug, warn};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// NVD API endpoint
const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// NVD intelligence data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdIntelligence {
    /// CVE identifiers
    pub cves: Vec<String>,

    /// Real-world incidents
    pub incidents: Vec<super::IncidentInfo>,

    /// CVSS v3 scores
    pub cvss_scores: Vec<CvssScore>,
}

/// CVSS score information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvssScore {
    /// CVE identifier
    pub cve_id: String,

    /// CVSS v3 base score
    pub base_score: f32,

    /// Severity (Low, Medium, High, Critical)
    pub severity: String,

    /// Attack vector
    pub attack_vector: String,

    /// Attack complexity
    pub attack_complexity: String,
}

/// NVD API response
#[derive(Debug, Deserialize)]
struct NvdApiResponse {
    #[serde(rename = "resultsPerPage")]
    results_per_page: i32,

    #[serde(rename = "totalResults")]
    total_results: i32,

    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnerability {
    cve: NvdCveItem,
}

#[derive(Debug, Deserialize)]
struct NvdCveItem {
    id: String,

    descriptions: Vec<NvdDescription>,

    metrics: Option<NvdMetrics>,

    #[serde(default)]
    references: Vec<NvdReference>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct NvdMetrics {
    #[serde(rename = "cvssMetricV31")]
    cvss_v31: Option<Vec<NvdCvssV31>>,
}

#[derive(Debug, Deserialize)]
struct NvdCvssV31 {
    #[serde(rename = "cvssData")]
    cvss_data: NvdCvssData,
}

#[derive(Debug, Deserialize)]
struct NvdCvssData {
    #[serde(rename = "baseScore")]
    base_score: f32,

    #[serde(rename = "baseSeverity")]
    base_severity: String,

    #[serde(rename = "attackVector")]
    attack_vector: String,

    #[serde(rename = "attackComplexity")]
    attack_complexity: String,
}

#[derive(Debug, Deserialize)]
struct NvdReference {
    url: String,
    source: String,
}

/// NVD API client
pub struct NvdClient {
    api_url: String,
    api_key: Option<String>,
    client: reqwest::Client,
}

impl NvdClient {
    /// Create a new NVD client
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("MCP-Scanner/2.6.0")
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            api_url: NVD_API_BASE.to_string(),
            api_key: std::env::var("NVD_API_KEY").ok(),
            client,
        })
    }

    /// Get CVEs by CWE identifier
    pub async fn get_cve_by_cwe(&self, cwe_id: usize) -> Result<NvdIntelligence> {
        debug!("Querying NVD for CWE-{}", cwe_id);

        let url = format!("{}?cweId=CWE-{}", self.api_url, cwe_id);

        let mut request = self.client.get(&url);

        // Add API key if available (increases rate limit)
        if let Some(api_key) = &self.api_key {
            request = request.header("apiKey", api_key);
        }

        // Make request
        let response = request
            .send()
            .await
            .context("Failed to query NVD API")?;

        if !response.status().is_success() {
            warn!("NVD API returned error: {}", response.status());
            return Ok(NvdIntelligence {
                cves: vec![],
                incidents: vec![],
                cvss_scores: vec![],
            });
        }

        let nvd_response: NvdApiResponse = response
            .json()
            .await
            .context("Failed to parse NVD response")?;

        self.parse_nvd_response(nvd_response)
    }

    /// Get specific CVE by ID
    pub async fn get_cve_by_id(&self, cve_id: &str) -> Result<Option<CvssScore>> {
        debug!("Querying NVD for CVE {}", cve_id);

        let url = format!("{}?cveId={}", self.api_url, cve_id);

        let mut request = self.client.get(&url);

        if let Some(api_key) = &self.api_key {
            request = request.header("apiKey", api_key);
        }

        let response = request
            .send()
            .await
            .context("Failed to query NVD API")?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let nvd_response: NvdApiResponse = response
            .json()
            .await
            .context("Failed to parse NVD response")?;

        if nvd_response.vulnerabilities.is_empty() {
            return Ok(None);
        }

        let cve_item = &nvd_response.vulnerabilities[0].cve;

        Ok(self.extract_cvss_score(cve_item))
    }

    /// Parse NVD API response
    fn parse_nvd_response(&self, response: NvdApiResponse) -> Result<NvdIntelligence> {
        let mut intel = NvdIntelligence {
            cves: vec![],
            incidents: vec![],
            cvss_scores: vec![],
        };

        // Limit to first 10 results to avoid overwhelming the response
        for vuln in response.vulnerabilities.iter().take(10) {
            let cve_item = &vuln.cve;

            // Add CVE ID
            intel.cves.push(cve_item.id.clone());

            // Extract CVSS score
            if let Some(cvss_score) = self.extract_cvss_score(cve_item) {
                intel.cvss_scores.push(cvss_score);
            }

            // Extract incident information from references
            for reference in &cve_item.references {
                // Check if reference indicates a real-world incident
                if self.is_incident_reference(&reference.url) {
                    let description = cve_item.descriptions
                        .iter()
                        .find(|d| d.lang == "en")
                        .map(|d| d.value.clone())
                        .unwrap_or_else(|| "No description available".to_string());

                    intel.incidents.push(super::IncidentInfo {
                        date: "Unknown".to_string(),
                        description: description.chars().take(200).collect::<String>() + "...",
                        impact: "See CVE details".to_string(),
                        source: reference.url.clone(),
                    });
                }
            }
        }

        Ok(intel)
    }

    /// Extract CVSS score from CVE item
    fn extract_cvss_score(&self, cve_item: &NvdCveItem) -> Option<CvssScore> {
        if let Some(metrics) = &cve_item.metrics {
            if let Some(cvss_v31) = &metrics.cvss_v31 {
                if let Some(cvss_metric) = cvss_v31.first() {
                    let cvss_data = &cvss_metric.cvss_data;

                    return Some(CvssScore {
                        cve_id: cve_item.id.clone(),
                        base_score: cvss_data.base_score,
                        severity: cvss_data.base_severity.clone(),
                        attack_vector: cvss_data.attack_vector.clone(),
                        attack_complexity: cvss_data.attack_complexity.clone(),
                    });
                }
            }
        }

        None
    }

    /// Check if a reference URL indicates a real-world incident
    fn is_incident_reference(&self, url: &str) -> bool {
        let incident_indicators = [
            "exploit-db.com",
            "packetstormsecurity.com",
            "metasploit.com",
            "rapid7.com",
            "securityfocus.com",
            "securelist.com",
        ];

        incident_indicators.iter().any(|indicator| url.contains(indicator))
    }

    /// Check if API is available
    pub async fn health_check(&self) -> Result<bool> {
        let url = format!("{}?resultsPerPage=1", self.api_url);

        match self.client.get(&url).send().await {
            Ok(response) => Ok(response.status().is_success()),
            Err(_) => Ok(false),
        }
    }
}

impl Default for NvdClient {
    fn default() -> Self {
        Self {
            api_url: NVD_API_BASE.to_string(),
            api_key: None,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("Failed to build default HTTP client - this should never fail"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_nvd_client() {
        let client = NvdClient::new();
        assert!(client.is_ok());
    }

    #[test]
    fn test_is_incident_reference() {
        let client = NvdClient::new().unwrap();

        assert!(client.is_incident_reference("https://www.exploit-db.com/exploits/12345"));
        assert!(client.is_incident_reference("https://packetstormsecurity.com/files/12345"));
        assert!(!client.is_incident_reference("https://nvd.nist.gov/vuln/detail/CVE-2021-12345"));
    }
}
