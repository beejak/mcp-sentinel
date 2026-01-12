//! VulnerableMCP API Client
//!
//! Integrates with the VulnerableMCP threat intelligence database to check
//! for known vulnerabilities in MCP servers and related infrastructure.

use crate::models::vulnerability::{Vulnerability, VulnerabilityType};
use anyhow::{Context, Result};
use tracing::{debug, warn};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// VulnerableMCP API endpoint
const VULNERABLE_MCP_API: &str = "https://api.vulnerablemcp.com/v1";

/// VulnerableMCP intelligence data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerableMcpIntel {
    /// CVE identifiers
    pub cves: Vec<String>,

    /// Known exploits
    pub exploits: Vec<super::ExploitInfo>,

    /// Threat actors
    pub threat_actors: Vec<String>,

    /// Severity score (CVSS)
    pub cvss_score: Option<f32>,

    /// Exploit availability
    pub exploit_available: bool,
}

/// VulnerableMCP API response
#[derive(Debug, Deserialize)]
struct ApiResponse {
    status: String,
    data: Option<ApiData>,
}

#[derive(Debug, Deserialize)]
struct ApiData {
    vulnerabilities: Vec<ApiVulnerability>,
}

#[derive(Debug, Deserialize)]
struct ApiVulnerability {
    cve_id: Option<String>,
    cvss_score: Option<f32>,
    exploit_available: bool,
    exploits: Vec<ApiExploit>,
    threat_actors: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ApiExploit {
    name: String,
    source: String,
    availability: String,
    maturity: String,
}

/// VulnerableMCP API client
pub struct VulnerableMcpClient {
    api_url: String,
    api_key: Option<String>,
    client: reqwest::Client,
}

impl VulnerableMcpClient {
    /// Create a new VulnerableMCP client
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("MCP-Scanner/2.6.0")
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            api_url: VULNERABLE_MCP_API.to_string(),
            api_key: std::env::var("VULNERABLE_MCP_API_KEY").ok(),
            client,
        })
    }

    /// Check vulnerability against VulnerableMCP database
    pub async fn check_vulnerability(&self, vulnerability: &Vulnerability) -> Result<VulnerableMcpIntel> {
        debug!("Checking VulnerableMCP for vulnerability: {}", vulnerability.id);

        // Build query parameters based on vulnerability type
        let query = self.build_query(vulnerability);

        // Make API request
        let response = self.query_api(&query).await?;

        // Parse response into intelligence data
        self.parse_response(response)
    }

    /// Build API query from vulnerability
    fn build_query(&self, vulnerability: &Vulnerability) -> String {
        let vuln_type = match vulnerability.vuln_type {
            VulnerabilityType::CommandInjection => "command_injection",
            VulnerabilityType::SQLInjection => "sql_injection",
            VulnerabilityType::XSS => "xss",
            VulnerabilityType::PathTraversal => "path_traversal",
            VulnerabilityType::SSRF => "ssrf",
            VulnerabilityType::PrototypePollution => "prototype_pollution",
            VulnerabilityType::CodeInjection => "code_injection",
            _ => "generic",
        };

        // Include CWE if available
        let cwe_param = vulnerability.cwe_id
            .map(|cwe| format!("&cwe={}", cwe))
            .unwrap_or_default();

        format!("type={}{}", vuln_type, cwe_param)
    }

    /// Query VulnerableMCP API
    async fn query_api(&self, query: &str) -> Result<ApiResponse> {
        let url = format!("{}/vulnerabilities?{}", self.api_url, query);

        let mut request = self.client.get(&url);

        // Add API key if available
        if let Some(api_key) = &self.api_key {
            request = request.header("X-API-Key", api_key);
        }

        // Make request with timeout
        let response = request
            .send()
            .await
            .context("Failed to query VulnerableMCP API")?;

        if !response.status().is_success() {
            warn!("VulnerableMCP API returned error: {}", response.status());
            // Return empty response on error
            return Ok(ApiResponse {
                status: "error".to_string(),
                data: None,
            });
        }

        response
            .json::<ApiResponse>()
            .await
            .context("Failed to parse VulnerableMCP response")
    }

    /// Parse API response into intelligence data
    fn parse_response(&self, response: ApiResponse) -> Result<VulnerableMcpIntel> {
        // Return empty intel if no data available
        let data = match response.data {
            Some(d) if response.status == "success" => d,
            _ => {
                return Ok(VulnerableMcpIntel {
                    cves: vec![],
                    exploits: vec![],
                    threat_actors: vec![],
                    cvss_score: None,
                    exploit_available: false,
                });
            }
        };
        let mut intel = VulnerableMcpIntel {
            cves: vec![],
            exploits: vec![],
            threat_actors: vec![],
            cvss_score: None,
            exploit_available: false,
        };

        // Aggregate data from all matching vulnerabilities
        for vuln in data.vulnerabilities {
            if let Some(cve) = vuln.cve_id {
                intel.cves.push(cve);
            }

            if let Some(cvss) = vuln.cvss_score {
                // Use highest CVSS score
                intel.cvss_score = Some(
                    intel.cvss_score
                        .map(|existing| existing.max(cvss))
                        .unwrap_or(cvss)
                );
            }

            if vuln.exploit_available {
                intel.exploit_available = true;
            }

            // Add exploits
            for exploit in vuln.exploits {
                intel.exploits.push(super::ExploitInfo {
                    name: exploit.name,
                    source: exploit.source,
                    availability: exploit.availability,
                    maturity: exploit.maturity,
                });
            }

            // Add threat actors (deduplicate)
            for actor in vuln.threat_actors {
                if !intel.threat_actors.contains(&actor) {
                    intel.threat_actors.push(actor);
                }
            }
        }

        Ok(intel)
    }

    /// Check if API is available
    pub async fn health_check(&self) -> Result<bool> {
        let url = format!("{}/health", self.api_url);

        match self.client.get(&url).send().await {
            Ok(response) => Ok(response.status().is_success()),
            Err(_) => Ok(false),
        }
    }
}

impl Default for VulnerableMcpClient {
    fn default() -> Self {
        Self {
            api_url: VULNERABLE_MCP_API.to_string(),
            api_key: None,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to build default HTTP client - this should never fail"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::vulnerability::Severity;

    #[test]
    fn test_build_query() {
        let client = VulnerableMcpClient::new().unwrap();

        let vuln = Vulnerability::new(
            "TEST-001",
            VulnerabilityType::CommandInjection,
            Severity::High,
            "Test Vulnerability",
            "Test description",
        );

        let query = client.build_query(&vuln);
        assert!(query.contains("type=command_injection"));
    }

    #[test]
    fn test_build_query_with_cwe() {
        let client = VulnerableMcpClient::new().unwrap();

        let mut vuln = Vulnerability::new(
            "TEST-002",
            VulnerabilityType::SQLInjection,
            Severity::Critical,
            "SQL Injection",
            "Test SQL injection",
        );
        vuln.cwe_id = Some(89);

        let query = client.build_query(&vuln);
        assert!(query.contains("type=sql_injection"));
        assert!(query.contains("cwe=89"));
    }
}
