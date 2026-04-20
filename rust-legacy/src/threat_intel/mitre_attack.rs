//! MITRE ATT&CK Framework Integration
//!
//! Maps detected vulnerabilities to MITRE ATT&CK techniques and tactics.
//! This helps security teams understand how vulnerabilities fit into
//! the broader attack lifecycle.

use crate::models::vulnerability::{Vulnerability, VulnerabilityType};
use anyhow::Result;
use std::collections::HashMap;

/// MITRE ATT&CK technique mapper
pub struct MitreAttackMapper {
    /// Mapping of vulnerability types to ATT&CK techniques
    mappings: HashMap<VulnerabilityType, Vec<super::AttackTechnique>>,
}

impl MitreAttackMapper {
    /// Create a new MITRE ATT&CK mapper with predefined mappings
    pub fn new() -> Result<Self> {
        let mut mappings = HashMap::new();

        // Command Injection -> T1059 (Command and Scripting Interpreter)
        mappings.insert(
            VulnerabilityType::CommandInjection,
            vec![
                super::AttackTechnique {
                    id: "T1059".to_string(),
                    name: "Command and Scripting Interpreter".to_string(),
                    tactic: "Execution".to_string(),
                    description: "Adversaries abuse command and script interpreters to execute commands, scripts, or binaries.".to_string(),
                },
                super::AttackTechnique {
                    id: "T1059.004".to_string(),
                    name: "Command and Scripting Interpreter: Unix Shell".to_string(),
                    tactic: "Execution".to_string(),
                    description: "Adversaries abuse Unix shell commands and scripts for execution.".to_string(),
                },
            ],
        );

        // SQL Injection -> T1190 (Exploit Public-Facing Application)
        mappings.insert(
            VulnerabilityType::SQLInjection,
            vec![
                super::AttackTechnique {
                    id: "T1190".to_string(),
                    name: "Exploit Public-Facing Application".to_string(),
                    tactic: "Initial Access".to_string(),
                    description: "Adversaries exploit vulnerabilities in Internet-facing software to gain initial access.".to_string(),
                },
                super::AttackTechnique {
                    id: "T1213".to_string(),
                    name: "Data from Information Repositories".to_string(),
                    tactic: "Collection".to_string(),
                    description: "Adversaries leverage information repositories to find and collect sensitive data.".to_string(),
                },
            ],
        );

        // XSS -> T1189 (Drive-by Compromise), T1059.007 (JavaScript)
        mappings.insert(
            VulnerabilityType::XSS,
            vec![
                super::AttackTechnique {
                    id: "T1189".to_string(),
                    name: "Drive-by Compromise".to_string(),
                    tactic: "Initial Access".to_string(),
                    description: "Adversaries gain access to systems through users visiting compromised websites.".to_string(),
                },
                super::AttackTechnique {
                    id: "T1059.007".to_string(),
                    name: "Command and Scripting Interpreter: JavaScript".to_string(),
                    tactic: "Execution".to_string(),
                    description: "Adversaries abuse JavaScript for execution on victim systems.".to_string(),
                },
                super::AttackTechnique {
                    id: "T1185".to_string(),
                    name: "Browser Session Hijacking".to_string(),
                    tactic: "Collection".to_string(),
                    description: "Adversaries exploit security session vulnerabilities to gain access to user accounts.".to_string(),
                },
            ],
        );

        // Path Traversal -> T1083 (File and Directory Discovery), T1005 (Data from Local System)
        mappings.insert(
            VulnerabilityType::PathTraversal,
            vec![
                super::AttackTechnique {
                    id: "T1083".to_string(),
                    name: "File and Directory Discovery".to_string(),
                    tactic: "Discovery".to_string(),
                    description: "Adversaries enumerate files and directories to find sensitive data.".to_string(),
                },
                super::AttackTechnique {
                    id: "T1005".to_string(),
                    name: "Data from Local System".to_string(),
                    tactic: "Collection".to_string(),
                    description: "Adversaries search local system sources to find files of interest.".to_string(),
                },
            ],
        );

        // SSRF -> T1071 (Application Layer Protocol), T1090 (Proxy)
        mappings.insert(
            VulnerabilityType::SSRF,
            vec![
                super::AttackTechnique {
                    id: "T1071".to_string(),
                    name: "Application Layer Protocol".to_string(),
                    tactic: "Command and Control".to_string(),
                    description: "Adversaries abuse application layer protocols to avoid detection.".to_string(),
                },
                super::AttackTechnique {
                    id: "T1090".to_string(),
                    name: "Proxy".to_string(),
                    tactic: "Command and Control".to_string(),
                    description: "Adversaries use compromised servers as proxies to direct traffic.".to_string(),
                },
                super::AttackTechnique {
                    id: "T1595.002".to_string(),
                    name: "Active Scanning: Vulnerability Scanning".to_string(),
                    tactic: "Reconnaissance".to_string(),
                    description: "Adversaries scan internal networks for vulnerabilities through SSRF.".to_string(),
                },
            ],
        );

        // Prototype Pollution -> T1059.007 (JavaScript), T1211 (Exploitation for Defense Evasion)
        mappings.insert(
            VulnerabilityType::PrototypePollution,
            vec![
                super::AttackTechnique {
                    id: "T1059.007".to_string(),
                    name: "Command and Scripting Interpreter: JavaScript".to_string(),
                    tactic: "Execution".to_string(),
                    description: "Adversaries abuse JavaScript for execution on victim systems.".to_string(),
                },
                super::AttackTechnique {
                    id: "T1211".to_string(),
                    name: "Exploitation for Defense Evasion".to_string(),
                    tactic: "Defense Evasion".to_string(),
                    description: "Adversaries exploit software vulnerabilities to bypass security controls.".to_string(),
                },
            ],
        );

        // Code Injection -> T1055 (Process Injection), T1059 (Command and Scripting Interpreter)
        mappings.insert(
            VulnerabilityType::CodeInjection,
            vec![
                super::AttackTechnique {
                    id: "T1055".to_string(),
                    name: "Process Injection".to_string(),
                    tactic: "Defense Evasion".to_string(),
                    description: "Adversaries inject code into processes to evade detection.".to_string(),
                },
                super::AttackTechnique {
                    id: "T1059".to_string(),
                    name: "Command and Scripting Interpreter".to_string(),
                    tactic: "Execution".to_string(),
                    description: "Adversaries abuse interpreters to execute malicious code.".to_string(),
                },
            ],
        );

        // Hardcoded Secrets -> T1552 (Unsecured Credentials)
        mappings.insert(
            VulnerabilityType::HardcodedSecret,
            vec![
                super::AttackTechnique {
                    id: "T1552.001".to_string(),
                    name: "Unsecured Credentials: Credentials In Files".to_string(),
                    tactic: "Credential Access".to_string(),
                    description: "Adversaries search compromised systems for credentials stored in files.".to_string(),
                },
                super::AttackTechnique {
                    id: "T1078".to_string(),
                    name: "Valid Accounts".to_string(),
                    tactic: "Persistence".to_string(),
                    description: "Adversaries obtain and abuse credentials to maintain access.".to_string(),
                },
            ],
        );

        // Insecure Configuration -> T1190 (Exploit Public-Facing Application)
        mappings.insert(
            VulnerabilityType::InsecureConfiguration,
            vec![
                super::AttackTechnique {
                    id: "T1190".to_string(),
                    name: "Exploit Public-Facing Application".to_string(),
                    tactic: "Initial Access".to_string(),
                    description: "Adversaries exploit misconfigurations in public-facing applications.".to_string(),
                },
                super::AttackTechnique {
                    id: "T1548".to_string(),
                    name: "Abuse Elevation Control Mechanism".to_string(),
                    tactic: "Privilege Escalation".to_string(),
                    description: "Adversaries abuse misconfigurations to gain higher-level permissions.".to_string(),
                },
            ],
        );

        Ok(Self { mappings })
    }

    /// Map vulnerability to MITRE ATT&CK techniques
    pub fn map_vulnerability(&self, vulnerability: &Vulnerability) -> Result<Vec<super::AttackTechnique>> {
        let techniques = self
            .mappings
            .get(&vulnerability.vuln_type)
            .cloned()
            .unwrap_or_default();

        Ok(techniques)
    }

    /// Get all techniques for a specific tactic
    pub fn get_techniques_by_tactic(&self, tactic: &str) -> Vec<super::AttackTechnique> {
        let mut techniques = Vec::new();

        for technique_list in self.mappings.values() {
            for technique in technique_list {
                if technique.tactic == tactic && !techniques.iter().any(|t: &super::AttackTechnique| t.id == technique.id) {
                    techniques.push(technique.clone());
                }
            }
        }

        techniques
    }

    /// Get all supported tactics
    pub fn get_tactics(&self) -> Vec<String> {
        let mut tactics = Vec::new();

        for technique_list in self.mappings.values() {
            for technique in technique_list {
                if !tactics.contains(&technique.tactic) {
                    tactics.push(technique.tactic.clone());
                }
            }
        }

        tactics.sort();
        tactics
    }

    /// Get statistics about technique coverage
    pub fn get_coverage_stats(&self) -> CoverageStats {
        let mut unique_techniques = Vec::new();
        let mut unique_tactics = Vec::new();

        for technique_list in self.mappings.values() {
            for technique in technique_list {
                if !unique_techniques.contains(&technique.id) {
                    unique_techniques.push(technique.id.clone());
                }
                if !unique_tactics.contains(&technique.tactic) {
                    unique_tactics.push(technique.tactic.clone());
                }
            }
        }

        CoverageStats {
            total_vuln_types: self.mappings.len(),
            total_techniques: unique_techniques.len(),
            total_tactics: unique_tactics.len(),
        }
    }
}

impl Default for MitreAttackMapper {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

/// Coverage statistics
#[derive(Debug, Clone)]
pub struct CoverageStats {
    pub total_vuln_types: usize,
    pub total_techniques: usize,
    pub total_tactics: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::vulnerability::Severity;

    #[test]
    fn test_map_command_injection() {
        let mapper = MitreAttackMapper::new().unwrap();

        let vuln = Vulnerability::new(
            "TEST-001",
            VulnerabilityType::CommandInjection,
            Severity::High,
            "Command Injection",
            "Test",
        );

        let techniques = mapper.map_vulnerability(&vuln).unwrap();
        assert!(!techniques.is_empty());
        assert!(techniques.iter().any(|t| t.id == "T1059"));
    }

    #[test]
    fn test_map_sql_injection() {
        let mapper = MitreAttackMapper::new().unwrap();

        let vuln = Vulnerability::new(
            "TEST-002",
            VulnerabilityType::SQLInjection,
            Severity::Critical,
            "SQL Injection",
            "Test",
        );

        let techniques = mapper.map_vulnerability(&vuln).unwrap();
        assert!(!techniques.is_empty());
        assert!(techniques.iter().any(|t| t.id == "T1190"));
    }

    #[test]
    fn test_get_tactics() {
        let mapper = MitreAttackMapper::new().unwrap();
        let tactics = mapper.get_tactics();

        assert!(!tactics.is_empty());
        assert!(tactics.contains(&"Execution".to_string()));
        assert!(tactics.contains(&"Initial Access".to_string()));
    }

    #[test]
    fn test_coverage_stats() {
        let mapper = MitreAttackMapper::new().unwrap();
        let stats = mapper.get_coverage_stats();

        assert!(stats.total_vuln_types > 0);
        assert!(stats.total_techniques > 0);
        assert!(stats.total_tactics > 0);
    }
}
