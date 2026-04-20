//! Threat Intelligence API Usage Examples
//!
//! This file demonstrates how to use the Phase 2.6 threat intelligence
//! integration for vulnerability enrichment.

use mcp_sentinel::threat_intel::{ThreatIntelService, ThreatIntelligence};
use mcp_sentinel::models::vulnerability::{Vulnerability, VulnerabilityType, Severity};
use anyhow::Result;

/// Example 1: Basic threat intelligence enrichment
///
/// Enrich a single vulnerability with CVE data, MITRE ATT&CK mapping,
/// and exploit information.
async fn example_basic_enrichment() -> Result<()> {
    println!("=== Example 1: Basic Threat Intelligence Enrichment ===\n");

    // Initialize threat intelligence service
    let threat_intel = ThreatIntelService::new()?;
    println!("✓ Threat intelligence service initialized");
    println!("  - VulnerableMCP API client ready");
    println!("  - MITRE ATT&CK mapper loaded");
    println!("  - NVD client configured\n");

    // Create a sample vulnerability
    let vulnerability = Vulnerability::new(
        "VULN-001",
        VulnerabilityType::CommandInjection,
        Severity::Critical,
        "Command Injection in Authentication",
        "User input is directly passed to shell command without sanitization",
    );

    println!("Enriching vulnerability: {}", vulnerability.title);

    // Enrich with threat intelligence
    let intel = threat_intel.enrich(&vulnerability).await?;

    // Display results
    println!("\nEnrichment Results:");
    println!("  MITRE ATT&CK Techniques: {}", intel.attack_techniques.len());
    for technique in &intel.attack_techniques {
        println!("    - {} ({}): {}", technique.id, technique.tactic, technique.name);
    }

    println!("\n  Related CVEs: {}", intel.cves.len());
    for cve in &intel.cves {
        println!("    - {}", cve);
    }

    println!("\n  Known Exploits: {}", intel.exploits.len());
    for exploit in &intel.exploits {
        println!("    - {} ({}) - {}", exploit.name, exploit.source, exploit.maturity);
    }

    println!("\n  Threat Actors: {}", intel.threat_actors.len());
    for actor in &intel.threat_actors {
        println!("    - {}", actor);
    }

    println!("\n  Real-World Incidents: {}", intel.incidents.len());
    for incident in &intel.incidents {
        println!("    - [{}] {}", incident.date, incident.description);
    }

    Ok(())
}

/// Example 2: Batch enrichment for multiple vulnerabilities
///
/// Efficiently enrich multiple vulnerabilities in a single operation.
async fn example_batch_enrichment() -> Result<()> {
    println!("\n=== Example 2: Batch Enrichment ===\n");

    let threat_intel = ThreatIntelService::new()?;

    // Create multiple vulnerabilities
    let vulnerabilities = vec![
        Vulnerability::new(
            "VULN-001",
            VulnerabilityType::CommandInjection,
            Severity::Critical,
            "Command Injection",
            "Shell command injection vulnerability",
        ),
        Vulnerability::new(
            "VULN-002",
            VulnerabilityType::SQLInjection,
            Severity::Critical,
            "SQL Injection",
            "Unsanitized SQL query",
        ),
        Vulnerability::new(
            "VULN-003",
            VulnerabilityType::XSS,
            Severity::High,
            "Cross-Site Scripting",
            "Unescaped user input in HTML",
        ),
    ];

    println!("Enriching {} vulnerabilities...", vulnerabilities.len());

    // Batch enrich
    let intel_results = threat_intel.enrich_batch(&vulnerabilities).await?;

    println!("\nBatch Enrichment Complete:");
    for (vuln, intel) in vulnerabilities.iter().zip(intel_results.iter()) {
        println!("  {} ({})", vuln.id, vuln.title);
        println!("    ATT&CK Techniques: {}", intel.attack_techniques.len());
        println!("    CVEs: {}", intel.cves.len());
        println!("    Exploits: {}", intel.exploits.len());
    }

    Ok(())
}

/// Example 3: MITRE ATT&CK mapping only
///
/// Use MITRE ATT&CK mapper independently for local, privacy-preserving mapping.
async fn example_mitre_attack_mapping() -> Result<()> {
    println!("\n=== Example 3: MITRE ATT&CK Mapping ===\n");

    use mcp_sentinel::threat_intel::mitre_attack::MitreAttackMapper;

    // Initialize MITRE ATT&CK mapper (local, no API calls)
    let mapper = MitreAttackMapper::new()?;
    println!("✓ MITRE ATT&CK mapper initialized (local mapping)\n");

    // Create a vulnerability
    let vulnerability = Vulnerability::new(
        "VULN-XSS-001",
        VulnerabilityType::XSS,
        Severity::High,
        "DOM-based XSS",
        "innerHTML assignment with user input",
    );

    // Map to MITRE ATT&CK
    let techniques = mapper.map_vulnerability(&vulnerability)?;

    println!("Mapped {} to {} MITRE ATT&CK techniques:\n", vulnerability.title, techniques.len());
    for technique in techniques {
        println!("  {} - {}", technique.id, technique.name);
        println!("    Tactic: {}", technique.tactic);
        println!("    Description: {}\n", technique.description);
    }

    // Get all supported tactics
    let tactics = mapper.get_tactics();
    println!("Supported MITRE ATT&CK Tactics ({}):", tactics.len());
    for tactic in tactics {
        println!("  - {}", tactic);
    }

    // Get coverage statistics
    let stats = mapper.get_coverage_stats();
    println!("\nCoverage Statistics:");
    println!("  Vulnerability Types Mapped: {}", stats.total_vuln_types);
    println!("  Unique Techniques: {}", stats.total_techniques);
    println!("  Tactics Covered: {}", stats.total_tactics);

    Ok(())
}

/// Example 4: NVD CVE lookup
///
/// Query National Vulnerability Database for CVE information.
async fn example_nvd_lookup() -> Result<()> {
    println!("\n=== Example 4: NVD CVE Lookup ===\n");

    use mcp_sentinel::threat_intel::nvd::NvdClient;

    // Initialize NVD client
    let nvd_client = NvdClient::new()?;
    println!("✓ NVD client initialized");

    // Check if NVD API key is set
    match std::env::var("NVD_API_KEY") {
        Ok(_) => println!("  - API key configured (50 req/min)"),
        Err(_) => println!("  - No API key (5 req/min limit)"),
    }
    println!();

    // Lookup by CWE (Command Injection - CWE-78)
    println!("Querying NVD for CWE-78 (Command Injection)...");
    let intel = nvd_client.get_cve_by_cwe(78).await?;

    println!("\nNVD Intelligence for CWE-78:");
    println!("  Related CVEs: {}", intel.cves.len());
    for (i, cve) in intel.cves.iter().take(5).enumerate() {
        println!("    {}. {}", i + 1, cve);
    }

    println!("\n  CVSS Scores: {}", intel.cvss_scores.len());
    for score in intel.cvss_scores.iter().take(3) {
        println!("    {} - Score: {} ({})", score.cve_id, score.base_score, score.severity);
        println!("      Attack Vector: {}, Complexity: {}", score.attack_vector, score.attack_complexity);
    }

    println!("\n  Real-World Incidents: {}", intel.incidents.len());
    for incident in intel.incidents.iter().take(3) {
        println!("    [{}] {}", incident.date, &incident.description[..100]);
    }

    // Lookup specific CVE
    println!("\nQuerying specific CVE: CVE-2024-12345...");
    if let Some(score) = nvd_client.get_cve_by_id("CVE-2024-12345").await? {
        println!("  CVE: {}", score.cve_id);
        println!("  CVSS Score: {} ({})", score.base_score, score.severity);
        println!("  Attack Vector: {}", score.attack_vector);
        println!("  Attack Complexity: {}", score.attack_complexity);
    } else {
        println!("  CVE not found in NVD database");
    }

    Ok(())
}

/// Example 5: VulnerableMCP API client
///
/// Query VulnerableMCP database for known vulnerabilities and exploits.
async fn example_vulnerable_mcp() -> Result<()> {
    println!("\n=== Example 5: VulnerableMCP API ===\n");

    use mcp_sentinel::threat_intel::vulnerable_mcp::VulnerableMcpClient;

    // Initialize VulnerableMCP client
    let mcp_client = VulnerableMcpClient::new()?;
    println!("✓ VulnerableMCP client initialized");

    // Check if API key is set
    match std::env::var("VULNERABLE_MCP_API_KEY") {
        Ok(_) => println!("  - API key configured"),
        Err(_) => println!("  - No API key (public API not yet available)"),
    }
    println!();

    // Create a vulnerability to check
    let mut vulnerability = Vulnerability::new(
        "VULN-SQL-001",
        VulnerabilityType::SQLInjection,
        Severity::Critical,
        "SQL Injection",
        "Unsanitized SQL query",
    );
    vulnerability.cwe_id = Some(89); // CWE-89: SQL Injection

    println!("Querying VulnerableMCP for SQL Injection...");
    let intel = mcp_client.check_vulnerability(&vulnerability).await?;

    println!("\nVulnerableMCP Intelligence:");
    println!("  CVEs: {}", intel.cves.len());
    for cve in intel.cves {
        println!("    - {}", cve);
    }

    println!("\n  CVSS Score: {:?}", intel.cvss_score);
    println!("  Exploit Available: {}", intel.exploit_available);

    println!("\n  Known Exploits: {}", intel.exploits.len());
    for exploit in intel.exploits {
        println!("    - {} ({}) - {}", exploit.name, exploit.source, exploit.maturity);
    }

    println!("\n  Threat Actors: {}", intel.threat_actors.len());
    for actor in intel.threat_actors {
        println!("    - {}", actor);
    }

    Ok(())
}

/// Example 6: Complete workflow with prioritization
///
/// Demonstrates a complete workflow: scan → enrich → prioritize → report.
async fn example_complete_workflow() -> Result<()> {
    println!("\n=== Example 6: Complete Workflow ===\n");

    // Step 1: Initialize services
    let threat_intel = ThreatIntelService::new()?;
    println!("Step 1: Initialized threat intelligence service");

    // Step 2: Create vulnerabilities (normally from scanner)
    let vulnerabilities = vec![
        Vulnerability::new(
            "VULN-001",
            VulnerabilityType::CommandInjection,
            Severity::Critical,
            "Command Injection",
            "Shell command injection",
        ),
        Vulnerability::new(
            "VULN-002",
            VulnerabilityType::XSS,
            Severity::High,
            "DOM XSS",
            "innerHTML with user input",
        ),
        Vulnerability::new(
            "VULN-003",
            VulnerabilityType::PathTraversal,
            Severity::Medium,
            "Path Traversal",
            "Unsanitized file path",
        ),
    ];
    println!("Step 2: Created {} vulnerabilities\n", vulnerabilities.len());

    // Step 3: Enrich with threat intelligence
    println!("Step 3: Enriching with threat intelligence...");
    let intel_results = threat_intel.enrich_batch(&vulnerabilities).await?;
    println!("        Enrichment complete\n");

    // Step 4: Prioritize based on threat intelligence
    println!("Step 4: Prioritizing based on threat intelligence:\n");

    #[derive(Debug)]
    struct VulnPriority<'a> {
        vuln: &'a Vulnerability,
        intel: &'a ThreatIntelligence,
        priority_score: u32,
    }

    let mut prioritized: Vec<VulnPriority> = vulnerabilities
        .iter()
        .zip(intel_results.iter())
        .map(|(vuln, intel)| {
            let mut score = match vuln.severity {
                Severity::Critical => 100,
                Severity::High => 75,
                Severity::Medium => 50,
                Severity::Low => 25,
                Severity::Info => 10,
            };

            // Increase priority if exploits available
            if !intel.exploits.is_empty() {
                score += 50;
            }

            // Increase priority if threat actors identified
            if !intel.threat_actors.is_empty() {
                score += 30;
            }

            // Increase priority if CVEs found
            score += (intel.cves.len() as u32) * 10;

            VulnPriority {
                vuln,
                intel,
                priority_score: score,
            }
        })
        .collect();

    // Sort by priority score (descending)
    prioritized.sort_by(|a, b| b.priority_score.cmp(&a.priority_score));

    // Step 5: Report prioritized vulnerabilities
    println!("Step 5: Prioritized Remediation Plan:\n");
    for (rank, item) in prioritized.iter().enumerate() {
        println!("  Priority {}: {} (Score: {})", rank + 1, item.vuln.title, item.priority_score);
        println!("    Severity: {:?}", item.vuln.severity);
        println!("    ATT&CK Techniques: {}", item.intel.attack_techniques.len());
        println!("    CVEs: {}", item.intel.cves.len());
        println!("    Exploits: {}", item.intel.exploits.len());
        println!("    Threat Actors: {}", item.intel.threat_actors.len());
        println!();
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("\n");
    println!("╔═══════════════════════════════════════════════════════════════════════════╗");
    println!("║                                                                           ║");
    println!("║          MCP Sentinel v2.6.0 - Threat Intelligence API Examples           ║");
    println!("║                                                                           ║");
    println!("╚═══════════════════════════════════════════════════════════════════════════╝");
    println!("\n");

    // Run all examples
    if let Err(e) = example_basic_enrichment().await {
        eprintln!("Example 1 failed: {}", e);
    }

    if let Err(e) = example_batch_enrichment().await {
        eprintln!("Example 2 failed: {}", e);
    }

    if let Err(e) = example_mitre_attack_mapping().await {
        eprintln!("Example 3 failed: {}", e);
    }

    if let Err(e) = example_nvd_lookup().await {
        eprintln!("Example 4 failed: {}", e);
    }

    if let Err(e) = example_vulnerable_mcp().await {
        eprintln!("Example 5 failed: {}", e);
    }

    if let Err(e) = example_complete_workflow().await {
        eprintln!("Example 6 failed: {}", e);
    }

    println!("\n");
    println!("╔═══════════════════════════════════════════════════════════════════════════╗");
    println!("║                          All Examples Complete!                           ║");
    println!("╚═══════════════════════════════════════════════════════════════════════════╝");
    println!("\n");

    println!("💡 Tips:");
    println!("  - Set VULNERABLE_MCP_API_KEY for VulnerableMCP API access");
    println!("  - Set NVD_API_KEY for faster NVD queries (50 req/min vs 5/min)");
    println!("  - MITRE ATT&CK mapping is local (no API key needed)");
    println!("  - All APIs fail gracefully if unavailable");
    println!("\n");

    Ok(())
}
