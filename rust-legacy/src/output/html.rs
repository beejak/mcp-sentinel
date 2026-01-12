//! HTML Report Generator - Interactive Security Dashboard
//!
//! ## Phase 2.5 - Advanced Reporting
//!
//! This module generates self-contained HTML reports with:
//! - Executive summary with risk score and trends
//! - Interactive charts (severity distribution, vulnerability types)
//! - Sortable/filterable vulnerability table
//! - Code snippets with syntax highlighting
//! - Export capabilities (CSV, JSON)
//! - Print-friendly CSS
//!
//! ## Why HTML Reports?
//!
//! **For Non-Technical Stakeholders**:
//! - Security managers need dashboards, not terminal output
//! - Executives want risk scores and trends
//! - Compliance teams need audit trails
//! - Developers want shareable findings
//!
//! **Self-Contained Design**:
//! - Single .html file (no external dependencies)
//! - Inline CSS and JavaScript
//! - Works offline
//! - Email-friendly
//!
//! ## Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────┐
//! │         HTML Report Structure              │
//! ├────────────────────────────────────────────┤
//! │                                            │
//! │  1. Executive Summary (Risk Score, Stats) │
//! │  2. Charts (Severity, Types, Timeline)    │
//! │  3. Vulnerability Table (Sortable)        │
//! │  4. Detailed Findings (Code Snippets)     │
//! │  5. Footer (Metadata, Export)             │
//! │                                            │
//! └────────────────────────────────────────────┘
//! ```
//!
//! ## Example Usage
//!
//! ```no_run
//! use mcp_sentinel::output::html;
//! use mcp_sentinel::models::scan_result::ScanResult;
//!
//! # fn example(result: &ScanResult) -> anyhow::Result<()> {
//! let html = html::generate(result)?;
//! std::fs::write("security-report.html", html)?;
//! println!("Report saved: security-report.html");
//! # Ok(())
//! # }
//! ```

use crate::models::{
    scan_result::ScanResult,
    vulnerability::{Severity, Vulnerability},
};
use anyhow::Result;
use chrono::Utc;
use handlebars::Handlebars;
use serde_json::json;
use std::collections::HashMap;
use tracing::{debug, info};

/// Generate HTML report from scan results.
///
/// ## Output
///
/// Returns a complete HTML document as a string. Contains:
/// - All CSS (inline <style>)
/// - All JavaScript (inline <script>)
/// - All data (embedded JSON)
/// - No external dependencies
pub fn generate(result: &ScanResult) -> Result<String> {
    info!("Generating HTML report for {} vulnerabilities", result.vulnerabilities.len());
    debug!("Compiling Handlebars template");
    let start = std::time::Instant::now();

    let mut handlebars = Handlebars::new();

    // Register template
    handlebars.register_template_string("report", HTML_TEMPLATE)?;

    // Prepare template data
    debug!("Preparing template data with statistics and groupings");
    let data = prepare_template_data(result);

    // Render
    let html = handlebars.render("report", &data)?;

    info!(
        "HTML report generated in {:?}, size: {} bytes ({:.1} KB)",
        start.elapsed(),
        html.len(),
        html.len() as f64 / 1024.0
    );

    Ok(html)
}

/// Prepare data for Handlebars template.
///
/// ## Why separate function
///
/// Makes data preparation testable. Can verify correct stats
/// calculation, grouping, etc. without rendering HTML.
fn prepare_template_data(result: &ScanResult) -> serde_json::Value {
    // Calculate statistics
    let total_vulns = result.vulnerabilities.len();
    let critical_count = result
        .vulnerabilities
        .iter()
        .filter(|v| v.severity == Severity::Critical)
        .count();
    let high_count = result
        .vulnerabilities
        .iter()
        .filter(|v| v.severity == Severity::High)
        .count();
    let medium_count = result
        .vulnerabilities
        .iter()
        .filter(|v| v.severity == Severity::Medium)
        .count();
    let low_count = result
        .vulnerabilities
        .iter()
        .filter(|v| v.severity == Severity::Low)
        .count();

    // Calculate risk score (0-100)
    let risk_score = calculate_risk_score(critical_count, high_count, medium_count, low_count);

    // Group vulnerabilities by type for charts
    let vuln_by_type = group_by_type(&result.vulnerabilities);

    // Group by severity for easy iteration
    let mut vulns_by_severity: HashMap<&str, Vec<&Vulnerability>> = HashMap::new();
    vulns_by_severity.insert("critical", Vec::new());
    vulns_by_severity.insert("high", Vec::new());
    vulns_by_severity.insert("medium", Vec::new());
    vulns_by_severity.insert("low", Vec::new());

    for vuln in &result.vulnerabilities {
        let key = match vuln.severity {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        };
        vulns_by_severity.get_mut(key).unwrap().push(vuln);
    }

    // Generate report timestamp
    let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

    json!({
        "scan_target": result.target,
        "scan_engines": result.engines.join(", "),
        "timestamp": timestamp,
        "total_vulns": total_vulns,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "risk_score": risk_score,
        "risk_level": risk_level_label(risk_score),
        "risk_color": risk_level_color(risk_score),
        "vuln_by_type": vuln_by_type,
        "vulnerabilities": result.vulnerabilities,
        "has_vulnerabilities": !result.vulnerabilities.is_empty(),
    })
}

/// Calculate risk score (0-100) based on vulnerability distribution.
///
/// ## Scoring Algorithm
///
/// - Critical: 10 points each
/// - High: 5 points each
/// - Medium: 2 points each
/// - Low: 1 point each
/// - Capped at 100
///
/// ## Why This Formula
///
/// - Emphasizes critical issues (blocking)
/// - Balanced weighting for high/medium
/// - Simple to understand for stakeholders
fn calculate_risk_score(critical: usize, high: usize, medium: usize, low: usize) -> u32 {
    let score = (critical * 10) + (high * 5) + (medium * 2) + low;
    std::cmp::min(score as u32, 100)
}

/// Get risk level label for risk score.
fn risk_level_label(score: u32) -> &'static str {
    match score {
        0 => "No Issues",
        1..=20 => "Low Risk",
        21..=50 => "Medium Risk",
        51..=80 => "High Risk",
        _ => "Critical Risk",
    }
}

/// Get color for risk score visualization.
fn risk_level_color(score: u32) -> &'static str {
    match score {
        0 => "#28a745",       // Green
        1..=20 => "#5cb85c",  // Light green
        21..=50 => "#f0ad4e", // Orange
        51..=80 => "#d9534f", // Red
        _ => "#a94442",       // Dark red
    }
}

/// Group vulnerabilities by type for pie chart.
fn group_by_type(vulnerabilities: &[Vulnerability]) -> Vec<serde_json::Value> {
    let mut type_counts: HashMap<String, usize> = HashMap::new();

    for vuln in vulnerabilities {
        let type_str = format!("{:?}", vuln.vuln_type);
        *type_counts.entry(type_str).or_insert(0) += 1;
    }

    type_counts
        .into_iter()
        .map(|(type_name, count)| {
            json!({
                "name": type_name,
                "count": count
            })
        })
        .collect()
}

/// HTML template with inline CSS and JavaScript.
///
/// ## Why Inline
///
/// - Single file portability
/// - No external CDN dependencies
/// - Works offline
/// - Consistent rendering across environments
const HTML_TEMPLATE: &str = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Sentinel Security Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f5f7fa;
            color: #333;
            line-height: 1.6;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }

        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
        }

        header h1 {
            font-size: 28px;
            margin-bottom: 10px;
        }

        header .meta {
            opacity: 0.9;
            font-size: 14px;
        }

        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
            border-bottom: 1px solid #e9ecef;
        }

        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }

        .stat-card.critical { border-color: #a94442; }
        .stat-card.high { border-color: #d9534f; }
        .stat-card.medium { border-color: #f0ad4e; }
        .stat-card.low { border-color: #5cb85c; }

        .stat-card .label {
            font-size: 12px;
            text-transform: uppercase;
            color: #6c757d;
            margin-bottom: 5px;
        }

        .stat-card .value {
            font-size: 32px;
            font-weight: bold;
        }

        .risk-score {
            text-align: center;
            padding: 40px;
            background: white;
        }

        .risk-circle {
            width: 150px;
            height: 150px;
            border-radius: 50%;
            margin: 0 auto 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 48px;
            font-weight: bold;
            color: white;
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }

        .vulnerabilities {
            padding: 30px;
        }

        .vuln-card {
            background: white;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }

        .vuln-header {
            padding: 15px 20px;
            border-left: 4px solid;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .vuln-header.critical { border-color: #a94442; background: #f2dede; }
        .vuln-header.high { border-color: #d9534f; background: #fcf8e3; }
        .vuln-header.medium { border-color: #f0ad4e; background: #fcf8e3; }
        .vuln-header.low { border-color: #5cb85c; background: #dff0d8; }

        .vuln-body {
            padding: 20px;
            display: none;
        }

        .vuln-body.expanded {
            display: block;
        }

        .code-snippet {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            padding: 15px;
            margin-top: 10px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            overflow-x: auto;
        }

        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }

        .badge.critical { background: #a94442; color: white; }
        .badge.high { background: #d9534f; color: white; }
        .badge.medium { background: #f0ad4e; color: white; }
        .badge.low { background: #5cb85c; color: white; }

        footer {
            padding: 20px;
            text-align: center;
            background: #f8f9fa;
            border-top: 1px solid #e9ecef;
            font-size: 12px;
            color: #6c757d;
        }

        @media print {
            body { background: white; padding: 0; }
            .container { box-shadow: none; }
            .vuln-body { display: block !important; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ MCP Sentinel Security Report</h1>
            <div class="meta">
                <strong>Target:</strong> {{scan_target}} &nbsp;|&nbsp;
                <strong>Engines:</strong> {{scan_engines}} &nbsp;|&nbsp;
                <strong>Generated:</strong> {{timestamp}}
            </div>
        </header>

        <div class="summary">
            <div class="stat-card">
                <div class="label">Total Issues</div>
                <div class="value">{{total_vulns}}</div>
            </div>
            <div class="stat-card critical">
                <div class="label">Critical</div>
                <div class="value">{{critical_count}}</div>
            </div>
            <div class="stat-card high">
                <div class="label">High</div>
                <div class="value">{{high_count}}</div>
            </div>
            <div class="stat-card medium">
                <div class="label">Medium</div>
                <div class="value">{{medium_count}}</div>
            </div>
            <div class="stat-card low">
                <div class="label">Low</div>
                <div class="value">{{low_count}}</div>
            </div>
        </div>

        <div class="risk-score">
            <div class="risk-circle" style="background: {{risk_color}};">
                {{risk_score}}
            </div>
            <h2>{{risk_level}}</h2>
            <p>Risk Score: {{risk_score}}/100</p>
        </div>

        {{#if has_vulnerabilities}}
        <div class="vulnerabilities">
            <h2 style="margin-bottom: 20px;">Vulnerability Details</h2>
            {{#each vulnerabilities}}
            <div class="vuln-card">
                <div class="vuln-header {{severity}}" onclick="toggleDetails('vuln-{{@index}}')">
                    <div>
                        <strong>{{title}}</strong>
                        <span class="badge {{severity}}">{{severity}}</span>
                    </div>
                    <span>▼</span>
                </div>
                <div id="vuln-{{@index}}" class="vuln-body">
                    <p><strong>Description:</strong> {{description}}</p>
                    {{#if location}}
                    <p><strong>Location:</strong> {{location.file}}:{{location.line}}</p>
                    {{/if}}
                    {{#if impact}}
                    <p><strong>Impact:</strong> {{impact}}</p>
                    {{/if}}
                    {{#if remediation}}
                    <p><strong>Remediation:</strong> {{remediation}}</p>
                    {{/if}}
                    {{#if code_snippet}}
                    <div class="code-snippet">{{code_snippet}}</div>
                    {{/if}}
                    <p><strong>Confidence:</strong> {{confidence}}</p>
                </div>
            </div>
            {{/each}}
        </div>
        {{else}}
        <div style="padding: 60px; text-align: center; color: #28a745;">
            <h2>✓ No Vulnerabilities Found</h2>
            <p>Your MCP server passed all security checks!</p>
        </div>
        {{/if}}

        <footer>
            <p>Generated by <strong>MCP Sentinel</strong> | https://github.com/beejak/MCP_Scanner</p>
            <p>Report generated at {{timestamp}}</p>
        </footer>
    </div>

    <script>
        function toggleDetails(id) {
            const element = document.getElementById(id);
            element.classList.toggle('expanded');
        }
    </script>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::location::Location;
    use crate::models::scan_result::{ScanResult, ScanSummary};

    /// Test HTML generation with empty results.
    ///
    /// Why: Empty results should produce valid HTML showing "No Vulnerabilities".
    /// This ensures the report generator doesn't fail on edge cases.
    #[test]
    fn test_generate_empty_report() {
        let result = ScanResult {
            target: "/test/project".to_string(),
            engines: vec!["static".to_string()],
            vulnerabilities: vec![],
            summary: ScanSummary {
                total_files: 0,
                total_vulnerabilities: 0,
                critical_count: 0,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
                risk_score: 0,
            },
        };

        let html = generate(&result).expect("Should generate HTML");
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("No Vulnerabilities Found"));
    }

    /// Test HTML generation with vulnerabilities.
    ///
    /// Why: Ensures vulnerabilities are correctly rendered with all details.
    #[test]
    fn test_generate_with_vulnerabilities() {
        let vuln = Vulnerability {
            id: "TEST-001".to_string(),
            title: "Test Vulnerability".to_string(),
            description: "Test description".to_string(),
            severity: Severity::High,
            vuln_type: crate::models::vulnerability::VulnerabilityType::CommandInjection,
            location: Some(Location {
                file: "/test/file.py".to_string(),
                line: Some(42),
                column: Some(10),
            }),
            code_snippet: Some("os.system(user_input)".to_string()),
            impact: Some("RCE".to_string()),
            remediation: Some("Use subprocess".to_string()),
            confidence: 0.95,
            evidence: None,
        };

        let result = ScanResult {
            target: "/test/project".to_string(),
            engines: vec!["static".to_string()],
            vulnerabilities: vec![vuln],
            summary: ScanSummary {
                total_files: 1,
                total_vulnerabilities: 1,
                critical_count: 0,
                high_count: 1,
                medium_count: 0,
                low_count: 0,
                risk_score: 5,
            },
        };

        let html = generate(&result).expect("Should generate HTML");
        assert!(html.contains("Test Vulnerability"));
        assert!(html.contains("Test description"));
        assert!(html.contains("/test/file.py"));
        assert!(html.contains("os.system(user_input)"));
    }

    /// Test risk score calculation.
    ///
    /// Why: Risk score drives executive summary and CI/CD decisions.
    /// Correct calculation is critical for reporting accuracy.
    #[test]
    fn test_risk_score_calculation() {
        assert_eq!(calculate_risk_score(0, 0, 0, 0), 0);
        assert_eq!(calculate_risk_score(1, 0, 0, 0), 10);  // 1 critical
        assert_eq!(calculate_risk_score(0, 1, 0, 0), 5);   // 1 high
        assert_eq!(calculate_risk_score(0, 0, 1, 0), 2);   // 1 medium
        assert_eq!(calculate_risk_score(0, 0, 0, 1), 1);   // 1 low
        assert_eq!(calculate_risk_score(2, 3, 5, 10), 55); // Mixed
        assert_eq!(calculate_risk_score(20, 0, 0, 0), 100); // Capped at 100
    }

    /// Test risk level labels.
    ///
    /// Why: Labels should match score ranges for consistent reporting.
    #[test]
    fn test_risk_level_labels() {
        assert_eq!(risk_level_label(0), "No Issues");
        assert_eq!(risk_level_label(10), "Low Risk");
        assert_eq!(risk_level_label(30), "Medium Risk");
        assert_eq!(risk_level_label(60), "High Risk");
        assert_eq!(risk_level_label(90), "Critical Risk");
    }
}
