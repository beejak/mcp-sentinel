//! Terminal output renderer

use anyhow::Result;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Table};
use crossterm::style::{Color, Stylize};

use crate::models::{
    scan_result::ScanResult,
    vulnerability::{Severity, Vulnerability},
};

/// Render scan results to terminal
pub fn render(result: &ScanResult) -> Result<()> {
    // Check if colors should be disabled
    let use_color = std::env::var("NO_COLOR").is_err();

    println!();
    print_header(use_color);
    println!();

    print_scan_info(result, use_color);
    println!();

    print_separator();
    print_summary(result, use_color);
    print_separator();

    if !result.vulnerabilities.is_empty() {
        println!();
        print_vulnerabilities(result, use_color);
    }

    println!();
    print_footer(result, use_color);
    println!();

    Ok(())
}

fn print_header(use_color: bool) {
    let title = "MCP Sentinel";
    let version = format!("v{}", crate::VERSION);

    if use_color {
        println!(
            "{}  {} {}",
            "🛡️".bold(),
            title.bold().with(Color::Blue),
            version.with(Color::DarkGrey)
        );
    } else {
        println!("🛡️  {} {}", title, version);
    }
}

fn print_scan_info(result: &ScanResult, use_color: bool) {
    if use_color {
        println!(
            "📂 Scanning: {}",
            result.target.clone().with(Color::Cyan)
        );
        println!(
            "🔍 Engines: {}",
            result
                .engines
                .join(" | ")
                .with(Color::Green)
        );
    } else {
        println!("📂 Scanning: {}", result.target);
        println!("🔍 Engines: {}", result.engines.join(" | "));
    }
}

fn print_separator() {
    println!("{}", "━".repeat(60));
}

fn print_summary(result: &ScanResult, use_color: bool) {
    println!("📊 SCAN RESULTS");
    println!();

    let risk_badge = result.severity_badge();

    if use_color {
        println!("Risk Score: {}/100 {}", result.summary.risk_score, risk_badge);
    } else {
        println!("Risk Score: {}/100 {}", result.summary.risk_score, risk_badge);
    }

    println!();

    // Print counts by severity
    print_severity_count("CRITICAL", result.summary.critical, Severity::Critical, use_color);
    print_severity_count("HIGH", result.summary.high, Severity::High, use_color);
    print_severity_count("MEDIUM", result.summary.medium, Severity::Medium, use_color);
    print_severity_count("LOW", result.summary.low, Severity::Low, use_color);
}

fn print_severity_count(label: &str, count: usize, severity: Severity, use_color: bool) {
    let emoji = severity.to_emoji();

    if use_color {
        let color = match severity {
            Severity::Critical => Color::Red,
            Severity::High => Color::DarkYellow,
            Severity::Medium => Color::Yellow,
            Severity::Low => Color::Blue,
        };

        println!(
            "{} {} Issues: {}",
            emoji,
            label.with(color).bold(),
            count.to_string().with(color)
        );
    } else {
        println!("{} {} Issues: {}", emoji, label, count);
    }
}

fn print_vulnerabilities(result: &ScanResult, use_color: bool) {
    // Group by severity and print
    for severity in &[
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ] {
        let vulns: Vec<&Vulnerability> = result
            .vulnerabilities
            .iter()
            .filter(|v| &v.severity == severity)
            .collect();

        if vulns.is_empty() {
            continue;
        }

        print_separator();
        if use_color {
            let color = match severity {
                Severity::Critical => Color::Red,
                Severity::High => Color::DarkYellow,
                Severity::Medium => Color::Yellow,
                Severity::Low => Color::Blue,
            };
            println!(
                "{} {} ISSUES",
                severity.to_emoji(),
                severity.to_badge().with(color).bold()
            );
        } else {
            println!("{} {} ISSUES", severity.to_emoji(), severity.to_badge());
        }
        print_separator();
        println!();

        for vuln in vulns {
            print_vulnerability(vuln, use_color);
            println!();
        }
    }
}

fn print_vulnerability(vuln: &Vulnerability, use_color: bool) {
    // ID and Title
    if use_color {
        println!(
            "[{}] {}",
            vuln.id.clone().with(Color::Cyan).bold(),
            vuln.title.clone().bold()
        );
    } else {
        println!("[{}] {}", vuln.id, vuln.title);
    }

    // Location
    if let Some(location) = &vuln.location {
        if use_color {
            println!("  Location: {}", location.format().with(Color::DarkGrey));
        } else {
            println!("  Location: {}", location.format());
        }
    }

    println!();

    // Description
    println!("  {}", vuln.description);

    // Impact
    if let Some(impact) = &vuln.impact {
        println!();
        if use_color {
            println!("  ⚠️  Impact: {}", impact.with(Color::DarkYellow));
        } else {
            println!("  ⚠️  Impact: {}", impact);
        }
    }

    // Remediation
    if let Some(remediation) = &vuln.remediation {
        println!();
        if use_color {
            println!("  🔧 Remediation: {}", remediation.with(Color::Green));
        } else {
            println!("  🔧 Remediation: {}", remediation);
        }
    }

    // Code snippet
    if let Some(snippet) = &vuln.code_snippet {
        println!();
        println!("  Code:");
        for line in snippet.lines() {
            if use_color {
                println!("    {}", line.with(Color::DarkGrey));
            } else {
                println!("    {}", line);
            }
        }
    }

    // AI Analysis
    if let Some(ai) = &vuln.ai_analysis {
        println!();
        if use_color {
            println!("  🤖 AI Analysis ({}):", ai.model.with(Color::Magenta));
        } else {
            println!("  🤖 AI Analysis ({}):", ai.model);
        }
        println!("  {}", ai.explanation);
        println!("  Confidence: {:.0}%", ai.confidence * 100.0);
    }
}

fn print_footer(result: &ScanResult, use_color: bool) {
    let duration = result.metadata.scan_duration_ms;
    let duration_str = if duration < 1000 {
        format!("{}ms", duration)
    } else {
        format!("{:.1}s", duration as f64 / 1000.0)
    };

    if use_color {
        println!("⏱️  Scan completed in {}", duration_str.with(Color::Green));
    } else {
        println!("⏱️  Scan completed in {}", duration_str);
    }
}

/// Print a simple table of vulnerabilities
pub fn print_summary_table(result: &ScanResult) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec!["ID", "Severity", "Type", "Location"]);

    for vuln in &result.vulnerabilities {
        let location = vuln
            .location
            .as_ref()
            .map(|l| l.format())
            .unwrap_or_else(|| "N/A".to_string());

        table.add_row(vec![
            &vuln.id,
            vuln.severity.to_badge(),
            vuln.vuln_type.name(),
            &location,
        ]);
    }

    println!("{}", table);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::vulnerability::{Location, Vulnerability, VulnerabilityType};

    #[test]
    fn test_render_empty_result() {
        let result = ScanResult::new("test-target", vec!["static".to_string()]);
        // Should not panic
        let _ = render(&result);
    }

    #[test]
    fn test_render_with_vulnerabilities() {
        let mut result = ScanResult::new("test-target", vec!["static".to_string()]);
        result.add_vulnerability(
            Vulnerability::new(
                "C-001",
                VulnerabilityType::CommandInjection,
                Severity::Critical,
                "Command Injection",
                "Unsafe command execution detected",
            )
            .with_location(Location::new("test.py").with_line(42))
            .with_impact("Remote code execution")
            .with_remediation("Use subprocess with array arguments"),
        );

        // Should not panic
        let _ = render(&result);
    }
}
