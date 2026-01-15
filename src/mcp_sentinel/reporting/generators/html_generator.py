"""
HTML report generator with interactive dashboard.

Generates beautiful, self-contained HTML reports with:
- Executive summary dashboard
- Vulnerability breakdown by severity
- Detailed findings with code snippets
- Risk score visualization
- Engine attribution
"""

from datetime import datetime
from html import escape
from pathlib import Path

from mcp_sentinel import __version__
from mcp_sentinel.models.scan_result import ScanResult
from mcp_sentinel.models.vulnerability import Vulnerability


class HTMLGenerator:
    """Generate interactive HTML reports."""

    def generate(self, result: ScanResult) -> str:
        """
        Generate HTML report from scan result.

        Args:
            result: ScanResult from scanner

        Returns:
            Complete HTML document as string
        """
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Sentinel Security Report - {escape(result.target)}</title>
    <style>
        {self._get_css()}
    </style>
</head>
<body>
    {self._generate_header(result)}
    {self._generate_summary(result)}
    {self._generate_severity_breakdown(result)}
    {self._generate_findings(result)}
    {self._generate_footer()}
    <script>
        {self._get_javascript()}
    </script>
</body>
</html>
"""

    def save_to_file(self, result: ScanResult, output_path: Path) -> None:
        """
        Save HTML report to file.

        Args:
            result: ScanResult from scanner
            output_path: Path to output file
        """
        html = self.generate(result)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")

    def _generate_header(self, result: ScanResult) -> str:
        """Generate report header."""
        status_color = "green" if result.status == "completed" else "red"
        return f"""
    <header class="header">
        <div class="container">
            <h1>🛡️ MCP Sentinel Security Report</h1>
            <p class="subtitle">Enterprise Security Scanner v{__version__}</p>
            <div class="header-info">
                <span><strong>Target:</strong> {escape(result.target)}</span>
                <span><strong>Status:</strong> <span class="badge badge-{status_color}">{result.status.upper()}</span></span>
                <span><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</span>
            </div>
        </div>
    </header>
"""

    def _generate_summary(self, result: ScanResult) -> str:
        """Generate executive summary dashboard."""
        risk_score = result.risk_score()
        risk_level, risk_color = self._get_risk_level(risk_score)

        return f"""
    <section class="summary">
        <div class="container">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card metric-card">
                    <div class="summary-value">{result.statistics.total_files}</div>
                    <div class="summary-label">Total Files</div>
                </div>
                <div class="summary-card metric-card">
                    <div class="summary-value">{result.statistics.scanned_files}</div>
                    <div class="summary-label">Files Scanned</div>
                </div>
                <div class="summary-card metric-card">
                    <div class="summary-value">{result.statistics.total_vulnerabilities}</div>
                    <div class="summary-label">Total Vulnerabilities</div>
                </div>
                <div class="summary-card metric-card">
                    <div class="summary-value">{result.statistics.scan_duration_seconds:.2f}s</div>
                    <div class="summary-label">Scan Duration</div>
                </div>
                <div class="summary-card risk-card">
                    <div class="summary-value risk-{risk_color}">{risk_score:.1f}/100</div>
                    <div class="summary-label">Risk Score</div>
                    <div class="risk-badge badge-{risk_color}">{risk_level}</div>
                </div>
            </div>
        </div>
    </section>
"""

    def _generate_severity_breakdown(self, result: ScanResult) -> str:
        """Generate severity breakdown section."""
        total = result.statistics.total_vulnerabilities
        if total == 0:
            return """
    <section class="severity-section">
        <div class="container">
            <h2>Vulnerabilities by Severity</h2>
            <div class="no-findings">
                <span class="emoji">✅</span>
                <p>No vulnerabilities found! Your code looks secure.</p>
            </div>
        </div>
    </section>
"""

        severities = [
            ("Critical", result.statistics.critical_count, "critical"),
            ("High", result.statistics.high_count, "high"),
            ("Medium", result.statistics.medium_count, "medium"),
            ("Low", result.statistics.low_count, "low"),
            ("Info", result.statistics.info_count, "info"),
        ]

        bars = ""
        for name, count, level in severities:
            if count > 0:
                percentage = (count / total) * 100
                bars += f"""
                <div class="severity-item">
                    <div class="severity-header">
                        <span class="severity-label">{name}</span>
                        <span class="severity-count">{count}</span>
                    </div>
                    <div class="severity-bar">
                        <div class="severity-fill severity-{level}" style="width: {percentage}%"></div>
                    </div>
                </div>
"""

        return f"""
    <section class="severity-section">
        <div class="container">
            <h2>Vulnerabilities by Severity</h2>
            <div class="severity-breakdown">
                {bars}
            </div>
        </div>
    </section>
"""

    def _generate_findings(self, result: ScanResult) -> str:
        """Generate detailed findings section."""
        if not result.vulnerabilities:
            return ""

        findings_html = ""
        for i, vuln in enumerate(result.vulnerabilities, 1):
            findings_html += self._generate_finding_card(i, vuln)

        return f"""
    <section class="findings-section">
        <div class="container">
            <h2>Detailed Findings</h2>
            <p class="findings-count">Found {len(result.vulnerabilities)} vulnerabilities</p>
            <div class="findings-list">
                {findings_html}
            </div>
        </div>
    </section>
"""

    def _generate_finding_card(self, index: int, vuln: Vulnerability) -> str:
        """Generate individual finding card."""
        severity_color = vuln.severity.value.lower()

        return f"""
        <div class="finding-card">
            <div class="finding-header">
                <div class="finding-number">#{index}</div>
                <div class="finding-title">
                    <h3>{escape(vuln.title)}</h3>
                    <span class="badge badge-{severity_color}">{vuln.severity.value.upper()}</span>
                </div>
            </div>
            <div class="finding-meta">
                <span><strong>File:</strong> {escape(vuln.file_path)}:{vuln.line_number}</span>
                <span><strong>Engine:</strong> {escape(vuln.engine)}</span>
                <span><strong>Detector:</strong> {escape(vuln.detector)}</span>
                <span><strong>CWE:</strong> {escape(vuln.cwe_id)}</span>
                <span><strong>CVSS:</strong> {vuln.cvss_score}</span>
            </div>
            <div class="finding-description">
                <p>{escape(vuln.description)}</p>
            </div>
            {self._generate_code_snippet(vuln)}
            {self._generate_remediation(vuln)}
        </div>
"""

    def _generate_code_snippet(self, vuln: Vulnerability) -> str:
        """Generate code snippet section."""
        if not vuln.code_snippet:
            return ""

        return f"""
            <div class="code-section">
                <h4>Code Snippet</h4>
                <pre><code>{escape(vuln.code_snippet)}</code></pre>
            </div>
"""

    def _generate_remediation(self, vuln: Vulnerability) -> str:
        """Generate remediation section."""
        if not vuln.remediation:
            return ""

        return f"""
            <div class="remediation-section">
                <h4>💡 Remediation</h4>
                <pre>{escape(vuln.remediation)}</pre>
            </div>
"""

    def _generate_footer(self) -> str:
        """Generate report footer."""
        return f"""
    <footer class="footer">
        <div class="container">
            <p>Generated by <strong>MCP Sentinel v{__version__}</strong></p>
            <p>🤖 Enterprise Security Scanner for MCP Servers</p>
            <p><a href="https://github.com/beejak/mcp-sentinel" target="_blank">GitHub Repository</a></p>
        </div>
    </footer>
"""

    def _get_risk_level(self, score: float) -> tuple[str, str]:
        """Get risk level and color from score."""
        if score >= 70:
            return ("CRITICAL RISK", "critical")
        elif score >= 50:
            return ("HIGH RISK", "high")
        elif score >= 30:
            return ("MEDIUM RISK", "medium")
        elif score >= 10:
            return ("LOW RISK", "low")
        else:
            return ("MINIMAL RISK", "info")

    def _get_css(self) -> str:
        """Get embedded CSS styles."""
        return """
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    padding: 20px;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
}

.header {
    background: white;
    border-radius: 15px;
    padding: 30px;
    margin-bottom: 20px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.1);
}

.header h1 {
    color: #667eea;
    font-size: 2.5em;
    margin-bottom: 10px;
}

.subtitle {
    color: #666;
    font-size: 1.1em;
    margin-bottom: 20px;
}

.header-info {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
}

.header-info span {
    color: #555;
}

.summary {
    background: white;
    border-radius: 15px;
    padding: 30px;
    margin-bottom: 20px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.1);
}

.summary h2 {
    color: #333;
    margin-bottom: 20px;
    font-size: 1.8em;
}

.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
}

.summary-card {
    background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
    padding: 25px;
    border-radius: 10px;
    text-align: center;
    transition: transform 0.3s;
}

.summary-card:hover {
    transform: translateY(-5px);
}

.summary-card.risk-card {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
}

.summary-value {
    font-size: 2.5em;
    font-weight: bold;
    margin-bottom: 10px;
}

.summary-label {
    font-size: 0.9em;
    opacity: 0.8;
}

.risk-critical { color: #dc3545; }
.risk-high { color: #fd7e14; }
.risk-medium { color: #ffc107; }
.risk-low { color: #28a745; }
.risk-info { color: #17a2b8; }

.risk-badge {
    margin-top: 10px;
    padding: 5px 15px;
    border-radius: 20px;
    font-size: 0.8em;
    font-weight: bold;
}

.badge {
    padding: 5px 12px;
    border-radius: 15px;
    font-size: 0.85em;
    font-weight: 600;
}

.badge-green { background: #28a745; color: white; }
.badge-red { background: #dc3545; color: white; }
.badge-critical { background: #dc3545; color: white; }
.badge-high { background: #fd7e14; color: white; }
.badge-medium { background: #ffc107; color: #333; }
.badge-low { background: #28a745; color: white; }
.badge-info { background: #17a2b8; color: white; }

.severity-section, .findings-section {
    background: white;
    border-radius: 15px;
    padding: 30px;
    margin-bottom: 20px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.1);
}

.severity-breakdown {
    margin-top: 20px;
}

.severity-item {
    margin-bottom: 15px;
}

.severity-header {
    display: flex;
    justify-content: space-between;
    margin-bottom: 5px;
}

.severity-bar {
    height: 30px;
    background: #f0f0f0;
    border-radius: 15px;
    overflow: hidden;
}

.severity-fill {
    height: 100%;
    transition: width 0.5s ease;
}

.severity-critical { background: linear-gradient(90deg, #dc3545, #c82333); }
.severity-high { background: linear-gradient(90deg, #fd7e14, #e66000); }
.severity-medium { background: linear-gradient(90deg, #ffc107, #e0a800); }
.severity-low { background: linear-gradient(90deg, #28a745, #218838); }
.severity-info { background: linear-gradient(90deg, #17a2b8, #138496); }

.no-findings {
    text-align: center;
    padding: 40px;
}

.no-findings .emoji {
    font-size: 4em;
}

.findings-count {
    color: #666;
    margin-bottom: 20px;
}

.finding-card {
    background: #f8f9fa;
    border-left: 5px solid #667eea;
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 20px;
    transition: box-shadow 0.3s;
}

.finding-card:hover {
    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
}

.finding-header {
    display: flex;
    align-items: center;
    gap: 15px;
    margin-bottom: 15px;
}

.finding-number {
    background: #667eea;
    color: white;
    width: 40px;
    height: 40px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: bold;
}

.finding-title {
    flex: 1;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.finding-title h3 {
    color: #333;
    font-size: 1.3em;
}

.finding-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 15px;
    margin-bottom: 15px;
    font-size: 0.9em;
    color: #666;
}

.finding-description {
    margin-bottom: 15px;
    line-height: 1.6;
}

.code-section, .remediation-section {
    margin-top: 15px;
    background: white;
    border-radius: 8px;
    padding: 15px;
}

.code-section h4, .remediation-section h4 {
    color: #667eea;
    margin-bottom: 10px;
}

pre {
    background: #2d2d2d;
    color: #f8f8f2;
    padding: 15px;
    border-radius: 5px;
    overflow-x: auto;
    font-family: 'Courier New', monospace;
    font-size: 0.9em;
}

.code-section pre {
    background: #2d2d2d;
}

.remediation-section pre {
    background: #f8f9fa;
    color: #333;
    border: 1px solid #ddd;
}

.footer {
    background: white;
    border-radius: 15px;
    padding: 20px;
    text-align: center;
    color: #666;
    box-shadow: 0 10px 30px rgba(0,0,0,0.1);
}

.footer p {
    margin: 5px 0;
}

.footer a {
    color: #667eea;
    text-decoration: none;
}

.footer a:hover {
    text-decoration: underline;
}

@media (max-width: 768px) {
    .summary-grid {
        grid-template-columns: 1fr;
    }

    .header-info {
        flex-direction: column;
    }
}
"""

    def _get_javascript(self) -> str:
        """Get embedded JavaScript for interactivity."""
        return """
// Animate severity bars on load
document.addEventListener('DOMContentLoaded', function() {
    const bars = document.querySelectorAll('.severity-fill');
    bars.forEach(bar => {
        const width = bar.style.width;
        bar.style.width = '0%';
        setTimeout(() => {
            bar.style.width = width;
        }, 100);
    });
});
"""
