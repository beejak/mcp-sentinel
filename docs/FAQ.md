# MCP Sentinel - FAQ

## General

**Q: What is MCP Sentinel?**
A: MCP Sentinel is a multi-engine security scanning platform that combines static analysis, SAST, semantic analysis, and AI to detect vulnerabilities in code.

**Q: How does it differ from Bandit or SonarQube?**
A: Sentinel aggregates results from multiple engines (including Bandit) and enhances them with AI and semantic understanding to reduce false positives. It also offers automated remediation.

## Usage

**Q: Can I scan a single file?**
A: Yes. `mcp-sentinel scan /path/to/file.py`

**Q: How do I enable AI analysis?**
A: Set `ENABLE_AI_ANALYSIS=True` in your environment and provide a valid API key (e.g., `ANTHROPIC_API_KEY`).

**Q: Why is the scan taking so long?**
A: AI analysis can be slow. Try disabling it for quick checks: `ENABLE_AI_ANALYSIS=False`. Also, ensure you are not scanning `venv` or `node_modules` (these should be ignored by default).

## Troubleshooting

**Q: "Command not found: mcp-sentinel"**
A: Ensure you have installed the package in your virtual environment: `pip install -e .` or `poetry install`.

**Q: "Database connection failed"**
A: Check your `DATABASE_URL` and ensure PostgreSQL is running and accessible.

**Q: "Rate limit exceeded" (AI)**
A: Check your quota with your AI provider (OpenAI/Anthropic). Implement retry logic or increase limits.

**Q: How do I report a bug?**
A: Please open an issue on our GitHub repository with the log output (run with `LOG_LEVEL=debug`).
