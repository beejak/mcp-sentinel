# 🎓 Advanced CLI & Logging Tutorial

This tutorial guides you through the new advanced CLI features and structured logging system introduced in MCP Sentinel v1.0.0-beta.4.

## 🚀 Enhanced CLI Features

The MCP Sentinel CLI has been refactored to be more robust, interactive, and user-friendly.

### 1. Interactive Prompts
If you forget to provide required arguments (like the target directory), the CLI will now politely ask you for them instead of failing immediately.

```bash
$ mcp-sentinel scan
? Target directory to scan: /path/to/project
```

### 2. Structured Logging
We now support comprehensive logging configurations suitable for both local debugging and enterprise CI/CD pipelines.

#### Logging Levels
Control verbosity with `--log-level`. Available levels: `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`.

```bash
# Debug mode for detailed troubleshooting
mcp-sentinel --log-level DEBUG scan .

# Quiet mode (only warnings and errors)
mcp-sentinel --log-level WARN scan .
```

#### File Logging (JSON)
For integration with log aggregators (Splunk, ELK, etc.), you can output structured JSON logs to a file while keeping the console output human-readable.

```bash
mcp-sentinel --log-file scan_logs.json scan .
```

**Example JSON Log Entry:**
```json
{
  "timestamp": "2026-01-24T10:00:00.123456",
  "level": "INFO",
  "logger": "mcp_sentinel.core.scanner",
  "message": "Starting scan of target: .",
  "module": "scanner",
  "line": 45
}
```

### 3. Log Rotation
Log files are automatically rotated when they reach 10MB, keeping up to 5 backup files (`scan_logs.json.1`, `scan_logs.json.2`, etc.) to prevent disk usage issues.

## 🛠️ Integration Examples

### CI/CD Pipeline (GitHub Actions)
```yaml
- name: Security Scan
  run: |
    mcp-sentinel --log-level INFO --log-file sentinel_audit.json scan .
  continue-on-error: true

- name: Upload Logs
  uses: actions/upload-artifact@v3
  with:
    name: scan-logs
    path: sentinel_audit.json
```

### Debugging a Scan
If a scan is failing or producing unexpected results, enable debug logging to trace the execution flow:

```bash
mcp-sentinel --log-level DEBUG scan ./my-project
```

## 📝 Best Practices

1. **Always use `--log-file` in CI/CD** to preserve audit trails.
2. **Use `INFO` (default)** for general usage to avoid cluttering the terminal.
3. **Use `DEBUG`** only when troubleshooting specific issues, as it produces voluminous output.
4. **Monitor log rotation** if you have extremely long-running scans or very verbose logging enabled permanently.
