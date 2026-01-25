# MCP Sentinel - Maintenance Guide

This guide describes how to maintain, upgrade, and troubleshoot the MCP Sentinel system.

## Routine Maintenance

### Log Rotation
Logs are stored in `/logs` (container) or local directory.
- **Retention**: Default retention is 30 days.
- **Config**: Modify `logging.conf` or `LOG_RETENTION` env var.

### Database Maintenance
- **Backups**: Perform daily backups of the PostgreSQL database.
- **Vacuum**: Run `VACUUM ANALYZE` weekly to optimize query performance.
- **Pruning**: Old scan results (> 90 days) can be archived or deleted if not needed for compliance.

### Dependency Updates
Run the following monthly:
```bash
poetry update
```
Check for breaking changes in `pyproject.toml` before deploying.

## Upgrading

### Docker Upgrade
1. Pull new image: `docker pull mcp-sentinel:latest`
2. Stop container: `docker-compose down`
3. Start container: `docker-compose up -d`

### Manual Upgrade
1. Pull code: `git pull origin main`
2. Update deps: `poetry install`
3. Migrate DB: `alembic upgrade head` (if applicable)

## Troubleshooting Common Issues

### High Memory Usage
- **Cause**: Large file scans or memory leaks in analysis engines.
- **Fix**: Increase container memory limit or exclude large files. Check `ProcessPoolExecutor` settings.

### Slow Scans
- **Cause**: AI engine latency or network issues.
- **Fix**: Use local LLMs (Ollama) or cache results (enabled by default).

### False Positives
- **Fix**: Update detector patterns in `src/mcp_sentinel/detectors`. Add suppression comments in code if supported.

## Support
For critical issues, contact the security engineering team or file a high-priority ticket.
