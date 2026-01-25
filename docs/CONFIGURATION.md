# MCP Sentinel - Configuration Guide

This guide details all available configuration options for MCP Sentinel. Configuration can be managed via environment variables or a `.env` file.

## Environment Variables

### General Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `ENVIRONMENT` | `development` | execution environment (development/production/testing) |
| `LOG_LEVEL` | `info` | Logging verbosity (debug/info/warning/error) |

### API Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `API_HOST` | `0.0.0.0` | Host interface to bind the API server |
| `API_PORT` | `8000` | Port to listen on |
| `API_WORKERS` | `4` | Number of worker processes |

### Database Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://...` | Connection string for PostgreSQL |
| `DB_ECHO` | `False` | Enable SQL query logging |
| `DB_POOL_SIZE` | `5` | Connection pool size |
| `DB_MAX_OVERFLOW` | `10` | Max overflow connections |

### Redis & Celery

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `CELERY_BROKER_URL` | `redis://localhost:6379/1` | Celery broker URL |
| `CELERY_RESULT_BACKEND` | `redis://localhost:6379/2` | Celery result backend |

### AI Provider Settings

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | API Key for OpenAI |
| `OPENAI_MODEL` | Model to use (default: `gpt-4-turbo-preview`) |
| `ANTHROPIC_API_KEY` | API Key for Anthropic |
| `ANTHROPIC_MODEL` | Model to use (default: `claude-3-5-sonnet-20241022`) |
| `GOOGLE_API_KEY` | API Key for Google Gemini |
| `OLLAMA_BASE_URL` | Base URL for Ollama (default: `http://localhost:11434`) |

### Engine Settings

Toggle specific analysis engines.

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_STATIC_ANALYSIS` | `True` | Enable regex/pattern matching |
| `ENABLE_SEMANTIC_ANALYSIS` | `True` | Enable AST/Data flow analysis |
| `ENABLE_SAST` | `True` | Enable external SAST tools (Bandit, etc.) |
| `ENABLE_AI_ANALYSIS` | `True` | Enable LLM-based analysis |
| `ENABLE_THREAT_INTEL` | `True` | Enable threat intelligence lookups |

## Security Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | *dev-secret* | Secret key for JWT signing (CHANGE IN PROD!) |
| `ALGORITHM` | `HS256` | JWT signing algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Token expiration time |

## Example .env File

```bash
ENVIRONMENT=production
LOG_LEVEL=warning

API_PORT=8080

DATABASE_URL=postgresql+asyncpg://user:pass@db:5432/sentinel

ANTHROPIC_API_KEY=sk-ant-...
ENABLE_AI_ANALYSIS=True
```
