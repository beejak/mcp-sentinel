"""
Configuration management for MCP Sentinel.
"""


from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    """Database configuration."""

    url: str = Field(
        default="postgresql+asyncpg://sentinel:sentinel@localhost:5432/mcp_sentinel",
        alias="DATABASE_URL",
    )
    echo: bool = Field(default=False, alias="DB_ECHO")
    pool_size: int = Field(default=5, alias="DB_POOL_SIZE")
    max_overflow: int = Field(default=10, alias="DB_MAX_OVERFLOW")


class RedisSettings(BaseSettings):
    """Redis configuration."""

    url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")
    password: str | None = Field(default=None, alias="REDIS_PASSWORD")


class CelerySettings(BaseSettings):
    """Celery configuration."""

    broker_url: str = Field(default="redis://localhost:6379/1", alias="CELERY_BROKER_URL")
    result_backend: str = Field(default="redis://localhost:6379/2", alias="CELERY_RESULT_BACKEND")
    task_serializer: str = "json"
    result_serializer: str = "json"
    accept_content: list[str] = ["json"]
    timezone: str = "UTC"
    enable_utc: bool = True


class SecuritySettings(BaseSettings):
    """Security configuration."""

    secret_key: str = Field(default="dev-secret-key-change-in-production", alias="SECRET_KEY")
    algorithm: str = Field(default="HS256", alias="ALGORITHM")
    access_token_expire_minutes: int = Field(default=30, alias="ACCESS_TOKEN_EXPIRE_MINUTES")


class AISettings(BaseSettings):
    """AI provider configuration."""

    openai_api_key: str | None = Field(default=None, alias="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4-turbo-preview", alias="OPENAI_MODEL")

    anthropic_api_key: str | None = Field(default=None, alias="ANTHROPIC_API_KEY")
    anthropic_model: str = Field(default="claude-3-5-sonnet-20241022", alias="ANTHROPIC_MODEL")

    google_api_key: str | None = Field(default=None, alias="GOOGLE_API_KEY")
    google_model: str = Field(default="gemini-pro", alias="GOOGLE_MODEL")

    ollama_base_url: str = Field(default="http://localhost:11434", alias="OLLAMA_BASE_URL")
    ollama_model: str = Field(default="llama2", alias="OLLAMA_MODEL")


class EngineSettings(BaseSettings):
    """Analysis engine configuration."""

    enable_static: bool = Field(default=True, alias="ENABLE_STATIC_ANALYSIS")
    enable_semantic: bool = Field(default=True, alias="ENABLE_SEMANTIC_ANALYSIS")
    enable_sast: bool = Field(default=True, alias="ENABLE_SAST")
    enable_ai: bool = Field(default=True, alias="ENABLE_AI_ANALYSIS")
    enable_threat_intel: bool = Field(default=True, alias="ENABLE_THREAT_INTEL")


class Settings(BaseSettings):
    """Main application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Environment
    environment: str = Field(default="development", alias="ENVIRONMENT")
    log_level: str = Field(default="info", alias="LOG_LEVEL")

    # API
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8000, alias="API_PORT")
    api_workers: int = Field(default=4, alias="API_WORKERS")

    # Sub-configs
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    celery: CelerySettings = Field(default_factory=CelerySettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    ai: AISettings = Field(default_factory=AISettings)
    engines: EngineSettings = Field(default_factory=EngineSettings)

    # Performance
    max_workers: int = Field(default=4, alias="MAX_WORKERS")
    cache_ttl: int = Field(default=3600, alias="CACHE_TTL")
    parallel_execution: bool = Field(default=True, alias="PARALLEL_EXECUTION")

    # CORS
    cors_allowed_origins: list[str] = Field(
        default=["http://localhost:3000"], alias="CORS_ALLOWED_ORIGINS"
    )


# Global settings instance
settings = Settings()
