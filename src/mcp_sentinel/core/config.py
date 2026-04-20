"""
Configuration management for MCP Sentinel.
"""

from __future__ import annotations  # Python 3.9 compatibility for list[str] syntax

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class EngineSettings(BaseSettings):  # type: ignore[misc]
    """Analysis engine configuration."""

    enable_static: bool = Field(default=True, alias="ENABLE_STATIC_ANALYSIS")


class Settings(BaseSettings):  # type: ignore[misc]
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

    # Sub-configs
    engines: EngineSettings = Field(default_factory=EngineSettings)

    # Performance
    max_workers: int = Field(default=4, alias="MAX_WORKERS")
    cache_ttl: int = Field(default=3600, alias="CACHE_TTL")


# Global settings instance
settings = Settings()
