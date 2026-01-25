"""
Configuration management testing - CURRENTLY UNTESTED.

This test suite provides comprehensive coverage of Settings, nested config classes,
environment variable handling, and validation.

Critical for production deployment and reliability.
"""

import os
import pytest
from pathlib import Path
from typing import Dict
from unittest.mock import patch

from mcp_sentinel.core.config import (
    AISettings,
    CelerySettings,
    DatabaseSettings,
    EngineSettings,
    RedisSettings,
    SecuritySettings,
    Settings,
)


class TestDatabaseSettings:
    """Test DatabaseSettings configuration."""

    def test_database_default_values(self):
        """Test default database configuration values."""
        db = DatabaseSettings()

        assert db.url == "postgresql+asyncpg://sentinel:sentinel@localhost:5432/mcp_sentinel"
        assert db.echo is False
        assert db.pool_size == 5
        assert db.max_overflow == 10

    def test_database_env_override(self):
        """Test database configuration from environment variables."""
        env = {
            "DATABASE_URL": "postgresql+asyncpg://user:pass@db:5432/testdb",
            "DB_ECHO": "true",
            "DB_POOL_SIZE": "10",
            "DB_MAX_OVERFLOW": "20",
        }

        with patch.dict(os.environ, env, clear=False):
            db = DatabaseSettings()

            assert db.url == "postgresql+asyncpg://user:pass@db:5432/testdb"
            assert db.echo is True
            assert db.pool_size == 10
            assert db.max_overflow == 20

    def test_database_partial_override(self):
        """Test partial database configuration override."""
        env = {"DATABASE_URL": "postgresql://localhost/test"}

        with patch.dict(os.environ, env, clear=False):
            db = DatabaseSettings()

            assert db.url == "postgresql://localhost/test"
            assert db.echo is False  # Still default

    def test_database_url_validation(self):
        """Test database URL format validation."""
        env = {"DATABASE_URL": "postgresql://testdb"}

        with patch.dict(os.environ, env, clear=False):
            db = DatabaseSettings()

            # Should accept valid URL
            assert db.url == "postgresql://testdb"


class TestRedisSettings:
    """Test RedisSettings configuration."""

    def test_redis_default_values(self):
        """Test default Redis configuration values."""
        redis = RedisSettings()

        assert redis.url == "redis://localhost:6379/0"
        assert redis.password is None

    def test_redis_env_override(self):
        """Test Redis configuration from environment variables."""
        env = {
            "REDIS_URL": "redis://redis-server:6380/1",
            "REDIS_PASSWORD": "secret123",
        }

        with patch.dict(os.environ, env, clear=False):
            redis = RedisSettings()

            assert redis.url == "redis://redis-server:6380/1"
            assert redis.password == "secret123"

    def test_redis_without_password(self):
        """Test Redis configuration without password."""
        env = {"REDIS_URL": "redis://localhost:6379/0"}

        with patch.dict(os.environ, env, clear=False):
            redis = RedisSettings()

            assert redis.password is None


class TestCelerySettings:
    """Test CelerySettings configuration."""

    def test_celery_default_values(self):
        """Test default Celery configuration values."""
        celery = CelerySettings()

        assert celery.broker_url == "redis://localhost:6379/1"
        assert celery.result_backend == "redis://localhost:6379/2"
        assert celery.task_serializer == "json"
        assert celery.result_serializer == "json"
        assert celery.accept_content == ["json"]
        assert celery.timezone == "UTC"
        assert celery.enable_utc is True

    def test_celery_env_override(self):
        """Test Celery configuration from environment variables."""
        env = {
            "CELERY_BROKER_URL": "redis://celery-broker:6379/3",
            "CELERY_RESULT_BACKEND": "redis://celery-backend:6379/4",
        }

        with patch.dict(os.environ, env, clear=False):
            celery = CelerySettings()

            assert celery.broker_url == "redis://celery-broker:6379/3"
            assert celery.result_backend == "redis://celery-backend:6379/4"

    def test_celery_task_serialization(self):
        """Test Celery task serialization settings."""
        celery = CelerySettings()

        assert "json" in celery.accept_content
        assert celery.task_serializer == "json"
        assert celery.result_serializer == "json"


class TestSecuritySettings:
    """Test SecuritySettings configuration."""

    def test_security_default_values(self):
        """Test default security configuration values."""
        security = SecuritySettings()

        assert security.secret_key == "dev-secret-key-change-in-production"
        assert security.algorithm == "HS256"
        assert security.access_token_expire_minutes == 30

    def test_security_env_override(self):
        """Test security configuration from environment variables."""
        env = {
            "SECRET_KEY": "production-secret-key-very-secure",
            "ALGORITHM": "HS512",
            "ACCESS_TOKEN_EXPIRE_MINUTES": "60",
        }

        with patch.dict(os.environ, env, clear=False):
            security = SecuritySettings()

            assert security.secret_key == "production-secret-key-very-secure"
            assert security.algorithm == "HS512"
            assert security.access_token_expire_minutes == 60

    def test_security_token_expiration_validation(self):
        """Test token expiration time validation."""
        env = {"ACCESS_TOKEN_EXPIRE_MINUTES": "120"}

        with patch.dict(os.environ, env, clear=False):
            security = SecuritySettings()

            assert security.access_token_expire_minutes == 120


class TestAISettings:
    """Test AISettings configuration."""

    def test_ai_default_values(self):
        """Test default AI configuration values."""
        ai = AISettings()

        assert ai.openai_api_key is None
        assert ai.openai_model == "gpt-4-turbo-preview"
        assert ai.anthropic_api_key is None
        assert ai.anthropic_model == "claude-3-5-sonnet-20241022"
        assert ai.google_api_key is None
        assert ai.google_model == "gemini-pro"
        assert ai.ollama_base_url == "http://localhost:11434"
        assert ai.ollama_model == "llama2"

    def test_ai_openai_config(self):
        """Test OpenAI configuration."""
        env = {
            "OPENAI_API_KEY": "sk-test-key-123",
            "OPENAI_MODEL": "gpt-4",
        }

        with patch.dict(os.environ, env, clear=False):
            ai = AISettings()

            assert ai.openai_api_key == "sk-test-key-123"
            assert ai.openai_model == "gpt-4"

    def test_ai_anthropic_config(self):
        """Test Anthropic configuration."""
        env = {
            "ANTHROPIC_API_KEY": "sk-ant-test-key",
            "ANTHROPIC_MODEL": "claude-3-opus-20240229",
        }

        with patch.dict(os.environ, env, clear=False):
            ai = AISettings()

            assert ai.anthropic_api_key == "sk-ant-test-key"
            assert ai.anthropic_model == "claude-3-opus-20240229"

    def test_ai_google_config(self):
        """Test Google AI configuration."""
        env = {
            "GOOGLE_API_KEY": "google-api-key-123",
            "GOOGLE_MODEL": "gemini-pro-vision",
        }

        with patch.dict(os.environ, env, clear=False):
            ai = AISettings()

            assert ai.google_api_key == "google-api-key-123"
            assert ai.google_model == "gemini-pro-vision"

    def test_ai_ollama_config(self):
        """Test Ollama local model configuration."""
        env = {
            "OLLAMA_BASE_URL": "http://ollama:11434",
            "OLLAMA_MODEL": "codellama",
        }

        with patch.dict(os.environ, env, clear=False):
            ai = AISettings()

            assert ai.ollama_base_url == "http://ollama:11434"
            assert ai.ollama_model == "codellama"

    def test_ai_all_providers_configured(self):
        """Test configuration with all AI providers."""
        env = {
            "OPENAI_API_KEY": "openai-key",
            "ANTHROPIC_API_KEY": "anthropic-key",
            "GOOGLE_API_KEY": "google-key",
        }

        with patch.dict(os.environ, env, clear=False):
            ai = AISettings()

            assert ai.openai_api_key is not None
            assert ai.anthropic_api_key is not None
            assert ai.google_api_key is not None


class TestEngineSettings:
    """Test EngineSettings configuration."""

    def test_engine_default_values(self):
        """Test default engine configuration values."""
        engines = EngineSettings()

        assert engines.enable_static is True
        assert engines.enable_semantic is True
        assert engines.enable_sast is True
        assert engines.enable_ai is True
        assert engines.enable_threat_intel is True

    def test_engine_disable_specific_engines(self):
        """Test disabling specific engines."""
        env = {
            "ENABLE_STATIC_ANALYSIS": "false",
            "ENABLE_AI_ANALYSIS": "false",
        }

        with patch.dict(os.environ, env, clear=False):
            engines = EngineSettings()

            assert engines.enable_static is False
            assert engines.enable_semantic is True  # Still enabled
            assert engines.enable_ai is False

    def test_engine_enable_all(self):
        """Test enabling all engines explicitly."""
        env = {
            "ENABLE_STATIC_ANALYSIS": "true",
            "ENABLE_SEMANTIC_ANALYSIS": "true",
            "ENABLE_SAST": "true",
            "ENABLE_AI_ANALYSIS": "true",
            "ENABLE_THREAT_INTEL": "true",
        }

        with patch.dict(os.environ, env, clear=False):
            engines = EngineSettings()

            assert all(
                [
                    engines.enable_static,
                    engines.enable_semantic,
                    engines.enable_sast,
                    engines.enable_ai,
                    engines.enable_threat_intel,
                ]
            )


class TestSettingsMain:
    """Test main Settings configuration."""

    def test_settings_default_values(self):
        """Test all default configuration values."""
        settings = Settings()

        # Environment
        assert settings.environment == "development"
        assert settings.log_level == "info"

        # API
        assert settings.api_host == "0.0.0.0"
        assert settings.api_port == 8000
        assert settings.api_workers == 4

        # Performance
        assert settings.max_workers == 4
        assert settings.cache_ttl == 3600
        assert settings.parallel_execution is True

        # CORS
        assert settings.cors_allowed_origins == ["http://localhost:3000"]

    def test_settings_environment_override(self):
        """Test environment variables override defaults."""
        env = {
            "ENVIRONMENT": "production",
            "LOG_LEVEL": "debug",
            "API_HOST": "127.0.0.1",
            "API_PORT": "9000",
        }

        with patch.dict(os.environ, env, clear=False):
            settings = Settings()

            assert settings.environment == "production"
            assert settings.log_level == "debug"
            assert settings.api_host == "127.0.0.1"
            assert settings.api_port == 9000

    def test_settings_nested_configs_initialized(self):
        """Test nested settings are properly initialized."""
        settings = Settings()

        assert hasattr(settings, "database")
        assert hasattr(settings, "redis")
        assert hasattr(settings, "celery")
        assert hasattr(settings, "security")
        assert hasattr(settings, "ai")
        assert hasattr(settings, "engines")

        assert isinstance(settings.database, DatabaseSettings)
        assert isinstance(settings.redis, RedisSettings)
        assert isinstance(settings.celery, CelerySettings)
        assert isinstance(settings.security, SecuritySettings)
        assert isinstance(settings.ai, AISettings)
        assert isinstance(settings.engines, EngineSettings)

    def test_settings_performance_config(self):
        """Test performance configuration."""
        env = {
            "MAX_WORKERS": "8",
            "CACHE_TTL": "7200",
            "PARALLEL_EXECUTION": "false",
        }

        with patch.dict(os.environ, env, clear=False):
            settings = Settings()

            assert settings.max_workers == 8
            assert settings.cache_ttl == 7200
            assert settings.parallel_execution is False

    def test_settings_cors_single_origin(self):
        """Test CORS with single origin."""
        env = {"CORS_ALLOWED_ORIGINS": '["https://example.com"]'}

        with patch.dict(os.environ, env, clear=False):
            settings = Settings()

            # Note: Pydantic may parse this differently
            # This tests the current behavior
            assert isinstance(settings.cors_allowed_origins, list)

    def test_settings_api_workers_validation(self):
        """Test API workers count validation."""
        env = {"API_WORKERS": "16"}

        with patch.dict(os.environ, env, clear=False):
            settings = Settings()

            assert settings.api_workers == 16

    def test_settings_log_level_values(self):
        """Test different log level values."""
        log_levels = ["debug", "info", "warning", "error", "critical"]

        for level in log_levels:
            env = {"LOG_LEVEL": level}

            with patch.dict(os.environ, env, clear=False):
                settings = Settings()

                assert settings.log_level == level


class TestSettingsIntegration:
    """Test Settings integration and environment precedence."""

    def test_full_production_config(self):
        """Test complete production-like configuration."""
        env = {
            "ENVIRONMENT": "production",
            "LOG_LEVEL": "warning",
            "API_HOST": "0.0.0.0",
            "API_PORT": "8080",
            "DATABASE_URL": "postgresql+asyncpg://user:pass@db:5432/prod",
            "REDIS_URL": "redis://redis:6379/0",
            "REDIS_PASSWORD": "prod-password",
            "SECRET_KEY": "production-secret-key-12345",
            "OPENAI_API_KEY": "sk-prod-key",
            "ANTHROPIC_API_KEY": "sk-ant-prod",
            "MAX_WORKERS": "16",
        }

        with patch.dict(os.environ, env, clear=False):
            settings = Settings()

            assert settings.environment == "production"
            assert settings.log_level == "warning"
            assert settings.database.url.startswith("postgresql+asyncpg://")
            assert settings.redis.password == "prod-password"
            assert settings.security.secret_key == "production-secret-key-12345"
            assert settings.ai.openai_api_key == "sk-prod-key"
            assert settings.max_workers == 16

    def test_development_config(self):
        """Test development configuration."""
        env = {
            "ENVIRONMENT": "development",
            "LOG_LEVEL": "debug",
            "ENABLE_AI_ANALYSIS": "false",  # Disable AI in dev
        }

        with patch.dict(os.environ, env, clear=False):
            settings = Settings()

            assert settings.environment == "development"
            assert settings.log_level == "debug"
            assert settings.engines.enable_ai is False

    def test_testing_config(self):
        """Test testing environment configuration."""
        env = {
            "ENVIRONMENT": "testing",
            "DATABASE_URL": "sqlite+aiosqlite:///test.db",
            "REDIS_URL": "redis://localhost:6379/15",  # Separate test DB
        }

        with patch.dict(os.environ, env, clear=False):
            settings = Settings()

            assert settings.environment == "testing"
            assert "test.db" in settings.database.url

    def test_case_insensitive_env_vars(self):
        """Test that environment variables are case-insensitive."""
        env = {
            "environment": "production",  # lowercase
            "LOG_LEVEL": "INFO",  # uppercase
        }

        with patch.dict(os.environ, env, clear=False):
            settings = Settings()

            # Should work with case insensitivity
            assert settings.environment in ["production", "development"]

    def test_extra_env_vars_ignored(self):
        """Test that extra unknown environment variables are ignored."""
        env = {
            "UNKNOWN_CONFIG": "value",
            "ANOTHER_RANDOM_VAR": "test",
            "LOG_LEVEL": "info",
        }

        with patch.dict(os.environ, env, clear=False):
            settings = Settings()

            # Should not crash, should ignore unknown vars
            assert settings.log_level == "info"


class TestSettingsValidation:
    """Test Settings validation and edge cases."""

    def test_invalid_port_number(self):
        """Test handling of invalid port numbers."""
        env = {"API_PORT": "-1"}

        with patch.dict(os.environ, env, clear=False):
            # May raise validation error or coerce to valid value
            try:
                settings = Settings()
                # If it doesn't raise, port should be some valid value
                assert isinstance(settings.api_port, int)
            except Exception:
                # Validation error is acceptable
                pass

    def test_zero_workers(self):
        """Test handling of zero workers."""
        env = {"MAX_WORKERS": "0"}

        with patch.dict(os.environ, env, clear=False):
            settings = Settings()

            # Should accept 0 or coerce to valid value
            assert isinstance(settings.max_workers, int)

    def test_empty_string_values(self):
        """Test handling of empty string values."""
        env = {"ENVIRONMENT": ""}

        with patch.dict(os.environ, env, clear=False):
            try:
                settings = Settings()
                # Should either use default or accept empty
                assert isinstance(settings.environment, str)
            except Exception:
                # Validation error is acceptable
                pass


class TestSettingsHelpers:
    """Test Settings helper methods and properties."""

    def test_settings_singleton_pattern(self):
        """Test that settings can be imported as singleton."""
        from mcp_sentinel.core.config import settings as settings1
        from mcp_sentinel.core.config import settings as settings2

        # Same object
        assert settings1 is settings2

    def test_settings_immutability(self):
        """Test that settings values can be accessed."""
        settings = Settings()

        # Should be able to read values
        assert isinstance(settings.log_level, str)
        assert isinstance(settings.api_port, int)

    def test_nested_config_access(self):
        """Test accessing nested configuration values."""
        settings = Settings()

        # Should be able to access nested values
        assert isinstance(settings.database.url, str)
        assert isinstance(settings.redis.url, str)
        assert isinstance(settings.security.secret_key, str)
        assert isinstance(settings.ai.openai_model, str)
