"""
Tests for configuration management.
"""

import os
import pytest
from unittest.mock import patch

from mcp_sentinel.core.config import (
    EngineSettings,
    Settings,
)


class TestEngineSettings:
    """Test EngineSettings configuration."""

    def test_engine_settings_defaults(self):
        engines = EngineSettings()
        assert engines.enable_static is True

    def test_engine_settings_env_override(self):
        with patch.dict(os.environ, {"ENABLE_STATIC_ANALYSIS": "false"}):
            engines = EngineSettings()
            assert engines.enable_static is False


class TestSettings:
    """Test main Settings configuration."""

    def test_settings_defaults(self):
        settings = Settings()
        assert settings.environment == "development"
        assert settings.log_level == "info"
        assert settings.max_workers == 4
        assert settings.cache_ttl == 3600

    def test_settings_engines_sub_config(self):
        settings = Settings()
        assert isinstance(settings.engines, EngineSettings)
        assert settings.engines.enable_static is True

    def test_settings_env_override(self):
        with patch.dict(os.environ, {"ENVIRONMENT": "production", "LOG_LEVEL": "warning"}):
            settings = Settings()
            assert settings.environment == "production"
            assert settings.log_level == "warning"
