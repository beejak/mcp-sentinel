"""AI provider implementations."""

from mcp_sentinel.engines.ai.providers.base import (
    BaseAIProvider,
    AIProviderType,
    AIProviderConfig,
    AIResponse,
)

try:
    from mcp_sentinel.engines.ai.providers.anthropic_provider import AnthropicProvider
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False


__all__ = [
    "BaseAIProvider",
    "AIProviderType",
    "AIProviderConfig",
    "AIResponse",
]

if ANTHROPIC_AVAILABLE:
    __all__.append("AnthropicProvider")
