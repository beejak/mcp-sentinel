"""
Base provider interface for AI-powered vulnerability detection.

All AI providers (OpenAI, Anthropic, Google, Ollama) must implement this interface.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any


class AIProviderType(Enum):
    """Supported AI provider types."""

    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    GOOGLE = "google"
    OLLAMA = "ollama"


@dataclass
class AIResponse:
    """Standardized AI response containing vulnerability analysis."""

    vulnerabilities: list[dict[str, Any]]
    raw_response: str
    confidence: float
    tokens_used: int
    cost_usd: float
    provider: str
    model: str


@dataclass
class AIProviderConfig:
    """Configuration for AI providers."""

    provider_type: AIProviderType
    api_key: str | None = None
    model: str | None = None
    temperature: float = 0.0  # Deterministic for security analysis
    max_tokens: int = 4096
    timeout: int = 60
    max_retries: int = 3


class BaseAIProvider(ABC):
    """
    Abstract base class for AI vulnerability detection providers.

    All providers must implement:
    - analyze_code: Analyze code for vulnerabilities
    - estimate_cost: Estimate analysis cost
    - is_available: Check if provider is configured and accessible
    """

    def __init__(self, config: AIProviderConfig):
        """
        Initialize the AI provider.

        Args:
            config: Provider configuration
        """
        self.config = config
        self.provider_type = config.provider_type

    @abstractmethod
    async def analyze_code(
        self, code: str, file_path: str, language: str, context: dict[str, Any] | None = None
    ) -> AIResponse:
        """
        Analyze code for security vulnerabilities using AI.

        Args:
            code: Source code to analyze
            file_path: Path to the file being analyzed
            language: Programming language
            context: Additional context (e.g., related files, known patterns)

        Returns:
            AIResponse containing detected vulnerabilities
        """
        pass

    @abstractmethod
    def estimate_cost(self, code: str) -> float:
        """
        Estimate the cost of analyzing the given code.

        Args:
            code: Source code to analyze

        Returns:
            Estimated cost in USD
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the provider is configured and available.

        Returns:
            True if provider can be used
        """
        pass

    @abstractmethod
    def get_model_name(self) -> str:
        """
        Get the model name being used.

        Returns:
            Model name/identifier
        """
        pass

    def _count_tokens(self, text: str) -> int:
        """
        Rough token count estimation (4 chars ≈ 1 token).

        Args:
            text: Text to count tokens for

        Returns:
            Estimated token count
        """
        return len(text) // 4
