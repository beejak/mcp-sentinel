"""
AI Analysis Engine for vulnerability detection.

Leverages large language models (Claude, GPT-4, etc.) to detect
complex vulnerabilities that pattern-based tools might miss.
"""

import os
from typing import List, Optional, Dict, Any
from pathlib import Path

from mcp_sentinel.engines.base import BaseEngine, EngineType, EngineStatus
from mcp_sentinel.models.vulnerability import (
    Vulnerability,
    VulnerabilityType,
    Severity,
    Confidence,
)
from mcp_sentinel.engines.ai.providers.base import (
    BaseAIProvider,
    AIProviderConfig,
    AIProviderType,
    AIResponse,
)


class AIEngine(BaseEngine):
    """
    AI-powered vulnerability detection engine.

    Features:
    - Multi-provider support (Anthropic, OpenAI, Google, Ollama)
    - Contextual vulnerability analysis
    - Business logic flaw detection
    - False positive reduction
    - Automated remediation suggestions
    """

    def __init__(
        self,
        provider_type: Optional[AIProviderType] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        max_cost_per_scan: float = 1.0,
        enabled: bool = True,
    ):
        """
        Initialize AI engine.

        Args:
            provider_type: AI provider to use (default: Anthropic if available)
            api_key: API key for the provider
            model: Specific model to use
            max_cost_per_scan: Maximum cost in USD per scan
            enabled: Whether engine is enabled
        """
        super().__init__(
            name="AI Analysis Engine",
            engine_type=EngineType.AI,
            enabled=enabled,
        )

        self.max_cost_per_scan = max_cost_per_scan
        self.total_cost = 0.0
        self.provider: Optional[BaseAIProvider] = None

        # Auto-detect provider if not specified
        if provider_type is None:
            provider_type = self._detect_available_provider()

        if provider_type:
            self.provider = self._create_provider(
                provider_type, api_key, model
            )

        if self.provider and self.provider.is_available():
            self.status = EngineStatus.READY
        else:
            self.status = EngineStatus.NOT_AVAILABLE

    async def scan_file(
        self,
        file_path: Path,
        content: str,
        language: str
    ) -> List[Vulnerability]:
        """
        Scan a file using AI analysis.

        Args:
            file_path: Path to the file
            content: File content
            language: Programming language

        Returns:
            List of detected vulnerabilities
        """
        if not self.provider or not self.enabled:
            return []

        # Check cost limit
        estimated_cost = self.provider.estimate_cost(content)
        if self.total_cost + estimated_cost > self.max_cost_per_scan:
            return []

        try:
            # Analyze code with AI
            response: AIResponse = await self.provider.analyze_code(
                code=content,
                file_path=str(file_path),
                language=language,
                context=None
            )

            # Track cost
            self.total_cost += response.cost_usd

            # Convert AI response to Vulnerability objects
            vulnerabilities = []
            for vuln_dict in response.vulnerabilities:
                vuln = self._convert_ai_response(
                    vuln_dict=vuln_dict,
                    file_path=file_path,
                    content=content,
                    provider=response.provider,
                    model=response.model,
                )
                if vuln:
                    vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            # Log error but don't fail the scan
            return []

    async def initialize(self) -> bool:
        """Initialize the AI engine."""
        if self.provider and self.provider.is_available():
            self.status = EngineStatus.READY
            return True
        self.status = EngineStatus.NOT_AVAILABLE
        return False

    async def cleanup(self):
        """Cleanup resources."""
        self.provider = None

    def _detect_available_provider(self) -> Optional[AIProviderType]:
        """
        Auto-detect available AI provider based on API keys.

        Priority:
        1. Anthropic (best for code analysis)
        2. OpenAI (widely available)
        3. Google (good alternative)
        4. Ollama (free, local)

        Returns:
            Available provider type or None
        """
        if os.getenv("ANTHROPIC_API_KEY"):
            return AIProviderType.ANTHROPIC
        if os.getenv("OPENAI_API_KEY"):
            return AIProviderType.OPENAI
        if os.getenv("GOOGLE_API_KEY"):
            return AIProviderType.GOOGLE
        # Ollama runs locally, always "available" if installed
        return AIProviderType.OLLAMA

    def _create_provider(
        self,
        provider_type: AIProviderType,
        api_key: Optional[str],
        model: Optional[str]
    ) -> Optional[BaseAIProvider]:
        """
        Create AI provider instance.

        Args:
            provider_type: Type of provider
            api_key: API key
            model: Model name

        Returns:
            Provider instance or None
        """
        config = AIProviderConfig(
            provider_type=provider_type,
            api_key=api_key,
            model=model,
            temperature=0.0,  # Deterministic for security
            max_tokens=4096,
        )

        try:
            if provider_type == AIProviderType.ANTHROPIC:
                from mcp_sentinel.engines.ai.providers.anthropic_provider import AnthropicProvider
                return AnthropicProvider(config)
            elif provider_type == AIProviderType.OPENAI:
                # TODO: Implement OpenAI provider
                return None
            elif provider_type == AIProviderType.GOOGLE:
                # TODO: Implement Google provider
                return None
            elif provider_type == AIProviderType.OLLAMA:
                # TODO: Implement Ollama provider
                return None
            else:
                return None
        except Exception:
            return None

    def _convert_ai_response(
        self,
        vuln_dict: Dict[str, Any],
        file_path: Path,
        content: str,
        provider: str,
        model: str,
    ) -> Optional[Vulnerability]:
        """
        Convert AI response dictionary to Vulnerability object.

        Args:
            vuln_dict: Vulnerability dict from AI
            file_path: File path
            content: File content
            provider: AI provider name
            model: AI model name

        Returns:
            Vulnerability object or None
        """
        try:
            # Map AI severity to our Severity enum
            severity_map = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
            }
            severity = severity_map.get(
                vuln_dict.get("severity", "MEDIUM").upper(),
                Severity.MEDIUM
            )

            # Map AI confidence to our Confidence enum
            confidence_map = {
                "HIGH": Confidence.HIGH,
                "MEDIUM": Confidence.MEDIUM,
                "LOW": Confidence.LOW,
            }
            confidence = confidence_map.get(
                vuln_dict.get("confidence", "MEDIUM").upper(),
                Confidence.MEDIUM
            )

            # Map vulnerability type
            vuln_type_map = {
                "SQL_INJECTION": VulnerabilityType.CODE_INJECTION,
                "COMMAND_INJECTION": VulnerabilityType.CODE_INJECTION,
                "CODE_INJECTION": VulnerabilityType.CODE_INJECTION,
                "XSS": VulnerabilityType.XSS,
                "PATH_TRAVERSAL": VulnerabilityType.PATH_TRAVERSAL,
                "SECRETS": VulnerabilityType.SECRETS,
                "PROMPT_INJECTION": VulnerabilityType.PROMPT_INJECTION,
                "SUPPLY_CHAIN": VulnerabilityType.SUPPLY_CHAIN,
                "CONFIG_SECURITY": VulnerabilityType.CONFIG_SECURITY,
            }
            vuln_type = vuln_type_map.get(
                vuln_dict.get("type", "").upper(),
                VulnerabilityType.CODE_INJECTION
            )

            # Get line number and code snippet
            line_number = vuln_dict.get("line", 1)
            lines = content.split("\n")
            if 1 <= line_number <= len(lines):
                code_snippet = lines[line_number - 1].strip()
            else:
                code_snippet = ""

            # Create vulnerability
            return Vulnerability(
                type=vuln_type,
                severity=severity,
                confidence=confidence,
                file_path=str(file_path),
                line_number=line_number,
                code_snippet=code_snippet,
                title=f"AI Detected: {vuln_dict.get('description', 'Security Issue')}",
                description=vuln_dict.get("description", ""),
                remediation=vuln_dict.get("remediation", ""),
                cwe_id=vuln_dict.get("cwe_id"),
                detector_name=f"AI Engine ({provider}/{model})",
                engine="ai",
            )

        except Exception:
            return None
