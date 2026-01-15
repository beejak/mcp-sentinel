"""
Anthropic Claude provider for AI-powered vulnerability detection.

Recommended provider for code security analysis due to:
- Excellent code understanding
- 200k context window
- Strong reasoning capabilities
- Cost-effective ($3/1M input, $15/1M output)
"""

import json
import os
from typing import Any

try:
    from anthropic import AsyncAnthropic

    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

from mcp_sentinel.engines.ai.providers.base import (
    AIProviderConfig,
    AIResponse,
    BaseAIProvider,
)


class AnthropicProvider(BaseAIProvider):
    """
    Anthropic Claude provider for vulnerability detection.

    Uses Claude 3.5 Sonnet for optimal balance of speed and accuracy.
    """

    # Model costs (per 1M tokens)
    INPUT_COST_PER_1M = 3.00  # $3 per 1M input tokens
    OUTPUT_COST_PER_1M = 15.00  # $15 per 1M output tokens

    DEFAULT_MODEL = "claude-3-5-sonnet-20241022"

    def __init__(self, config: AIProviderConfig):
        """
        Initialize Anthropic provider.

        Args:
            config: Provider configuration
        """
        super().__init__(config)

        if not ANTHROPIC_AVAILABLE:
            raise ImportError(
                "anthropic package not installed. " "Install with: pip install anthropic"
            )

        # Get API key from config or environment
        api_key = config.api_key or os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                "Anthropic API key not found. Set ANTHROPIC_API_KEY environment variable "
                "or provide in config"
            )

        self.client = AsyncAnthropic(api_key=api_key)
        self.model = config.model or self.DEFAULT_MODEL

    async def analyze_code(
        self, code: str, file_path: str, language: str, context: dict[str, Any] | None = None
    ) -> AIResponse:
        """
        Analyze code using Claude for security vulnerabilities.

        Args:
            code: Source code to analyze
            file_path: Path to the file
            language: Programming language
            context: Additional context

        Returns:
            AIResponse with detected vulnerabilities
        """
        # Build prompt
        system_prompt = self._build_system_prompt()
        user_prompt = self._build_user_prompt(code, file_path, language, context)

        try:
            # Call Claude API
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )

            # Extract response
            content = response.content[0].text
            input_tokens = response.usage.input_tokens
            output_tokens = response.usage.output_tokens
            total_tokens = input_tokens + output_tokens

            # Calculate cost
            cost = (input_tokens / 1_000_000) * self.INPUT_COST_PER_1M + (
                output_tokens / 1_000_000
            ) * self.OUTPUT_COST_PER_1M

            # Parse JSON response
            vulnerabilities = self._parse_response(content)

            return AIResponse(
                vulnerabilities=vulnerabilities,
                raw_response=content,
                confidence=0.85,  # Claude has high confidence
                tokens_used=total_tokens,
                cost_usd=cost,
                provider="anthropic",
                model=self.model,
            )

        except Exception as e:
            # Return empty response on error
            return AIResponse(
                vulnerabilities=[],
                raw_response=f"Error: {str(e)}",
                confidence=0.0,
                tokens_used=0,
                cost_usd=0.0,
                provider="anthropic",
                model=self.model,
            )

    def estimate_cost(self, code: str) -> float:
        """
        Estimate cost of analyzing code.

        Args:
            code: Source code

        Returns:
            Estimated cost in USD
        """
        # Rough estimate: prompt + code + expected response
        input_tokens = (
            self._count_tokens(self._build_system_prompt()) + self._count_tokens(code) + 500
        )
        output_tokens = 1000  # Estimated response size

        cost = (input_tokens / 1_000_000) * self.INPUT_COST_PER_1M + (
            output_tokens / 1_000_000
        ) * self.OUTPUT_COST_PER_1M
        return cost

    def is_available(self) -> bool:
        """
        Check if Anthropic provider is available.

        Returns:
            True if API key is configured
        """
        return ANTHROPIC_AVAILABLE and (
            self.config.api_key is not None or os.getenv("ANTHROPIC_API_KEY") is not None
        )

    def get_model_name(self) -> str:
        """Get model name."""
        return self.model

    def _build_system_prompt(self) -> str:
        """Build system prompt for Claude."""
        return """You are a security expert analyzing code for vulnerabilities.

Your task is to identify security vulnerabilities including:
- SQL injection
- Command injection
- Code injection (eval, exec)
- Cross-site scripting (XSS)
- Path traversal
- Insecure secrets/credentials
- Prompt injection (AI-specific)
- Supply chain vulnerabilities
- Configuration security issues

For each vulnerability found, provide:
1. type: Vulnerability type (e.g., "SQL_INJECTION", "XSS", "COMMAND_INJECTION")
2. severity: "CRITICAL", "HIGH", "MEDIUM", or "LOW"
3. confidence: "HIGH", "MEDIUM", or "LOW"
4. line: Line number where vulnerability occurs
5. description: Clear explanation of the vulnerability
6. remediation: Specific steps to fix the issue
7. cwe_id: Relevant CWE identifier (e.g., "CWE-89")

Output ONLY a JSON array of vulnerabilities. No markdown, no code blocks, just the JSON array.
If no vulnerabilities found, return an empty array: []

Example format:
[
  {
    "type": "SQL_INJECTION",
    "severity": "CRITICAL",
    "confidence": "HIGH",
    "line": 42,
    "description": "User input directly concatenated into SQL query",
    "remediation": "Use parameterized queries with placeholders",
    "cwe_id": "CWE-89"
  }
]

Only report real vulnerabilities with high confidence. Avoid false positives."""

    def _build_user_prompt(
        self, code: str, file_path: str, language: str, context: dict[str, Any] | None
    ) -> str:
        """Build user prompt with code to analyze."""
        prompt = f"""Analyze this {language} code for security vulnerabilities:

File: {file_path}

Code:
```{language}
{code}
```

Return JSON array of vulnerabilities found."""

        if context:
            prompt += f"\n\nAdditional context: {json.dumps(context)}"

        return prompt

    def _parse_response(self, response: str) -> list[dict[str, Any]]:
        """
        Parse Claude's JSON response.

        Args:
            response: Raw response text

        Returns:
            List of vulnerability dictionaries
        """
        try:
            # Try to find JSON array in response
            response = response.strip()

            # Remove markdown code blocks if present
            if response.startswith("```"):
                lines = response.split("\n")
                # Find actual JSON content
                json_lines = []
                in_code_block = False
                for line in lines:
                    if line.startswith("```"):
                        in_code_block = not in_code_block
                        continue
                    if in_code_block or (not line.startswith("```")):
                        json_lines.append(line)
                response = "\n".join(json_lines).strip()

            # Parse JSON
            vulnerabilities = json.loads(response)

            if not isinstance(vulnerabilities, list):
                return []

            return vulnerabilities

        except json.JSONDecodeError:
            # Failed to parse, return empty
            return []
