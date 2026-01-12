//! OpenAI LLM Provider
//!
//! Commercial API provider using GPT-3.5-turbo, GPT-4, and GPT-4-turbo models
//! for security-focused code analysis.
//!
//! # Features
//!
//! - Support for GPT-3.5-turbo, GPT-4, GPT-4-turbo, and GPT-4o models
//! - JSON mode for structured vulnerability output
//! - Function calling support (future)
//! - Low temperature for consistent security analysis
//! - Comprehensive error handling with API-specific guidance
//! - Automatic token counting and cost tracking
//!
//! # Configuration
//!
//! ```yaml
//! ai:
//!   providers:
//!     openai:
//!       model: "gpt-3.5-turbo"  # or gpt-4, gpt-4-turbo, gpt-4o
//!       api_key_env: "OPENAI_API_KEY"
//!       temperature: 0.1
//!       max_tokens: 2000
//! ```
//!
//! # Environment Variables
//!
//! - `OPENAI_API_KEY`: Your OpenAI API key (required)
//!
//! # Cost Structure (as of 2025)
//!
//! - GPT-3.5-turbo: $0.0005/1K input tokens, $0.0015/1K output tokens
//! - GPT-4-turbo: $0.01/1K input tokens, $0.03/1K output tokens
//! - GPT-4o: $0.005/1K input tokens, $0.015/1K output tokens
//! - GPT-4: $0.03/1K input tokens, $0.06/1K output tokens
//!
//! # Examples
//!
//! ```rust
//! use mcp_sentinel::providers::openai::{OpenAIProvider, OpenAISettings};
//!
//! # #[tokio::main]
//! # async fn main() -> anyhow::Result<()> {
//! let settings = OpenAISettings {
//!     model: "gpt-4-turbo".to_string(),
//!     api_key_env: "OPENAI_API_KEY".to_string(),
//!     temperature: 0.1,
//!     max_tokens: 2000,
//! };
//!
//! let provider = OpenAIProvider::new(&settings)?;
//! // Use provider for analysis
//! # Ok(())
//! # }
//! ```

use super::{AnalysisContext, LLMProvider, OpenAISettings};
use crate::models::{
    ai_finding::*,
    vulnerability::{Severity, Vulnerability},
    VulnerabilityType,
};
use anyhow::{Context, Result};
use async_openai::{
    config::OpenAIConfig,
    types::{
        ChatCompletionRequestMessage, ChatCompletionRequestSystemMessageArgs,
        ChatCompletionRequestUserMessageArgs, CreateChatCompletionRequestArgs, Role,
    },
    Client,
};
use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;
use tracing::{debug, error, info, instrument, warn};

/// OpenAI provider for GPT-based vulnerability analysis
///
/// This provider uses OpenAI's GPT models (3.5-turbo, 4, 4-turbo, 4o) for
/// AI-powered security analysis. It provides structured vulnerability detection
/// with confidence scores and actionable remediation guidance.
///
/// # Privacy
///
/// Code snippets are sent to OpenAI's API. For sensitive codebases, consider:
/// - Using Ollama or other local providers
/// - Limiting code context size
/// - Reviewing OpenAI's data usage policy
///
/// # Rate Limiting
///
/// OpenAI has rate limits based on your tier:
/// - Free tier: 3 RPM (requests per minute)
/// - Tier 1: 60 RPM
/// - Tier 2: 3500 RPM
/// - Tier 3: 10000 RPM
///
/// The AI engine handles rate limiting and retries automatically.
pub struct OpenAIProvider {
    client: Client<OpenAIConfig>,
    settings: OpenAISettings,
    cost_per_1k_input: f64,
    cost_per_1k_output: f64,
}

impl OpenAIProvider {
    /// Create a new OpenAI provider
    ///
    /// # Arguments
    ///
    /// * `settings` - OpenAI configuration settings
    ///
    /// # Returns
    ///
    /// Initialized OpenAI provider
    ///
    /// # Errors
    ///
    /// - API key not found in environment
    /// - API key invalid format
    /// - Network connection issues (during health check)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mcp_sentinel::providers::openai::{OpenAIProvider, OpenAISettings};
    ///
    /// # #[tokio::main]
    /// # async fn main() -> anyhow::Result<()> {
    /// let settings = OpenAISettings::default();
    /// let provider = OpenAIProvider::new(&settings)?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(settings), fields(model = %settings.model))]
    pub fn new(settings: &OpenAISettings) -> Result<Self> {
        info!("Initializing OpenAI provider");

        // Get API key from environment
        let api_key = std::env::var(&settings.api_key_env).context(format!(
            "OpenAI API key not found in environment variable: {}\n\n\
            To set your API key:\n\
              export {}=sk-...\n\n\
            To get an API key:\n\
              1. Visit https://platform.openai.com/api-keys\n\
              2. Sign up or log in\n\
              3. Click 'Create new secret key'\n\
              4. Copy the key (starts with 'sk-')",
            settings.api_key_env, settings.api_key_env
        ))?;

        // Validate API key format
        if !api_key.starts_with("sk-") {
            anyhow::bail!(
                "Invalid OpenAI API key format. Key should start with 'sk-'\n\n\
                Check that the environment variable {} contains a valid OpenAI API key.",
                settings.api_key_env
            );
        }

        // Create OpenAI client
        let config = OpenAIConfig::new().with_api_key(api_key);
        let client = Client::with_config(config);

        // Determine cost per 1K tokens based on model
        let (cost_per_1k_input, cost_per_1k_output) = Self::get_model_costs(&settings.model);

        debug!(
            "OpenAI provider initialized: model={}, cost_in=${:.4}/1K, cost_out=${:.4}/1K",
            settings.model, cost_per_1k_input, cost_per_1k_output
        );

        Ok(Self {
            client,
            settings: settings.clone(),
            cost_per_1k_input,
            cost_per_1k_output,
        })
    }

    /// Get model costs per 1K tokens (input, output)
    fn get_model_costs(model: &str) -> (f64, f64) {
        match model {
            "gpt-3.5-turbo" | "gpt-3.5-turbo-1106" | "gpt-3.5-turbo-0125" => (0.0005, 0.0015),
            "gpt-4-turbo" | "gpt-4-turbo-2024-04-09" => (0.01, 0.03),
            "gpt-4o" | "gpt-4o-2024-05-13" => (0.005, 0.015),
            "gpt-4" | "gpt-4-0613" => (0.03, 0.06),
            "gpt-4-32k" => (0.06, 0.12),
            _ => {
                // Unknown model, use GPT-3.5-turbo pricing as fallback
                warn!("Unknown model '{}', using GPT-3.5-turbo pricing", model);
                (0.0005, 0.0015)
            }
        }
    }

    /// Send a chat completion request to OpenAI
    ///
    /// # Arguments
    ///
    /// * `system_prompt` - System message (role/instructions)
    /// * `user_prompt` - User message (actual request)
    ///
    /// # Returns
    ///
    /// API response text and token usage
    ///
    /// # Errors
    ///
    /// - API rate limit exceeded
    /// - Network errors
    /// - Invalid API key
    /// - Model not available
    #[instrument(skip(self, system_prompt, user_prompt), fields(model = %self.settings.model))]
    async fn chat_completion(
        &self,
        system_prompt: &str,
        user_prompt: &str,
    ) -> Result<(String, usize, usize)> {
        debug!("Sending chat completion request");

        let messages = vec![
            ChatCompletionRequestMessage::System(
                ChatCompletionRequestSystemMessageArgs::default()
                    .content(system_prompt)
                    .build()?,
            ),
            ChatCompletionRequestMessage::User(
                ChatCompletionRequestUserMessageArgs::default()
                    .content(user_prompt)
                    .build()?,
            ),
        ];

        let request = CreateChatCompletionRequestArgs::default()
            .model(&self.settings.model)
            .messages(messages)
            .temperature(self.settings.temperature)
            .max_tokens(self.settings.max_tokens as u16)
            .build()?;

        let response = self.client.chat().create(request).await.context(
            "Failed to call OpenAI API. Possible causes:\n\
            - Rate limit exceeded (wait and retry)\n\
            - Network connection issues\n\
            - Invalid API key\n\
            - Insufficient credits",
        )?;

        let content = response.choices[0]
            .message
            .content
            .clone()
            .unwrap_or_default();

        let input_tokens = response.usage.as_ref().map(|u| u.prompt_tokens as usize).unwrap_or(0);
        let output_tokens = response.usage.as_ref().map(|u| u.completion_tokens as usize).unwrap_or(0);

        debug!(
            "Received response: {} chars, {} input tokens, {} output tokens",
            content.len(),
            input_tokens,
            output_tokens
        );

        Ok((content, input_tokens, output_tokens))
    }

    /// Extract JSON from response (may be in markdown code blocks)
    fn extract_json(response: &str) -> Option<Value> {
        // Try parsing directly
        if let Ok(json) = serde_json::from_str::<Value>(response) {
            return Some(json);
        }

        // Try extracting from markdown code blocks
        if let Some(start) = response.find("```json") {
            if let Some(end) = response[start..].find("```") {
                let json_str = &response[start + 7..start + end].trim();
                if let Ok(json) = serde_json::from_str::<Value>(json_str) {
                    return Some(json);
                }
            }
        }

        // Try finding JSON object directly
        if let Some(start) = response.find('{') {
            if let Some(end) = response.rfind('}') {
                let json_str = &response[start..=end];
                if let Ok(json) = serde_json::from_str::<Value>(json_str) {
                    return Some(json);
                }
            }
        }

        None
    }

    /// Parse vulnerability type from string
    fn parse_vuln_type(type_str: &str) -> VulnerabilityType {
        match type_str.to_lowercase().as_str() {
            "secrets_leakage" | "secrets" | "hardcoded_secrets" => VulnerabilityType::SecretsLeakage,
            "command_injection" | "command" | "code_injection" => VulnerabilityType::CommandInjection,
            "sensitive_file_access" | "file_access" | "path_traversal" => VulnerabilityType::SensitiveFileAccess,
            "tool_poisoning" | "supply_chain" => VulnerabilityType::ToolPoisoning,
            "prompt_injection" | "prompt" => VulnerabilityType::PromptInjection,
            _ => VulnerabilityType::SecretsLeakage, // Default fallback
        }
    }

    /// Parse severity from string
    fn parse_severity(severity_str: &str) -> Severity {
        match severity_str.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Medium, // Default fallback
        }
    }

    /// Calculate cost from token usage
    fn calculate_cost(&self, input_tokens: usize, output_tokens: usize) -> f64 {
        let input_cost = (input_tokens as f64 / 1000.0) * self.cost_per_1k_input;
        let output_cost = (output_tokens as f64 / 1000.0) * self.cost_per_1k_output;
        input_cost + output_cost
    }
}

#[async_trait]
impl LLMProvider for OpenAIProvider {
    /// Analyze code for security vulnerabilities using GPT models
    ///
    /// # Arguments
    ///
    /// * `code` - Code snippet to analyze (recommended max 50 lines)
    /// * `context` - Additional context about the code
    ///
    /// # Returns
    ///
    /// AI finding with vulnerability details, confidence score, and remediation
    ///
    /// # Errors
    ///
    /// - API rate limit exceeded
    /// - Network errors
    /// - Invalid response format
    #[instrument(skip(self, code, context), fields(file = %context.file_path, lang = %context.language))]
    async fn analyze_code(&self, code: &str, context: &AnalysisContext) -> Result<AIFinding> {
        info!("Analyzing code with OpenAI");

        let system_prompt = "You are a security expert specializing in vulnerability detection for MCP (Model Context Protocol) servers. \
            Analyze code for security vulnerabilities and respond ONLY with valid JSON in this exact format:\n\n\
            {\n  \
              \"vulnerability_type\": \"secrets_leakage|command_injection|sensitive_file_access|tool_poisoning|prompt_injection\",\n  \
              \"severity\": \"critical|high|medium|low\",\n  \
              \"confidence\": 0.0-1.0,\n  \
              \"description\": \"Brief description\",\n  \
              \"explanation\": \"Detailed explanation\",\n  \
              \"remediation\": \"How to fix it\",\n  \
              \"false_positive_likelihood\": 0.0-1.0,\n  \
              \"insights\": [\"insight1\", \"insight2\"]\n\
            }\n\n\
            Focus on MCP-specific risks: secrets in configs, command injection through tool args, \
            file access outside scope, tool supply chain risks, prompt injection in descriptions.";

        let user_prompt = format!(
            "File: {}\nLanguage: {}\n{}\n\n```{}\n{}\n```\n\nAnalyze for security vulnerabilities. Respond with JSON only.",
            context.file_path,
            context.language,
            context.scope.as_ref().map(|s| format!("Scope: {}", s)).unwrap_or_default(),
            context.language,
            code
        );

        let start = std::time::Instant::now();
        let (response, input_tokens, output_tokens) = self.chat_completion(&system_prompt, &user_prompt).await?;
        let duration_ms = start.elapsed().as_millis() as u64;

        // Extract JSON from response
        let json = Self::extract_json(&response).context(
            "Failed to parse JSON response from OpenAI. The model may not have followed the JSON format instruction."
        )?;

        // Parse the JSON response
        let vuln_type = Self::parse_vuln_type(
            json["vulnerability_type"]
                .as_str()
                .unwrap_or("secrets_leakage"),
        );
        let severity = Self::parse_severity(json["severity"].as_str().unwrap_or("medium"));
        let confidence = json["confidence"].as_f64().unwrap_or(0.7);
        let description = json["description"]
            .as_str()
            .unwrap_or("Potential security vulnerability detected")
            .to_string();
        let explanation = json["explanation"]
            .as_str()
            .unwrap_or("No detailed explanation provided")
            .to_string();
        let remediation = json["remediation"]
            .as_str()
            .unwrap_or("Review and fix the vulnerability")
            .to_string();
        let false_positive_likelihood = json["false_positive_likelihood"].as_f64().unwrap_or(0.2);
        let insights = json["insights"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let cost_usd = self.calculate_cost(input_tokens, output_tokens);

        Ok(AIFinding {
            vuln_type,
            severity,
            confidence,
            description,
            explanation,
            remediation,
            code_snippet: Some(code.to_string()),
            file_path: context.file_path.clone(),
            line_number: context.line_number,
            column: None,
            provider: "openai".to_string(),
            model: self.settings.model.clone(),
            context: AnalysisMetadata {
                language: context.language.clone(),
                scope: context.scope.clone(),
                timestamp: Utc::now(),
                duration_ms,
                tokens_used: Some(input_tokens + output_tokens),
                cost_usd: Some(cost_usd),
            },
            insights,
            false_positive_likelihood,
            impact: None,
        })
    }

    /// Generate detailed explanation for a detected vulnerability
    ///
    /// # Arguments
    ///
    /// * `vuln` - The detected vulnerability
    /// * `code` - The vulnerable code snippet
    ///
    /// # Returns
    ///
    /// Human-readable explanation of the vulnerability
    #[instrument(skip(self, vuln, code), fields(type = ?vuln.vuln_type))]
    async fn explain_vulnerability(&self, vuln: &Vulnerability, code: &str) -> Result<String> {
        info!("Generating vulnerability explanation");

        let system_prompt = "You are a security expert. Explain vulnerabilities clearly and concisely \
            to developers. Focus on WHY it's a vulnerability, WHAT the risks are, and HOW it could be exploited.";

        let user_prompt = format!(
            "Explain this vulnerability:\n\n\
            Type: {:?}\n\
            Severity: {:?}\n\
            Location: {}:{}\n\
            Description: {}\n\n\
            Code:\n```\n{}\n```\n\n\
            Provide a clear explanation for a developer.",
            vuln.vuln_type, vuln.severity, vuln.location.file, vuln.location.line, vuln.description, code
        );

        let (response, _, _) = self.chat_completion(&system_prompt, &user_prompt).await?;
        Ok(response)
    }

    /// Generate actionable remediation steps for a vulnerability
    ///
    /// # Arguments
    ///
    /// * `vuln` - The vulnerability to remediate
    ///
    /// # Returns
    ///
    /// Step-by-step remediation guidance with code examples
    #[instrument(skip(self, vuln), fields(type = ?vuln.vuln_type))]
    async fn generate_remediation(&self, vuln: &Vulnerability) -> Result<String> {
        info!("Generating remediation guidance");

        let system_prompt = "You are a security expert. Provide clear, actionable remediation steps \
            with code examples. Focus on SECURE alternatives and best practices.";

        let user_prompt = format!(
            "Provide remediation for this vulnerability:\n\n\
            Type: {:?}\n\
            Severity: {:?}\n\
            Description: {}\n\n\
            Provide specific steps and code examples to fix this issue.",
            vuln.vuln_type, vuln.severity, vuln.description
        );

        let (response, _, _) = self.chat_completion(&system_prompt, &user_prompt).await?;
        Ok(response)
    }

    fn name(&self) -> &str {
        "openai"
    }

    fn cost_per_request(&self) -> f64 {
        // Estimate based on average 500 input + 300 output tokens
        self.calculate_cost(500, 300)
    }

    /// Check OpenAI API availability and credentials
    ///
    /// # Returns
    ///
    /// true if API is available and credentials are valid
    #[instrument(skip(self))]
    async fn health_check(&self) -> Result<bool> {
        debug!("Performing OpenAI health check");

        // Try a minimal API call
        match self
            .chat_completion(
                "You are a helpful assistant.",
                "Respond with OK if you receive this.",
            )
            .await
        {
            Ok(_) => {
                info!("OpenAI health check passed");
                Ok(true)
            }
            Err(e) => {
                error!("OpenAI health check failed: {}", e);
                Ok(false)
            }
        }
    }

    fn model(&self) -> &str {
        &self.settings.model
    }

    fn is_local(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_costs() {
        let (input, output) = OpenAIProvider::get_model_costs("gpt-3.5-turbo");
        assert_eq!(input, 0.0005);
        assert_eq!(output, 0.0015);

        let (input, output) = OpenAIProvider::get_model_costs("gpt-4-turbo");
        assert_eq!(input, 0.01);
        assert_eq!(output, 0.03);

        let (input, output) = OpenAIProvider::get_model_costs("gpt-4o");
        assert_eq!(input, 0.005);
        assert_eq!(output, 0.015);
    }

    #[test]
    fn test_extract_json() {
        // Direct JSON
        let json = r#"{"test": "value"}"#;
        let result = OpenAIProvider::extract_json(json);
        assert!(result.is_some());

        // JSON in markdown
        let json = r#"```json
        {"test": "value"}
        ```"#;
        let result = OpenAIProvider::extract_json(json);
        assert!(result.is_some());

        // JSON embedded in text
        let json = "Some text before {"test": "value"} some text after";
        let result = OpenAIProvider::extract_json(json);
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_vuln_type() {
        assert!(matches!(
            OpenAIProvider::parse_vuln_type("secrets_leakage"),
            VulnerabilityType::SecretsLeakage
        ));
        assert!(matches!(
            OpenAIProvider::parse_vuln_type("command_injection"),
            VulnerabilityType::CommandInjection
        ));
        assert!(matches!(
            OpenAIProvider::parse_vuln_type("prompt"),
            VulnerabilityType::PromptInjection
        ));
    }

    #[test]
    fn test_parse_severity() {
        assert!(matches!(
            OpenAIProvider::parse_severity("critical"),
            Severity::Critical
        ));
        assert!(matches!(
            OpenAIProvider::parse_severity("high"),
            Severity::High
        ));
        assert!(matches!(
            OpenAIProvider::parse_severity("medium"),
            Severity::Medium
        ));
        assert!(matches!(
            OpenAIProvider::parse_severity("low"),
            Severity::Low
        ));
    }

    #[test]
    fn test_calculate_cost() {
        let settings = OpenAISettings {
            model: "gpt-3.5-turbo".to_string(),
            ..Default::default()
        };
        let provider = OpenAIProvider {
            client: Client::new(),
            settings,
            cost_per_1k_input: 0.0005,
            cost_per_1k_output: 0.0015,
        };

        // 500 input + 300 output tokens
        let cost = provider.calculate_cost(500, 300);
        assert!((cost - 0.00070).abs() < 0.0001); // $0.00025 + $0.00045 = $0.0007
    }
}
