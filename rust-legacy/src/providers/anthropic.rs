//! Anthropic LLM Provider
//!
//! Commercial API provider using Claude 3 models (Haiku, Sonnet, Opus)
//! for security-focused code analysis.
//!
//! # Features
//!
//! - Support for Claude 3 Haiku, Sonnet, and Opus models
//! - Extended context windows (up to 200K tokens)
//! - Strong reasoning capabilities for complex vulnerabilities
//! - Constitutional AI for ethical analysis
//! - JSON mode support
//! - Comprehensive error handling
//!
//! # Configuration
//!
//! ```yaml
//! ai:
//!   providers:
//!     anthropic:
//!       model: "claude-3-haiku-20240307"  # or sonnet, opus
//!       api_key_env: "ANTHROPIC_API_KEY"
//!       max_tokens: 2000
//! ```
//!
//! # Environment Variables
//!
//! - `ANTHROPIC_API_KEY`: Your Anthropic API key (required)
//!
//! # Cost Structure (as of 2025)
//!
//! - Claude 3 Haiku: $0.00025/1K input tokens, $0.00125/1K output tokens
//! - Claude 3 Sonnet: $0.003/1K input tokens, $0.015/1K output tokens
//! - Claude 3 Opus: $0.015/1K input tokens, $0.075/1K output tokens
//!
//! # Model Selection Guide
//!
//! - **Haiku**: Fast, cheap, good for simple scans (recommended for CI/CD)
//! - **Sonnet**: Balanced performance and cost (recommended for most users)
//! - **Opus**: Best quality, expensive, use for critical security audits
//!
//! # Examples
//!
//! ```rust
//! use mcp_sentinel::providers::anthropic::{AnthropicProvider, AnthropicSettings};
//!
//! # #[tokio::main]
//! # async fn main() -> anyhow::Result<()> {
//! let settings = AnthropicSettings {
//!     model: "claude-3-sonnet-20240229".to_string(),
//!     api_key_env: "ANTHROPIC_API_KEY".to_string(),
//!     max_tokens: 2000,
//! };
//!
//! let provider = AnthropicProvider::new(&settings)?;
//! // Use provider for analysis
//! # Ok(())
//! # }
//! ```

use super::{AnalysisContext, LLMProvider, AnthropicSettings};
use crate::models::{
    ai_finding::*,
    vulnerability::{Severity, Vulnerability},
    VulnerabilityType,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};

/// Anthropic API request structure
#[derive(Debug, Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: usize,
    messages: Vec<AnthropicMessage>,
    system: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AnthropicMessage {
    role: String,
    content: String,
}

/// Anthropic API response structure
#[derive(Debug, Deserialize)]
struct AnthropicResponse {
    content: Vec<ContentBlock>,
    usage: Usage,
}

#[derive(Debug, Deserialize)]
struct ContentBlock {
    #[serde(rename = "type")]
    content_type: String,
    text: String,
}

#[derive(Debug, Deserialize)]
struct Usage {
    input_tokens: usize,
    output_tokens: usize,
}

/// Anthropic provider for Claude 3 vulnerability analysis
///
/// This provider uses Anthropic's Claude 3 models (Haiku, Sonnet, Opus) for
/// AI-powered security analysis. Claude 3 excels at reasoning about complex
/// security vulnerabilities and providing detailed explanations.
///
/// # Why Claude for Security?
///
/// - Constitutional AI: Built-in ethical guardrails
/// - Strong reasoning: Better at complex vulnerability patterns
/// - Long context: Analyze larger code snippets (up to 200K tokens)
/// - Detailed explanations: Clear, actionable security guidance
///
/// # Privacy
///
/// Code snippets are sent to Anthropic's API. For sensitive codebases, consider:
/// - Using Ollama or other local providers
/// - Limiting code context size
/// - Reviewing Anthropic's data usage policy
///
/// # Rate Limiting
///
/// Anthropic has tiered rate limits:
/// - Free tier: 5 RPM
/// - Tier 1: 50 RPM
/// - Tier 2: 1000 RPM
/// - Tier 3: 2000 RPM
pub struct AnthropicProvider {
    client: Client,
    settings: AnthropicSettings,
    api_key: String,
    cost_per_1k_input: f64,
    cost_per_1k_output: f64,
}

impl AnthropicProvider {
    /// Create a new Anthropic provider
    ///
    /// # Arguments
    ///
    /// * `settings` - Anthropic configuration settings
    ///
    /// # Returns
    ///
    /// Initialized Anthropic provider
    ///
    /// # Errors
    ///
    /// - API key not found in environment
    /// - API key invalid format
    /// - Network connection issues (during health check)
    #[instrument(skip(settings), fields(model = %settings.model))]
    pub fn new(settings: &AnthropicSettings) -> Result<Self> {
        info!("Initializing Anthropic provider");

        // Get API key from environment
        let api_key = std::env::var(&settings.api_key_env).context(format!(
            "Anthropic API key not found in environment variable: {}\n\n\
            To set your API key:\n\
              export {}=sk-ant-...\n\n\
            To get an API key:\n\
              1. Visit https://console.anthropic.com/\n\
              2. Sign up or log in\n\
              3. Go to API Keys section\n\
              4. Click 'Create Key'\n\
              5. Copy the key (starts with 'sk-ant-')",
            settings.api_key_env, settings.api_key_env
        ))?;

        // Validate API key format
        if !api_key.starts_with("sk-ant-") {
            anyhow::bail!(
                "Invalid Anthropic API key format. Key should start with 'sk-ant-'\n\n\
                Check that the environment variable {} contains a valid Anthropic API key.",
                settings.api_key_env
            );
        }

        // Create HTTP client
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .context("Failed to create HTTP client")?;

        // Determine cost per 1K tokens based on model
        let (cost_per_1k_input, cost_per_1k_output) = Self::get_model_costs(&settings.model);

        debug!(
            "Anthropic provider initialized: model={}, cost_in=${:.5}/1K, cost_out=${:.5}/1K",
            settings.model, cost_per_1k_input, cost_per_1k_output
        );

        Ok(Self {
            client,
            settings: settings.clone(),
            api_key,
            cost_per_1k_input,
            cost_per_1k_output,
        })
    }

    /// Get model costs per 1K tokens (input, output)
    fn get_model_costs(model: &str) -> (f64, f64) {
        if model.contains("haiku") {
            (0.00025, 0.00125)
        } else if model.contains("sonnet") {
            (0.003, 0.015)
        } else if model.contains("opus") {
            (0.015, 0.075)
        } else {
            // Unknown model, use Sonnet pricing as fallback
            warn!("Unknown model '{}', using Sonnet pricing", model);
            (0.003, 0.015)
        }
    }

    /// Send a message to Claude API
    ///
    /// # Arguments
    ///
    /// * `system_prompt` - System message (role/instructions)
    /// * `user_prompt` - User message (actual request)
    ///
    /// # Returns
    ///
    /// API response text and token usage
    #[instrument(skip(self, system_prompt, user_prompt), fields(model = %self.settings.model))]
    async fn send_message(
        &self,
        system_prompt: &str,
        user_prompt: &str,
    ) -> Result<(String, usize, usize)> {
        debug!("Sending message to Claude API");

        let request = AnthropicRequest {
            model: self.settings.model.clone(),
            max_tokens: self.settings.max_tokens,
            system: Some(system_prompt.to_string()),
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: user_prompt.to_string(),
            }],
        };

        let response = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to call Anthropic API")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "Anthropic API error (status {}): {}\n\n\
                Possible causes:\n\
                - Rate limit exceeded (wait and retry)\n\
                - Invalid API key\n\
                - Insufficient credits\n\
                - Model not available",
                status,
                error_text
            );
        }

        let api_response: AnthropicResponse = response.json().await.context(
            "Failed to parse Anthropic API response. The API format may have changed."
        )?;

        let content = api_response
            .content
            .into_iter()
            .filter(|block| block.content_type == "text")
            .map(|block| block.text)
            .collect::<Vec<_>>()
            .join("\n");

        let input_tokens = api_response.usage.input_tokens;
        let output_tokens = api_response.usage.output_tokens;

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
            "secrets_leakage" | "secrets" | "hardcoded_secrets" => {
                VulnerabilityType::SecretsLeakage
            }
            "command_injection" | "command" | "code_injection" => {
                VulnerabilityType::CommandInjection
            }
            "sensitive_file_access" | "file_access" | "path_traversal" => {
                VulnerabilityType::SensitiveFileAccess
            }
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
impl LLMProvider for AnthropicProvider {
    /// Analyze code for security vulnerabilities using Claude
    ///
    /// # Arguments
    ///
    /// * `code` - Code snippet to analyze (can be larger than GPT due to 200K context)
    /// * `context` - Additional context about the code
    ///
    /// # Returns
    ///
    /// AI finding with vulnerability details, confidence score, and remediation
    #[instrument(skip(self, code, context), fields(file = %context.file_path, lang = %context.language))]
    async fn analyze_code(&self, code: &str, context: &AnalysisContext) -> Result<AIFinding> {
        info!("Analyzing code with Claude");

        let system_prompt = "You are a security expert specializing in vulnerability detection for MCP (Model Context Protocol) servers. \
            Analyze code for security vulnerabilities with careful reasoning about the actual risk.\n\n\
            Respond ONLY with valid JSON in this exact format:\n\n\
            {\n  \
              \"vulnerability_type\": \"secrets_leakage|command_injection|sensitive_file_access|tool_poisoning|prompt_injection\",\n  \
              \"severity\": \"critical|high|medium|low\",\n  \
              \"confidence\": 0.0-1.0,\n  \
              \"description\": \"Brief description\",\n  \
              \"explanation\": \"Detailed explanation with reasoning\",\n  \
              \"remediation\": \"Specific steps to fix\",\n  \
              \"false_positive_likelihood\": 0.0-1.0,\n  \
              \"insights\": [\"insight1\", \"insight2\"]\n\
            }\n\n\
            Focus on MCP-specific risks: secrets in configs, command injection through tool args, \
            file access outside scope, tool supply chain risks, prompt injection in descriptions.\n\n\
            Use your reasoning capabilities to determine if sanitization is present and effective.";

        let user_prompt = format!(
            "File: {}\nLanguage: {}\n{}\n\n```{}\n{}\n```\n\nAnalyze this code for security vulnerabilities. Think step by step about the actual risk. Respond with JSON only.",
            context.file_path,
            context.language,
            context
                .scope
                .as_ref()
                .map(|s| format!("Scope: {}", s))
                .unwrap_or_default(),
            context.language,
            code
        );

        let start = std::time::Instant::now();
        let (response, input_tokens, output_tokens) =
            self.send_message(&system_prompt, &user_prompt).await?;
        let duration_ms = start.elapsed().as_millis() as u64;

        // Extract JSON from response
        let json = Self::extract_json(&response).context(
            "Failed to parse JSON response from Claude. The model may not have followed the JSON format instruction.",
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
            provider: "anthropic".to_string(),
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
    #[instrument(skip(self, vuln, code), fields(type = ?vuln.vuln_type))]
    async fn explain_vulnerability(&self, vuln: &Vulnerability, code: &str) -> Result<String> {
        info!("Generating vulnerability explanation with Claude");

        let system_prompt = "You are a security expert. Explain vulnerabilities with clear reasoning. \
            Focus on WHY it's a vulnerability, WHAT the actual risks are, and HOW it could be exploited in practice.";

        let user_prompt = format!(
            "Explain this vulnerability with detailed reasoning:\n\n\
            Type: {:?}\n\
            Severity: {:?}\n\
            Location: {}:{}\n\
            Description: {}\n\n\
            Code:\n```\n{}\n```\n\n\
            Provide a thorough explanation that a developer can understand and act on.",
            vuln.vuln_type,
            vuln.severity,
            vuln.location.file,
            vuln.location.line,
            vuln.description,
            code
        );

        let (response, _, _) = self.send_message(&system_prompt, &user_prompt).await?;
        Ok(response)
    }

    /// Generate actionable remediation steps for a vulnerability
    #[instrument(skip(self, vuln), fields(type = ?vuln.vuln_type))]
    async fn generate_remediation(&self, vuln: &Vulnerability) -> Result<String> {
        info!("Generating remediation guidance with Claude");

        let system_prompt = "You are a security expert. Provide clear, actionable remediation steps \
            with specific code examples. Focus on SECURE alternatives and industry best practices.";

        let user_prompt = format!(
            "Provide comprehensive remediation for this vulnerability:\n\n\
            Type: {:?}\n\
            Severity: {:?}\n\
            Description: {}\n\n\
            Provide:\n\
            1. Specific steps to fix the issue\n\
            2. Code examples showing the secure implementation\n\
            3. Best practices to prevent similar issues\n\
            4. Testing recommendations",
            vuln.vuln_type, vuln.severity, vuln.description
        );

        let (response, _, _) = self.send_message(&system_prompt, &user_prompt).await?;
        Ok(response)
    }

    fn name(&self) -> &str {
        "anthropic"
    }

    fn cost_per_request(&self) -> f64 {
        // Estimate based on average 500 input + 300 output tokens
        self.calculate_cost(500, 300)
    }

    /// Check Claude API availability and credentials
    #[instrument(skip(self))]
    async fn health_check(&self) -> Result<bool> {
        debug!("Performing Claude health check");

        // Try a minimal API call
        match self
            .send_message(
                "You are a helpful assistant.",
                "Respond with OK if you receive this.",
            )
            .await
        {
            Ok(_) => {
                info!("Claude health check passed");
                Ok(true)
            }
            Err(e) => {
                error!("Claude health check failed: {}", e);
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
        let (input, output) = AnthropicProvider::get_model_costs("claude-3-haiku-20240307");
        assert_eq!(input, 0.00025);
        assert_eq!(output, 0.00125);

        let (input, output) = AnthropicProvider::get_model_costs("claude-3-sonnet-20240229");
        assert_eq!(input, 0.003);
        assert_eq!(output, 0.015);

        let (input, output) = AnthropicProvider::get_model_costs("claude-3-opus-20240229");
        assert_eq!(input, 0.015);
        assert_eq!(output, 0.075);
    }

    #[test]
    fn test_extract_json() {
        // Direct JSON
        let json = r#"{"test": "value"}"#;
        let result = AnthropicProvider::extract_json(json);
        assert!(result.is_some());

        // JSON in markdown
        let json = r#"```json
        {"test": "value"}
        ```"#;
        let result = AnthropicProvider::extract_json(json);
        assert!(result.is_some());

        // JSON embedded in text
        let json = "Some text before {\"test\": \"value\"} some text after";
        let result = AnthropicProvider::extract_json(json);
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_vuln_type() {
        assert!(matches!(
            AnthropicProvider::parse_vuln_type("secrets_leakage"),
            VulnerabilityType::SecretsLeakage
        ));
        assert!(matches!(
            AnthropicProvider::parse_vuln_type("command_injection"),
            VulnerabilityType::CommandInjection
        ));
    }

    #[test]
    fn test_parse_severity() {
        assert!(matches!(
            AnthropicProvider::parse_severity("critical"),
            Severity::Critical
        ));
        assert!(matches!(
            AnthropicProvider::parse_severity("high"),
            Severity::High
        ));
    }

    #[test]
    fn test_calculate_cost() {
        let settings = AnthropicSettings {
            model: "claude-3-haiku-20240307".to_string(),
            ..Default::default()
        };

        // Create provider (client will be unused in test)
        let client = Client::new();
        let provider = AnthropicProvider {
            client,
            settings,
            api_key: "test".to_string(),
            cost_per_1k_input: 0.00025,
            cost_per_1k_output: 0.00125,
        };

        // 500 input + 300 output tokens
        let cost = provider.calculate_cost(500, 300);
        assert!((cost - 0.000500).abs() < 0.000001); // $0.000125 + $0.000375 = $0.0005
    }
}
