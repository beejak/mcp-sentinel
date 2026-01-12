//! Google Gemini LLM Provider
//!
//! Commercial API provider using Google's Gemini Pro and Gemini Ultra models
//! for security-focused code analysis.
//!
//! # Features
//!
//! - Support for Gemini Pro, Gemini Pro Vision, and Gemini Ultra
//! - Fast inference with competitive pricing
//! - Strong code understanding capabilities
//! - JSON mode for structured output
//! - Multimodal support (Pro Vision)
//!
//! # Configuration
//!
//! ```yaml
//! ai:
//!   providers:
//!     google:
//!       model: "gemini-pro"  # or gemini-pro-vision, gemini-ultra
//!       api_key_env: "GOOGLE_API_KEY"
//! ```
//!
//! # Environment Variables
//!
//! - `GOOGLE_API_KEY`: Your Google AI Studio API key (required)
//!
//! # Cost Structure (as of 2025)
//!
//! - Gemini Pro: $0.00025/1K input tokens, $0.0005/1K output tokens
//! - Gemini Ultra: $0.00125/1K input tokens, $0.0025/1K output tokens
//!
//! # Model Selection Guide
//!
//! - **Gemini Pro**: Fast, cheap, good for most scans (recommended)
//! - **Gemini Ultra**: Best quality, more expensive
//! - **Gemini Pro Vision**: For multimodal analysis (future)
//!
//! # Examples
//!
//! ```rust
//! use mcp_sentinel::providers::google::{GoogleProvider, GoogleSettings};
//!
//! # fn main() -> anyhow::Result<()> {
//! let settings = GoogleSettings {
//!     model: "gemini-pro".to_string(),
//!     api_key_env: "GOOGLE_API_KEY".to_string(),
//! };
//!
//! let provider = GoogleProvider::new(&settings)?;
//! // Use provider for analysis
//! # Ok(())
//! # }
//! ```

use super::{AnalysisContext, LLMProvider, GoogleSettings};
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

/// Gemini API request structure
#[derive(Debug, Serialize)]
struct GeminiRequest {
    contents: Vec<GeminiContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation_config: Option<GeminiGenerationConfig>,
}

#[derive(Debug, Serialize)]
struct GeminiContent {
    role: String,
    parts: Vec<GeminiPart>,
}

#[derive(Debug, Serialize)]
struct GeminiPart {
    text: String,
}

#[derive(Debug, Serialize)]
struct GeminiGenerationConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_output_tokens: Option<usize>,
}

/// Gemini API response structure
#[derive(Debug, Deserialize)]
struct GeminiResponse {
    candidates: Vec<GeminiCandidate>,
    #[serde(default)]
    usage_metadata: Option<GeminiUsageMetadata>,
}

#[derive(Debug, Deserialize)]
struct GeminiCandidate {
    content: GeminiContent,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiUsageMetadata {
    prompt_token_count: usize,
    candidates_token_count: usize,
}

/// Google Gemini provider for AI-powered vulnerability analysis
///
/// This provider uses Google's Gemini Pro model for security analysis.
/// Gemini Pro offers fast inference at competitive pricing, making it
/// suitable for CI/CD pipelines and frequent scans.
///
/// # Why Gemini for Security?
///
/// - Fast inference: Lower latency than GPT-4
/// - Cost-effective: Cheaper than most competitors
/// - Strong code understanding: Trained on diverse code
/// - Google infrastructure: High availability
///
/// # Privacy
///
/// Code snippets are sent to Google's API. For sensitive codebases, consider:
/// - Using Ollama or other local providers
/// - Limiting code context size
/// - Reviewing Google's data usage policy
pub struct GoogleProvider {
    client: Client,
    settings: GoogleSettings,
    api_key: String,
    cost_per_1k_input: f64,
    cost_per_1k_output: f64,
}

impl GoogleProvider {
    /// Create a new Google Gemini provider
    ///
    /// # Arguments
    ///
    /// * `settings` - Google configuration settings
    ///
    /// # Returns
    ///
    /// Initialized Google provider
    ///
    /// # Errors
    ///
    /// - API key not found in environment
    /// - Network connection issues
    #[instrument(skip(settings), fields(model = %settings.model))]
    pub fn new(settings: &GoogleSettings) -> Result<Self> {
        info!("Initializing Google Gemini provider");

        // Get API key from environment
        let api_key = std::env::var(&settings.api_key_env).context(format!(
            "Google API key not found in environment variable: {}\n\n\
            To set your API key:\n\
              export {}=your-api-key\n\n\
            To get an API key:\n\
              1. Visit https://aistudio.google.com/app/apikey\n\
              2. Sign in with your Google account\n\
              3. Click 'Create API Key'\n\
              4. Copy the key",
            settings.api_key_env, settings.api_key_env
        ))?;

        // Create HTTP client
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .context("Failed to create HTTP client")?;

        // Determine cost per 1K tokens based on model
        let (cost_per_1k_input, cost_per_1k_output) = Self::get_model_costs(&settings.model);

        debug!(
            "Google Gemini provider initialized: model={}, cost_in=${:.5}/1K, cost_out=${:.5}/1K",
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
        if model.contains("ultra") {
            (0.00125, 0.0025)
        } else {
            // gemini-pro or gemini-pro-vision
            (0.00025, 0.0005)
        }
    }

    /// Send a message to Gemini API
    ///
    /// # Arguments
    ///
    /// * `prompt` - The prompt to send
    ///
    /// # Returns
    ///
    /// API response text and token usage
    #[instrument(skip(self, prompt), fields(model = %self.settings.model))]
    async fn generate(&self, prompt: &str) -> Result<(String, usize, usize)> {
        debug!("Sending request to Gemini API");

        let request = GeminiRequest {
            contents: vec![GeminiContent {
                role: "user".to_string(),
                parts: vec![GeminiPart {
                    text: prompt.to_string(),
                }],
            }],
            generation_config: Some(GeminiGenerationConfig {
                temperature: Some(0.1),
                max_output_tokens: Some(2000),
            }),
        };

        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            self.settings.model, self.api_key
        );

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to call Google Gemini API")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "Google Gemini API error (status {}): {}\n\n\
                Possible causes:\n\
                - Invalid API key\n\
                - Rate limit exceeded\n\
                - Model not available\n\
                - Quota exceeded",
                status,
                error_text
            );
        }

        let api_response: GeminiResponse = response.json().await.context(
            "Failed to parse Gemini API response. The API format may have changed.",
        )?;

        let content = api_response
            .candidates
            .first()
            .and_then(|c| c.content.parts.first())
            .map(|p| p.text.clone())
            .unwrap_or_default();

        let input_tokens = api_response
            .usage_metadata
            .as_ref()
            .map(|u| u.prompt_token_count)
            .unwrap_or(0);
        let output_tokens = api_response
            .usage_metadata
            .as_ref()
            .map(|u| u.candidates_token_count)
            .unwrap_or(0);

        debug!(
            "Received response: {} chars, {} input tokens, {} output tokens",
            content.len(),
            input_tokens,
            output_tokens
        );

        Ok((content, input_tokens, output_tokens))
    }

    /// Extract JSON from response
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
            _ => VulnerabilityType::SecretsLeakage,
        }
    }

    /// Parse severity from string
    fn parse_severity(severity_str: &str) -> Severity {
        match severity_str.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Medium,
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
impl LLMProvider for GoogleProvider {
    /// Analyze code for security vulnerabilities using Gemini
    #[instrument(skip(self, code, context), fields(file = %context.file_path, lang = %context.language))]
    async fn analyze_code(&self, code: &str, context: &AnalysisContext) -> Result<AIFinding> {
        info!("Analyzing code with Google Gemini");

        let prompt = format!(
            "You are a security expert analyzing code for vulnerabilities in MCP (Model Context Protocol) servers.\n\n\
            Analyze the following code and respond ONLY with valid JSON in this format:\n\n\
            {{\n  \
              \"vulnerability_type\": \"secrets_leakage|command_injection|sensitive_file_access|tool_poisoning|prompt_injection\",\n  \
              \"severity\": \"critical|high|medium|low\",\n  \
              \"confidence\": 0.0-1.0,\n  \
              \"description\": \"Brief description\",\n  \
              \"explanation\": \"Detailed explanation\",\n  \
              \"remediation\": \"How to fix\",\n  \
              \"false_positive_likelihood\": 0.0-1.0,\n  \
              \"insights\": [\"insight1\", \"insight2\"]\n\
            }}\n\n\
            File: {}\nLanguage: {}\n{}\n\n```{}\n{}\n```\n\n\
            Analyze for MCP-specific security risks. Respond with JSON only.",
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
        let (response, input_tokens, output_tokens) = self.generate(&prompt).await?;
        let duration_ms = start.elapsed().as_millis() as u64;

        // Extract JSON from response
        let json = Self::extract_json(&response).context(
            "Failed to parse JSON response from Gemini. The model may not have followed the JSON format instruction.",
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
            provider: "google".to_string(),
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
        info!("Generating vulnerability explanation with Gemini");

        let prompt = format!(
            "You are a security expert. Explain this vulnerability clearly:\n\n\
            Type: {:?}\n\
            Severity: {:?}\n\
            Location: {}:{}\n\
            Description: {}\n\n\
            Code:\n```\n{}\n```\n\n\
            Provide a clear, actionable explanation.",
            vuln.vuln_type,
            vuln.severity,
            vuln.location.file,
            vuln.location.line,
            vuln.description,
            code
        );

        let (response, _, _) = self.generate(&prompt).await?;
        Ok(response)
    }

    /// Generate actionable remediation steps
    #[instrument(skip(self, vuln), fields(type = ?vuln.vuln_type))]
    async fn generate_remediation(&self, vuln: &Vulnerability) -> Result<String> {
        info!("Generating remediation guidance with Gemini");

        let prompt = format!(
            "You are a security expert. Provide remediation steps:\n\n\
            Type: {:?}\n\
            Severity: {:?}\n\
            Description: {}\n\n\
            Provide specific steps and code examples to fix this issue.",
            vuln.vuln_type, vuln.severity, vuln.description
        );

        let (response, _, _) = self.generate(&prompt).await?;
        Ok(response)
    }

    fn name(&self) -> &str {
        "google"
    }

    fn cost_per_request(&self) -> f64 {
        // Estimate based on average 500 input + 300 output tokens
        self.calculate_cost(500, 300)
    }

    /// Check Gemini API availability
    #[instrument(skip(self))]
    async fn health_check(&self) -> Result<bool> {
        debug!("Performing Gemini health check");

        match self.generate("Respond with OK if you receive this.").await {
            Ok(_) => {
                info!("Gemini health check passed");
                Ok(true)
            }
            Err(e) => {
                error!("Gemini health check failed: {}", e);
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
        let (input, output) = GoogleProvider::get_model_costs("gemini-pro");
        assert_eq!(input, 0.00025);
        assert_eq!(output, 0.0005);

        let (input, output) = GoogleProvider::get_model_costs("gemini-ultra");
        assert_eq!(input, 0.00125);
        assert_eq!(output, 0.0025);
    }

    #[test]
    fn test_extract_json() {
        let json = r#"{"test": "value"}"#;
        let result = GoogleProvider::extract_json(json);
        assert!(result.is_some());

        let json = r#"```json
        {"test": "value"}
        ```"#;
        let result = GoogleProvider::extract_json(json);
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_vuln_type() {
        assert!(matches!(
            GoogleProvider::parse_vuln_type("secrets_leakage"),
            VulnerabilityType::SecretsLeakage
        ));
        assert!(matches!(
            GoogleProvider::parse_vuln_type("command_injection"),
            VulnerabilityType::CommandInjection
        ));
    }

    #[test]
    fn test_parse_severity() {
        assert!(matches!(
            GoogleProvider::parse_severity("critical"),
            Severity::Critical
        ));
        assert!(matches!(
            GoogleProvider::parse_severity("medium"),
            Severity::Medium
        ));
    }

    #[test]
    fn test_calculate_cost() {
        let settings = GoogleSettings {
            model: "gemini-pro".to_string(),
            api_key_env: "GOOGLE_API_KEY".to_string(),
        };

        let client = Client::new();
        let provider = GoogleProvider {
            client,
            settings,
            api_key: "test".to_string(),
            cost_per_1k_input: 0.00025,
            cost_per_1k_output: 0.0005,
        };

        let cost = provider.calculate_cost(500, 300);
        assert!((cost - 0.000275).abs() < 0.000001);
    }
}
