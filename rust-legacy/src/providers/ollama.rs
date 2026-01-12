//! Ollama Provider - Open Source Local LLM
//!
//! Ollama is a popular open-source tool for running large language models locally.
//! It provides a simple REST API for interacting with models like Llama 3, Mistral,
//! CodeLlama, Phi, and many others.
//!
//! # Supported Models
//!
//! - **codellama**: Meta's Code Llama (7B, 13B, 34B, 70B)
//! - **llama3**: Meta's Llama 3 (8B, 70B)
//! - **mistral**: Mistral 7B
//! - **mixtral**: Mixtral 8x7B
//! - **phi**: Microsoft Phi-2/3
//! - **deepseek-coder**: DeepSeek Coder
//! - **wizard-coder**: WizardCoder
//! - **starcoder2**: StarCoder 2
//! - And 50+ more models
//!
//! # Installation
//!
//! ```bash
//! # Install Ollama
//! curl -fsSL https://ollama.com/install.sh | sh
//!
//! # Pull a model
//! ollama pull codellama
//!
//! # Run Ollama server
//! ollama serve
//! ```
//!
//! # Configuration
//!
//! ```yaml
//! ai:
//!   providers:
//!     ollama:
//!       url: http://localhost:11434
//!       model: codellama
//!       timeout_seconds: 60
//! ```
//!
//! # Usage
//!
//! ```rust
//! use mcp_sentinel::providers::ollama::OllamaProvider;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let settings = OllamaSettings {
//!         url: "http://localhost:11434".to_string(),
//!         model: "codellama".to_string(),
//!         timeout_seconds: 60,
//!     };
//!
//!     let provider = OllamaProvider::new(&settings).await?;
//!     let finding = provider.analyze_code(code, &context).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Error Handling
//!
//! - **Connection errors**: Ollama server not running → Provides installation instructions
//! - **Model not found**: Model not pulled → Suggests `ollama pull` command
//! - **Timeout**: Analysis takes too long → Adjustable timeout setting
//! - **Invalid response**: Model returns non-JSON → Fallback parsing
//!
//! # Privacy & Security
//!
//! - **100% Local**: No data leaves your machine
//! - **No API Keys**: No authentication required
//! - **Free**: No usage costs
//! - **Open Source**: Full transparency

use super::{AnalysisContext, LLMProvider, OllamaSettings};
use crate::models::{ai_finding::*, Severity, Vulnerability, VulnerabilityType};
use anyhow::{Context as AnyhowContext, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};

/// Ollama LLM provider for local model inference
pub struct OllamaProvider {
    /// HTTP client for API requests
    client: Client,

    /// Provider settings
    settings: OllamaSettings,

    /// Available models on the server
    available_models: Vec<String>,
}

/// Ollama API response for generate endpoint
#[derive(Debug, Deserialize)]
struct OllamaGenerateResponse {
    model: String,
    response: String,
    done: bool,

    #[serde(default)]
    context: Vec<i64>,

    #[serde(default)]
    total_duration: Option<u64>,

    #[serde(default)]
    load_duration: Option<u64>,

    #[serde(default)]
    prompt_eval_count: Option<u64>,

    #[serde(default)]
    eval_count: Option<u64>,
}

/// Ollama model information
#[derive(Debug, Deserialize)]
struct OllamaModel {
    name: String,
    modified_at: String,
    size: i64,
}

/// Ollama tags (list models) response
#[derive(Debug, Deserialize)]
struct OllamaTagsResponse {
    models: Vec<OllamaModel>,
}

impl OllamaProvider {
    /// Create a new Ollama provider
    ///
    /// # Arguments
    ///
    /// * `settings` - Ollama configuration
    ///
    /// # Returns
    ///
    /// Initialized provider ready for inference
    ///
    /// # Errors
    ///
    /// - Cannot connect to Ollama server
    /// - Model not found
    /// - Invalid configuration
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use mcp_sentinel::providers::ollama::*;
    /// # async fn example() -> anyhow::Result<()> {
    /// let settings = OllamaSettings {
    ///     url: "http://localhost:11434".to_string(),
    ///     model: "codellama".to_string(),
    ///     timeout_seconds: 60,
    /// };
    ///
    /// let provider = OllamaProvider::new(&settings).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(settings), fields(url = %settings.url, model = %settings.model))]
    pub async fn new(settings: &OllamaSettings) -> Result<Self> {
        info!("Initializing Ollama provider");

        // Validate URL format
        if !settings.url.starts_with("http://") && !settings.url.starts_with("https://") {
            anyhow::bail!(
                "Invalid Ollama URL: '{}'. Must start with http:// or https://",
                settings.url
            );
        }

        // Create HTTP client with timeout
        let client = Client::builder()
            .timeout(Duration::from_secs(settings.timeout_seconds))
            .build()
            .context("Failed to create HTTP client")?;

        // Health check - try to connect to Ollama
        let tags_url = format!("{}/api/tags", settings.url);
        let response = client
            .get(&tags_url)
            .send()
            .await
            .context(format!(
                "Failed to connect to Ollama at {}. Is Ollama running?\n\n\
                To install Ollama:\n\
                  curl -fsSL https://ollama.com/install.sh | sh\n\n\
                To start Ollama:\n\
                  ollama serve",
                settings.url
            ))?;

        if !response.status().is_success() {
            anyhow::bail!(
                "Ollama server returned error status: {}",
                response.status()
            );
        }

        // Parse available models
        let tags: OllamaTagsResponse = response
            .json()
            .await
            .context("Failed to parse Ollama models list")?;

        let available_models: Vec<String> = tags
            .models
            .iter()
            .map(|m| m.name.clone())
            .collect();

        debug!("Available Ollama models: {:?}", available_models);

        // Check if requested model is available
        if !available_models.iter().any(|m| m.starts_with(&settings.model)) {
            warn!(
                "Model '{}' not found in available models: {:?}",
                settings.model, available_models
            );

            return Err(anyhow::anyhow!(
                "Model '{}' not found. Available models: {:?}\n\n\
                To pull this model:\n\
                  ollama pull {}",
                settings.model,
                available_models,
                settings.model
            ));
        }

        info!(
            "Ollama provider initialized successfully with model '{}'",
            settings.model
        );

        Ok(Self {
            client,
            settings: settings.clone(),
            available_models,
        })
    }

    /// Generate text using Ollama's generate endpoint
    ///
    /// # Arguments
    ///
    /// * `prompt` - Input prompt for the model
    ///
    /// # Returns
    ///
    /// Generated text response
    ///
    /// # Errors
    ///
    /// - Network timeout
    /// - Model error
    /// - Invalid response format
    #[instrument(skip(self, prompt), fields(model = %self.settings.model, prompt_len = prompt.len()))]
    async fn generate(&self, prompt: &str) -> Result<String> {
        let url = format!("{}/api/generate", self.settings.url);

        debug!("Sending request to Ollama");

        let payload = json!({
            "model": self.settings.model,
            "prompt": prompt,
            "stream": false,
            "options": {
                "temperature": 0.1,
                "top_p": 0.9,
                "num_predict": 2000,
            }
        });

        let start = std::time::Instant::now();

        let response = self
            .client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send request to Ollama")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Ollama returned error {}: {}", status, error_text);
        }

        let generate_response: OllamaGenerateResponse = response
            .json()
            .await
            .context("Failed to parse Ollama response")?;

        let duration = start.elapsed();

        debug!(
            "Ollama response received in {:.2}s (eval_count: {:?})",
            duration.as_secs_f64(),
            generate_response.eval_count
        );

        if generate_response.response.is_empty() {
            warn!("Ollama returned empty response");
            anyhow::bail!("Ollama returned empty response");
        }

        Ok(generate_response.response)
    }

    /// Parse vulnerability type from string
    fn parse_vuln_type(type_str: &str) -> VulnerabilityType {
        match type_str.to_lowercase().as_str() {
            "command_injection" | "command-injection" | "os_command" => {
                VulnerabilityType::CommandInjection
            }
            "secrets_leakage" | "secrets-leakage" | "hardcoded_secrets" | "credentials" => {
                VulnerabilityType::SecretsLeakage
            }
            "sensitive_file_access" | "sensitive-file-access" | "file_access" => {
                VulnerabilityType::SensitiveFileAccess
            }
            "tool_poisoning" | "tool-poisoning" => VulnerabilityType::ToolPoisoning,
            "prompt_injection" | "prompt-injection" | "llm_injection" => {
                VulnerabilityType::PromptInjection
            }
            "cross_origin_escalation" | "cross-origin" | "cors" => {
                VulnerabilityType::CrossOriginEscalation
            }
            _ => {
                debug!("Unknown vulnerability type '{}', defaulting to CommandInjection", type_str);
                VulnerabilityType::CommandInjection
            }
        }
    }

    /// Parse severity from string
    fn parse_severity(severity_str: &str) -> Severity {
        match severity_str.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" | "moderate" => Severity::Medium,
            "low" => Severity::Low,
            _ => {
                debug!("Unknown severity '{}', defaulting to Medium", severity_str);
                Severity::Medium
            }
        }
    }

    /// Extract JSON from potentially mixed response
    ///
    /// Some models may wrap JSON in markdown code blocks or add extra text.
    /// This function attempts to extract valid JSON from the response.
    fn extract_json(response: &str) -> Option<serde_json::Value> {
        // Try parsing directly first
        if let Ok(json) = serde_json::from_str(response) {
            return Some(json);
        }

        // Try extracting from code blocks
        let patterns = [
            (r"```json\s*\n(.*?)\n```", 1),
            (r"```\s*\n(.*?)\n```", 1),
            (r"\{.*\}", 0),
        ];

        for (pattern, group) in patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(captures) = re.captures(response) {
                    if let Some(json_str) = captures.get(group) {
                        if let Ok(json) = serde_json::from_str(json_str.as_str()) {
                            return Some(json);
                        }
                    }
                }
            }
        }

        None
    }
}

#[async_trait]
impl LLMProvider for OllamaProvider {
    #[instrument(skip(self, code, context), fields(
        file = %context.file_path,
        language = %context.language,
        code_len = code.len()
    ))]
    async fn analyze_code(
        &self,
        code: &str,
        context: &AnalysisContext,
    ) -> Result<AIFinding> {
        info!("Starting AI code analysis");

        // Construct analysis prompt
        let prompt = format!(
            r#"You are a security expert analyzing code for vulnerabilities.

Programming Language: {}
File: {}
{}

Code to analyze:
```
{}
```

Analyze this code for security vulnerabilities. Focus on:
- Command injection (os.system, subprocess, exec, eval)
- Hardcoded secrets (API keys, passwords, tokens)
- Sensitive file access (SSH keys, credentials, cookies)
- Prompt injection (LLM manipulation)
- Cross-origin issues

Respond with ONLY valid JSON (no markdown, no extra text):
{{
  "has_vulnerability": true/false,
  "type": "command_injection|secrets_leakage|sensitive_file_access|prompt_injection|tool_poisoning|cross_origin_escalation",
  "severity": "critical|high|medium|low",
  "confidence": 0.0-1.0,
  "description": "Brief one-sentence description",
  "explanation": "Detailed explanation of the vulnerability",
  "remediation": "Specific steps to fix this issue",
  "line_number": optional line number where vulnerability is,
  "false_positive_likelihood": 0.0-1.0
}}

If no vulnerability found, set has_vulnerability to false and omit other fields."#,
            context.language,
            context.file_path,
            context
                .suspected_type
                .as_ref()
                .map_or(String::new(), |t| format!("Suspected Issue: {}", t)),
            code
        );

        let start = std::time::Instant::now();
        let response = self.generate(&prompt).await?;
        let duration = start.elapsed();

        debug!("Received analysis response: {} chars", response.len());

        // Parse JSON response
        let parsed = Self::extract_json(&response)
            .context("Failed to extract valid JSON from Ollama response")?;

        // Check if vulnerability was found
        if !parsed["has_vulnerability"].as_bool().unwrap_or(false) {
            return Err(anyhow::anyhow!("No vulnerability detected by AI analysis"));
        }

        // Extract vulnerability details
        let vuln_type_str = parsed["type"]
            .as_str()
            .unwrap_or("command_injection");
        let severity_str = parsed["severity"]
            .as_str()
            .unwrap_or("medium");

        Ok(AIFinding {
            vuln_type: Self::parse_vuln_type(vuln_type_str),
            severity: Self::parse_severity(severity_str),
            confidence: parsed["confidence"]
                .as_f64()
                .unwrap_or(0.7)
                .clamp(0.0, 1.0),
            description: parsed["description"]
                .as_str()
                .unwrap_or("Security vulnerability detected")
                .to_string(),
            explanation: parsed["explanation"]
                .as_str()
                .unwrap_or("AI detected a potential security issue")
                .to_string(),
            remediation: parsed["remediation"]
                .as_str()
                .unwrap_or("Review and fix the security issue")
                .to_string(),
            code_snippet: Some(code.to_string()),
            file_path: context.file_path.clone(),
            line_number: parsed["line_number"].as_u64().map(|n| n as usize),
            column: None,
            provider: self.name().to_string(),
            model: self.model().to_string(),
            context: AnalysisMetadata {
                language: context.language.clone(),
                scope: context.scope.clone(),
                timestamp: chrono::Utc::now(),
                duration_ms: duration.as_millis() as u64,
                tokens_used: None, // Ollama doesn't provide token count
                cost_usd: Some(0.0), // Free!
            },
            insights: vec![],
            false_positive_likelihood: parsed["false_positive_likelihood"]
                .as_f64()
                .unwrap_or(0.3)
                .clamp(0.0, 1.0),
            impact: None,
        })
    }

    #[instrument(skip(self, vuln, code))]
    async fn explain_vulnerability(
        &self,
        vuln: &Vulnerability,
        code: &str,
    ) -> Result<String> {
        let prompt = format!(
            r#"Explain this security vulnerability in detail for a developer:

Vulnerability Type: {}
Severity: {:?}
Location: {}:{}

Code:
```
{}
```

Provide a clear, detailed explanation that helps the developer understand:
1. What the vulnerability is
2. Why it's dangerous
3. How an attacker could exploit it
4. Real-world impact

Be specific and technical."#,
            vuln.title,
            vuln.severity,
            vuln.location.file,
            vuln.location.line.unwrap_or(0),
            code
        );

        self.generate(&prompt).await
    }

    #[instrument(skip(self, vuln))]
    async fn generate_remediation(&self, vuln: &Vulnerability) -> Result<String> {
        let prompt = format!(
            r#"Provide step-by-step remediation for this security vulnerability:

Type: {}
Severity: {:?}
Description: {}

Provide:
1. Immediate steps to fix
2. Code examples showing the fix
3. Best practices to prevent recurrence
4. Testing recommendations

Be specific and actionable."#,
            vuln.title, vuln.severity, vuln.description
        );

        self.generate(&prompt).await
    }

    fn name(&self) -> &str {
        "ollama"
    }

    fn cost_per_request(&self) -> f64 {
        0.0 // Local, completely free!
    }

    #[instrument(skip(self))]
    async fn health_check(&self) -> Result<bool> {
        debug!("Performing Ollama health check");

        let url = format!("{}/api/tags", self.settings.url);
        match self.client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                info!("Ollama health check passed");
                Ok(true)
            }
            Ok(resp) => {
                warn!("Ollama health check failed with status: {}", resp.status());
                Ok(false)
            }
            Err(e) => {
                error!("Ollama health check failed: {}", e);
                Ok(false)
            }
        }
    }

    fn model(&self) -> &str {
        &self.settings.model
    }

    fn is_local(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_vuln_type() {
        assert!(matches!(
            OllamaProvider::parse_vuln_type("command_injection"),
            VulnerabilityType::CommandInjection
        ));
        assert!(matches!(
            OllamaProvider::parse_vuln_type("secrets-leakage"),
            VulnerabilityType::SecretsLeakage
        ));
    }

    #[test]
    fn test_parse_severity() {
        assert_eq!(OllamaProvider::parse_severity("critical"), Severity::Critical);
        assert_eq!(OllamaProvider::parse_severity("high"), Severity::High);
        assert_eq!(OllamaProvider::parse_severity("medium"), Severity::Medium);
        assert_eq!(OllamaProvider::parse_severity("low"), Severity::Low);
    }

    #[test]
    fn test_extract_json_direct() {
        let json_str = r#"{"test": "value"}"#;
        let result = OllamaProvider::extract_json(json_str);
        assert!(result.is_some());
    }

    #[test]
    fn test_extract_json_from_markdown() {
        let markdown = r#"Here's the analysis:
```json
{"test": "value"}
```
That's the result."#;
        let result = OllamaProvider::extract_json(markdown);
        assert!(result.is_some());
    }

    #[test]
    fn test_extract_json_from_mixed() {
        let mixed = r#"Some text {"test": "value"} more text"#;
        let result = OllamaProvider::extract_json(mixed);
        assert!(result.is_some());
    }
}
