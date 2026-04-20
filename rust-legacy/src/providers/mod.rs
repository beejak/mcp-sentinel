//! LLM Provider Abstraction Layer
//!
//! This module provides a unified interface for multiple LLM providers,
//! enabling AI-powered vulnerability analysis with support for both
//! commercial APIs (OpenAI, Anthropic, etc.) and local models (Ollama).
//!
//! # Supported Providers
//!
//! - **OpenAI**: GPT-3.5-turbo, GPT-4, GPT-4-turbo
//! - **Anthropic**: Claude 3 (Opus, Sonnet, Haiku)
//! - **Ollama**: Local models (llama3, mistral, codellama, etc.)
//! - **Mistral AI**: Mistral Large, Medium, Small
//! - **Cohere**: Command, Command-Light
//! - **HuggingFace**: Any inference API model
//! - **Google**: Gemini Pro, Gemini Ultra
//! - **Azure OpenAI**: Azure-hosted GPT models
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │     AI Analysis Engine              │
//! └──────────────┬──────────────────────┘
//!                │
//!         ┌──────▼──────┐
//!         │   Provider  │
//!         │   Factory   │
//!         └──────┬──────┘
//!                │
//!     ┌──────────┼──────────┐
//!     │          │          │
//! ┌───▼───┐  ┌──▼──┐   ┌───▼───┐
//! │OpenAI │  │Ollama│   │Claude │
//! └───────┘  └──────┘   └───────┘
//! ```
//!
//! # Usage
//!
//! ```rust
//! use mcp_sentinel::providers::{ProviderFactory, ProviderConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = ProviderConfig {
//!         primary: "ollama".to_string(),
//!         fallbacks: vec!["openai".to_string()],
//!         budget_limit: 1.0,
//!         ..Default::default()
//!     };
//!
//!     let provider = ProviderFactory::create(&config).await?;
//!     let finding = provider.analyze_code(code, &context).await?;
//!
//!     Ok(())
//! }
//! ```

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info, warn};

pub mod openai;
pub mod anthropic;
pub mod ollama;
pub mod mistral;
pub mod cohere;
pub mod huggingface;
pub mod google;
pub mod azure;

use crate::models::{Vulnerability, ai_finding::AIFinding};

/// Context information for AI analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisContext {
    /// File path being analyzed
    pub file_path: String,

    /// Programming language
    pub language: String,

    /// Function or class name (if known)
    pub scope: Option<String>,

    /// Line number of suspicious code
    pub line_number: Option<usize>,

    /// Existing vulnerability type (if pre-detected)
    pub suspected_type: Option<String>,

    /// Additional context (nearby code, imports, etc.)
    pub additional_context: Option<String>,
}

/// Unified LLM provider interface
///
/// All LLM providers must implement this trait to be usable
/// by the AI analysis engine.
#[async_trait]
pub trait LLMProvider: Send + Sync {
    /// Analyze a code snippet for security vulnerabilities
    ///
    /// # Arguments
    ///
    /// * `code` - The code snippet to analyze (max 50 lines recommended)
    /// * `context` - Additional context about the code
    ///
    /// # Returns
    ///
    /// An AI finding with vulnerability details, confidence score, and remediation
    ///
    /// # Errors
    ///
    /// - Network failures
    /// - API rate limits
    /// - Invalid API keys
    /// - Model unavailable
    async fn analyze_code(
        &self,
        code: &str,
        context: &AnalysisContext,
    ) -> Result<AIFinding>;

    /// Explain a detected vulnerability in detail
    ///
    /// # Arguments
    ///
    /// * `vuln` - The detected vulnerability
    /// * `code` - The vulnerable code snippet
    ///
    /// # Returns
    ///
    /// A human-readable explanation of why this is a vulnerability
    async fn explain_vulnerability(
        &self,
        vuln: &Vulnerability,
        code: &str,
    ) -> Result<String>;

    /// Generate actionable remediation guidance
    ///
    /// # Arguments
    ///
    /// * `vuln` - The vulnerability to remediate
    ///
    /// # Returns
    ///
    /// Specific steps to fix the vulnerability, including code examples
    async fn generate_remediation(
        &self,
        vuln: &Vulnerability,
    ) -> Result<String>;

    /// Get the provider name
    fn name(&self) -> &str;

    /// Get the cost per request in USD
    ///
    /// For local models (Ollama), this should return 0.0
    fn cost_per_request(&self) -> f64;

    /// Check if the provider is available and healthy
    ///
    /// # Returns
    ///
    /// true if provider is ready, false otherwise
    async fn health_check(&self) -> Result<bool>;

    /// Get the model being used
    fn model(&self) -> &str;

    /// Check if this is a local provider (no network calls)
    fn is_local(&self) -> bool {
        false
    }
}

/// Provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Primary provider to use
    pub primary: String,

    /// Fallback providers (in order of preference)
    pub fallbacks: Vec<String>,

    /// Budget limit in USD per scan
    pub budget_limit: f64,

    /// Maximum requests per scan
    pub max_requests: usize,

    /// Prefer local providers over remote
    pub prefer_local: bool,

    /// Provider-specific settings
    pub providers: ProviderSettings,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            primary: "ollama".to_string(),
            fallbacks: vec!["openai".to_string()],
            budget_limit: 1.0,
            max_requests: 50,
            prefer_local: true,
            providers: ProviderSettings::default(),
        }
    }
}

/// Provider-specific settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderSettings {
    pub openai: OpenAISettings,
    pub anthropic: AnthropicSettings,
    pub ollama: OllamaSettings,
    pub mistral: MistralSettings,
    pub cohere: CohereSettings,
    pub huggingface: HuggingFaceSettings,
    pub google: GoogleSettings,
    pub azure: AzureSettings,
}

impl Default for ProviderSettings {
    fn default() -> Self {
        Self {
            openai: OpenAISettings::default(),
            anthropic: AnthropicSettings::default(),
            ollama: OllamaSettings::default(),
            mistral: MistralSettings::default(),
            cohere: CohereSettings::default(),
            huggingface: HuggingFaceSettings::default(),
            google: GoogleSettings::default(),
            azure: AzureSettings::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAISettings {
    pub model: String,
    pub api_key_env: String,
    pub temperature: f32,
    pub max_tokens: usize,
}

impl Default for OpenAISettings {
    fn default() -> Self {
        Self {
            model: "gpt-3.5-turbo".to_string(),
            api_key_env: "OPENAI_API_KEY".to_string(),
            temperature: 0.1,
            max_tokens: 2000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnthropicSettings {
    pub model: String,
    pub api_key_env: String,
    pub max_tokens: usize,
}

impl Default for AnthropicSettings {
    fn default() -> Self {
        Self {
            model: "claude-3-haiku-20240307".to_string(),
            api_key_env: "ANTHROPIC_API_KEY".to_string(),
            max_tokens: 2000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OllamaSettings {
    pub url: String,
    pub model: String,
    pub timeout_seconds: u64,
}

impl Default for OllamaSettings {
    fn default() -> Self {
        Self {
            url: "http://localhost:11434".to_string(),
            model: "codellama".to_string(),
            timeout_seconds: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MistralSettings {
    pub model: String,
    pub api_key_env: String,
}

impl Default for MistralSettings {
    fn default() -> Self {
        Self {
            model: "mistral-small-latest".to_string(),
            api_key_env: "MISTRAL_API_KEY".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CohereSettings {
    pub model: String,
    pub api_key_env: String,
}

impl Default for CohereSettings {
    fn default() -> Self {
        Self {
            model: "command-light".to_string(),
            api_key_env: "COHERE_API_KEY".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuggingFaceSettings {
    pub model: String,
    pub api_key_env: String,
}

impl Default for HuggingFaceSettings {
    fn default() -> Self {
        Self {
            model: "codellama/CodeLlama-7b-hf".to_string(),
            api_key_env: "HUGGINGFACE_API_KEY".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleSettings {
    pub model: String,
    pub api_key_env: String,
}

impl Default for GoogleSettings {
    fn default() -> Self {
        Self {
            model: "gemini-pro".to_string(),
            api_key_env: "GOOGLE_API_KEY".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureSettings {
    pub model: String,
    pub api_key_env: String,
    pub endpoint_env: String,
    pub deployment_name: String,
}

impl Default for AzureSettings {
    fn default() -> Self {
        Self {
            model: "gpt-35-turbo".to_string(),
            api_key_env: "AZURE_OPENAI_KEY".to_string(),
            endpoint_env: "AZURE_OPENAI_ENDPOINT".to_string(),
            deployment_name: "gpt-35-turbo".to_string(),
        }
    }
}

/// Provider factory for creating LLM providers
pub struct ProviderFactory;

impl ProviderFactory {
    /// Create a provider based on configuration
    ///
    /// # Arguments
    ///
    /// * `config` - Provider configuration
    ///
    /// # Returns
    ///
    /// An Arc-wrapped provider instance
    ///
    /// # Errors
    ///
    /// - Provider not found
    /// - Provider initialization failed
    /// - Missing API keys
    pub async fn create(config: &ProviderConfig) -> Result<Arc<dyn LLMProvider>> {
        info!("Creating LLM provider: {}", config.primary);

        // Try primary provider
        match Self::create_provider(&config.primary, config).await {
            Ok(provider) => {
                info!("Successfully initialized primary provider: {}", config.primary);
                return Ok(provider);
            }
            Err(e) => {
                warn!(
                    "Failed to initialize primary provider {}: {}",
                    config.primary, e
                );
            }
        }

        // Try fallback providers
        for fallback in &config.fallbacks {
            debug!("Trying fallback provider: {}", fallback);
            match Self::create_provider(fallback, config).await {
                Ok(provider) => {
                    info!("Using fallback provider: {}", fallback);
                    return Ok(provider);
                }
                Err(e) => {
                    warn!("Fallback provider {} failed: {}", fallback, e);
                }
            }
        }

        anyhow::bail!(
            "Failed to initialize any LLM provider. Primary: {}, Fallbacks: {:?}",
            config.primary,
            config.fallbacks
        );
    }

    /// Create a specific provider by name
    async fn create_provider(
        name: &str,
        config: &ProviderConfig,
    ) -> Result<Arc<dyn LLMProvider>> {
        match name.to_lowercase().as_str() {
            "openai" => {
                let provider = openai::OpenAIProvider::new(&config.providers.openai)
                    .context("Failed to create OpenAI provider")?;
                Ok(Arc::new(provider))
            }
            "anthropic" | "claude" => {
                let provider = anthropic::AnthropicProvider::new(&config.providers.anthropic)
                    .context("Failed to create Anthropic provider")?;
                Ok(Arc::new(provider))
            }
            "ollama" => {
                let provider = ollama::OllamaProvider::new(&config.providers.ollama)
                    .await
                    .context("Failed to create Ollama provider")?;
                Ok(Arc::new(provider))
            }
            "mistral" => {
                let provider = mistral::MistralProvider::new(&config.providers.mistral)
                    .context("Failed to create Mistral provider")?;
                Ok(Arc::new(provider))
            }
            "cohere" => {
                let provider = cohere::CohereProvider::new(&config.providers.cohere)
                    .context("Failed to create Cohere provider")?;
                Ok(Arc::new(provider))
            }
            "huggingface" | "hf" => {
                let provider = huggingface::HuggingFaceProvider::new(&config.providers.huggingface)
                    .context("Failed to create HuggingFace provider")?;
                Ok(Arc::new(provider))
            }
            "google" | "gemini" => {
                let provider = google::GoogleProvider::new(&config.providers.google)
                    .context("Failed to create Google provider")?;
                Ok(Arc::new(provider))
            }
            "azure" | "azure-openai" => {
                let provider = azure::AzureProvider::new(&config.providers.azure)
                    .context("Failed to create Azure provider")?;
                Ok(Arc::new(provider))
            }
            _ => anyhow::bail!("Unknown LLM provider: {}", name),
        }
    }

    /// Get list of available providers
    pub fn available_providers() -> Vec<String> {
        vec![
            "openai".to_string(),
            "anthropic".to_string(),
            "ollama".to_string(),
            "mistral".to_string(),
            "cohere".to_string(),
            "huggingface".to_string(),
            "google".to_string(),
            "azure".to_string(),
        ]
    }
}

/// Provider health check results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderHealth {
    pub name: String,
    pub available: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

/// Check health of all configured providers
pub async fn check_all_providers(config: &ProviderConfig) -> Vec<ProviderHealth> {
    let mut results = Vec::new();

    for provider_name in ProviderFactory::available_providers() {
        let start = std::time::Instant::now();
        match ProviderFactory::create_provider(&provider_name, config).await {
            Ok(provider) => {
                let available = provider.health_check().await.unwrap_or(false);
                results.push(ProviderHealth {
                    name: provider_name,
                    available,
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    error: None,
                });
            }
            Err(e) => {
                results.push(ProviderHealth {
                    name: provider_name,
                    available: false,
                    latency_ms: None,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_config_default() {
        let config = ProviderConfig::default();
        assert_eq!(config.primary, "ollama");
        assert!(config.prefer_local);
        assert!(config.budget_limit > 0.0);
    }

    #[test]
    fn test_available_providers() {
        let providers = ProviderFactory::available_providers();
        assert!(providers.contains(&"openai".to_string()));
        assert!(providers.contains(&"ollama".to_string()));
        assert!(providers.contains(&"anthropic".to_string()));
    }
}
