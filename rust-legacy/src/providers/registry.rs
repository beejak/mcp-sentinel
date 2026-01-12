//! LLM Provider Registry System
//!
//! This module provides a dynamic registry system for LLM providers,
//! enabling easy addition of new providers without modifying core code.
//!
//! # Design Philosophy
//!
//! The registry uses a builder pattern combined with lazy initialization
//! to support:
//! - Dynamic provider registration
//! - Automatic provider discovery
//! - Type-safe provider construction
//! - Zero-cost abstractions
//!
//! # Adding New Providers
//!
//! To add a new LLM provider:
//!
//! 1. Implement the `LLMProvider` trait for your provider
//! 2. Add a constructor function with signature `fn new(config: &ProviderSettings) -> Result<Self>`
//! 3. Register in `register_all_providers()`
//!
//! ```rust
//! // Example: Adding a new provider
//! use crate::providers::{LLMProvider, ProviderRegistry};
//!
//! pub struct MyNewProvider { /* ... */ }
//!
//! impl LLMProvider for MyNewProvider {
//!     // Implement trait methods
//! }
//!
//! // Register in registry.rs:
//! registry.register(
//!     "mynewprovider",
//!     vec!["mynew", "newprovider"],  // Aliases
//!     |settings| Box::new(MyNewProvider::new(&settings.mynewprovider)?),
//!     ProviderMetadata {
//!         name: "My New Provider",
//!         description: "Description of the provider",
//!         provider_type: ProviderType::Commercial,
//!         supported_features: vec![/* features */],
//!         cost_per_1k_tokens: Some(0.001),
//!         requires_api_key: true,
//!         local_only: false,
//!         documentation_url: "https://example.com/docs",
//!     },
//! );
//! ```

use super::{LLMProvider, ProviderSettings};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

/// Provider constructor function type
type ProviderConstructor = Box<dyn Fn(&ProviderSettings) -> Result<Box<dyn LLMProvider>> + Send + Sync>;

/// Provider registry for managing all LLM providers
pub struct ProviderRegistry {
    /// Map of provider name to constructor and metadata
    providers: HashMap<String, (ProviderConstructor, ProviderMetadata)>,

    /// Map of aliases to canonical provider names
    aliases: HashMap<String, String>,
}

/// Provider metadata for documentation and discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMetadata {
    /// Display name of the provider
    pub name: &'static str,

    /// Brief description
    pub description: &'static str,

    /// Provider type (open-source, commercial, etc.)
    pub provider_type: ProviderType,

    /// Supported features
    pub supported_features: Vec<ProviderFeature>,

    /// Cost per 1K tokens (None if local/free)
    pub cost_per_1k_tokens: Option<f64>,

    /// Whether API key is required
    pub requires_api_key: bool,

    /// Whether this is a local-only provider
    pub local_only: bool,

    /// Documentation URL
    pub documentation_url: &'static str,
}

/// Provider type classification
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProviderType {
    /// Open-source, self-hosted
    OpenSource,

    /// Commercial API service
    Commercial,

    /// Hybrid (can be self-hosted or cloud)
    Hybrid,
}

/// Provider feature flags
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProviderFeature {
    /// Code analysis
    CodeAnalysis,

    /// Vulnerability detection
    VulnerabilityDetection,

    /// Remediation suggestions
    RemediationGeneration,

    /// Explanation generation
    ExplanationGeneration,

    /// Streaming responses
    Streaming,

    /// Function calling
    FunctionCalling,

    /// JSON mode
    JsonMode,

    /// Multi-modal (images, etc.)
    MultiModal,
}

impl ProviderRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            aliases: HashMap::new(),
        }
    }

    /// Register a provider with the registry
    ///
    /// # Arguments
    ///
    /// * `name` - Canonical name (lowercase, no spaces)
    /// * `aliases` - Alternative names for this provider
    /// * `constructor` - Function to construct the provider
    /// * `metadata` - Provider metadata for documentation
    pub fn register<F>(
        &mut self,
        name: &str,
        aliases: Vec<&str>,
        constructor: F,
        metadata: ProviderMetadata,
    ) where
        F: Fn(&ProviderSettings) -> Result<Box<dyn LLMProvider>> + Send + Sync + 'static,
    {
        let canonical_name = name.to_lowercase();

        // Register main name
        self.providers.insert(
            canonical_name.clone(),
            (Box::new(constructor), metadata),
        );

        // Register aliases
        for alias in aliases {
            self.aliases.insert(
                alias.to_lowercase(),
                canonical_name.clone(),
            );
        }

        debug!("Registered provider: {} (aliases: {:?})", name, aliases);
    }

    /// Create a provider by name
    ///
    /// # Arguments
    ///
    /// * `name` - Provider name or alias
    /// * `settings` - Provider settings
    ///
    /// # Returns
    ///
    /// An Arc-wrapped LLM provider instance
    ///
    /// # Errors
    ///
    /// - Provider not found
    /// - Provider initialization failed
    pub fn create(
        &self,
        name: &str,
        settings: &ProviderSettings,
    ) -> Result<Arc<dyn LLMProvider>> {
        let canonical_name = self.resolve_name(name)?;

        let (constructor, metadata) = self.providers
            .get(&canonical_name)
            .context(format!("Provider '{}' not registered", name))?;

        info!(
            "Creating provider: {} (type: {:?})",
            metadata.name,
            metadata.provider_type
        );

        let provider = constructor(settings)
            .context(format!("Failed to create provider '{}'", metadata.name))?;

        Ok(Arc::from(provider))
    }

    /// Resolve a name or alias to canonical name
    fn resolve_name(&self, name: &str) -> Result<String> {
        let lower_name = name.to_lowercase();

        // Check if it's a direct name
        if self.providers.contains_key(&lower_name) {
            return Ok(lower_name);
        }

        // Check aliases
        if let Some(canonical) = self.aliases.get(&lower_name) {
            return Ok(canonical.clone());
        }

        anyhow::bail!("Unknown provider: {}", name);
    }

    /// Get metadata for a provider
    pub fn get_metadata(&self, name: &str) -> Option<&ProviderMetadata> {
        let canonical_name = self.resolve_name(name).ok()?;
        self.providers.get(&canonical_name).map(|(_, meta)| meta)
    }

    /// List all registered providers
    pub fn list_providers(&self) -> Vec<(&str, &ProviderMetadata)> {
        self.providers
            .iter()
            .map(|(name, (_, meta))| (name.as_str(), meta))
            .collect()
    }

    /// List providers by type
    pub fn list_by_type(&self, provider_type: ProviderType) -> Vec<(&str, &ProviderMetadata)> {
        self.providers
            .iter()
            .filter(|(_, (_, meta))| meta.provider_type == provider_type)
            .map(|(name, (_, meta))| (name.as_str(), meta))
            .collect()
    }

    /// List local-only providers (no network calls)
    pub fn list_local_providers(&self) -> Vec<(&str, &ProviderMetadata)> {
        self.providers
            .iter()
            .filter(|(_, (_, meta))| meta.local_only)
            .map(|(name, (_, meta))| (name.as_str(), meta))
            .collect()
    }

    /// List free providers (no API costs)
    pub fn list_free_providers(&self) -> Vec<(&str, &ProviderMetadata)> {
        self.providers
            .iter()
            .filter(|(_, (_, meta))| meta.cost_per_1k_tokens.is_none() || meta.cost_per_1k_tokens == Some(0.0))
            .map(|(name, (_, meta))| (name.as_str(), meta))
            .collect()
    }

    /// Generate markdown documentation for all providers
    pub fn generate_documentation(&self) -> String {
        let mut doc = String::from("# LLM Provider Reference\n\n");
        doc.push_str("This document lists all supported LLM providers for AI-powered vulnerability analysis.\n\n");

        // Open Source Providers
        doc.push_str("## Open Source Providers\n\n");
        for (name, meta) in self.list_by_type(ProviderType::OpenSource) {
            doc.push_str(&format!("### {}\n\n", meta.name));
            doc.push_str(&format!("**Name**: `{}`\n\n", name));
            doc.push_str(&format!("**Description**: {}\n\n", meta.description));
            doc.push_str(&format!("**Cost**: Free (local)\n\n"));
            doc.push_str(&format!("**Requires API Key**: {}\n\n", if meta.requires_api_key { "Yes" } else { "No" }));
            doc.push_str(&format!("**Documentation**: {}\n\n", meta.documentation_url));
            doc.push_str("**Supported Features**:\n");
            for feature in &meta.supported_features {
                doc.push_str(&format!("- {:?}\n", feature));
            }
            doc.push_str("\n---\n\n");
        }

        // Commercial Providers
        doc.push_str("## Commercial Providers\n\n");
        for (name, meta) in self.list_by_type(ProviderType::Commercial) {
            doc.push_str(&format!("### {}\n\n", meta.name));
            doc.push_str(&format!("**Name**: `{}`\n\n", name));
            doc.push_str(&format!("**Description**: {}\n\n", meta.description));
            if let Some(cost) = meta.cost_per_1k_tokens {
                doc.push_str(&format!("**Cost**: ${:.4}/1K tokens\n\n", cost));
            }
            doc.push_str(&format!("**Requires API Key**: {}\n\n", if meta.requires_api_key { "Yes" } else { "No" }));
            doc.push_str(&format!("**Documentation**: {}\n\n", meta.documentation_url));
            doc.push_str("**Supported Features**:\n");
            for feature in &meta.supported_features {
                doc.push_str(&format!("- {:?}\n", feature));
            }
            doc.push_str("\n---\n\n");
        }

        doc
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Global registry instance (lazy initialization)
static GLOBAL_REGISTRY: once_cell::sync::Lazy<std::sync::RwLock<ProviderRegistry>> =
    once_cell::sync::Lazy::new(|| {
        let mut registry = ProviderRegistry::new();
        register_all_providers(&mut registry);
        std::sync::RwLock::new(registry)
    });

/// Get the global provider registry
pub fn global_registry() -> &'static std::sync::RwLock<ProviderRegistry> {
    &GLOBAL_REGISTRY
}

/// Register all available providers
///
/// This function is called once during initialization to register
/// all built-in providers. New providers should be added here.
fn register_all_providers(registry: &mut ProviderRegistry) {
    // Note: Individual providers will be registered here as they're implemented
    // This is a placeholder that will be filled in as we implement each provider

    info!("Registering all LLM providers...");

    // Providers will be registered here in subsequent implementations
    // Example:
    // registry.register(
    //     "ollama",
    //     vec!["ol", "local"],
    //     |settings| Box::new(super::ollama::OllamaProvider::new(&settings.ollama)?),
    //     ProviderMetadata { /* ... */ },
    // );

    debug!("Provider registration complete");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = ProviderRegistry::new();
        assert_eq!(registry.providers.len(), 0);
    }

    #[test]
    fn test_provider_type_serialization() {
        let pt = ProviderType::OpenSource;
        let json = serde_json::to_string(&pt).unwrap();
        assert!(json.contains("OpenSource"));
    }

    #[test]
    fn test_provider_feature_list() {
        let features = vec![
            ProviderFeature::CodeAnalysis,
            ProviderFeature::VulnerabilityDetection,
        ];
        assert_eq!(features.len(), 2);
    }
}
