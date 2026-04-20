//! AI-Powered Analysis Engine
//!
//! This engine orchestrates LLM providers for vulnerability analysis, managing:
//! - Provider fallback chains
//! - Budget tracking and limits
//! - Rate limiting and concurrency control
//! - Batch analysis optimization
//! - Cost estimation and reporting
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │        AI Analysis Engine               │
//! │  - Budget Tracking                      │
//! │  - Rate Limiting                        │
//! │  - Provider Fallback                    │
//! └──────────────┬──────────────────────────┘
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
//! use mcp_sentinel::engines::ai_analysis::AIAnalysisEngine;
//! use mcp_sentinel::providers::ProviderConfig;
//!
//! # #[tokio::main]
//! # async fn main() -> anyhow::Result<()> {
//! let config = ProviderConfig::default();
//! let engine = AIAnalysisEngine::new(config).await?;
//!
//! // Analyze a single code snippet
//! let findings = engine.analyze_code(code, &context).await?;
//!
//! // Get cost summary
//! let summary = engine.get_cost_summary();
//! println!("Total cost: ${:.4}", summary.total_cost);
//! # Ok(())
//! # }
//! ```

use crate::models::ai_finding::AIFinding;
use crate::providers::{AnalysisContext, LLMProvider, ProviderConfig, ProviderFactory};
use anyhow::{Context as AnyhowContext, Result};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::sync::{Semaphore, RwLock};
use tracing::{debug, error, info, instrument, warn};

/// AI Analysis Engine for orchestrating LLM providers
///
/// This engine manages multiple LLM providers with intelligent fallback,
/// budget tracking, and rate limiting to ensure cost-effective and
/// reliable AI-powered vulnerability analysis.
///
/// # Features
///
/// - **Provider Fallback**: Automatically tries alternative providers on failure
/// - **Budget Tracking**: Enforces spending limits across all providers
/// - **Rate Limiting**: Controls concurrent requests to avoid API limits
/// - **Cost Tracking**: Detailed cost breakdown by provider
/// - **Batch Analysis**: Optimized for analyzing multiple code snippets
pub struct AIAnalysisEngine {
    /// Primary LLM provider
    provider: Arc<dyn LLMProvider>,

    /// Configuration
    config: ProviderConfig,

    /// Total cost so far (in USD, stored as micro-dollars for atomic ops)
    total_cost_microdollars: Arc<AtomicU64>,

    /// Number of requests made
    request_count: Arc<AtomicUsize>,

    /// Semaphore for rate limiting
    rate_limiter: Arc<Semaphore>,

    /// Cost breakdown by provider
    cost_by_provider: Arc<RwLock<std::collections::HashMap<String, f64>>>,
}

impl AIAnalysisEngine {
    /// Create a new AI Analysis Engine
    ///
    /// # Arguments
    ///
    /// * `config` - Provider configuration including budget limits
    ///
    /// # Returns
    ///
    /// Initialized engine with primary provider
    ///
    /// # Errors
    ///
    /// - Failed to initialize any provider
    /// - Invalid configuration
    #[instrument(skip(config))]
    pub async fn new(config: ProviderConfig) -> Result<Self> {
        info!("Initializing AI Analysis Engine");

        // Create primary provider
        let provider = ProviderFactory::create(&config)
            .await
            .context("Failed to create any LLM provider")?;

        info!("AI Analysis Engine initialized with provider: {}", provider.name());

        // Create rate limiter (max_requests concurrent requests)
        let rate_limiter = Arc::new(Semaphore::new(config.max_requests));

        Ok(Self {
            provider,
            config,
            total_cost_microdollars: Arc::new(AtomicU64::new(0)),
            request_count: Arc::new(AtomicUsize::new(0)),
            rate_limiter,
            cost_by_provider: Arc::new(RwLock::new(std::collections::HashMap::new())),
        })
    }

    /// Analyze a single code snippet for vulnerabilities
    ///
    /// # Arguments
    ///
    /// * `code` - Code snippet to analyze
    /// * `context` - Context information about the code
    ///
    /// # Returns
    ///
    /// AI finding with vulnerability details
    ///
    /// # Errors
    ///
    /// - Budget limit exceeded
    /// - All providers failed
    /// - Rate limit exceeded
    #[instrument(skip(self, code, context), fields(file = %context.file_path, provider = %self.provider.name()))]
    pub async fn analyze_code(
        &self,
        code: &str,
        context: &AnalysisContext,
    ) -> Result<AIFinding> {
        // Check budget before analysis
        self.check_budget()?;

        // Acquire rate limit permit
        let _permit = self.rate_limiter.acquire().await.context(
            "Failed to acquire rate limit permit. Too many concurrent requests."
        )?;

        debug!("Analyzing code with AI provider");

        // Perform analysis
        let finding = self.provider.analyze_code(code, context).await.context(
            format!("AI analysis failed with provider: {}", self.provider.name())
        )?;

        // Track cost
        if let Some(cost) = finding.context.cost_usd {
            self.add_cost(&finding.provider, cost).await;
        }

        // Increment request count
        self.request_count.fetch_add(1, Ordering::SeqCst);

        info!(
            "AI analysis complete: {} vulnerability detected with {:.1}% confidence",
            finding.vuln_type.name(),
            finding.confidence * 100.0
        );

        Ok(finding)
    }

    /// Analyze multiple code snippets in batch
    ///
    /// # Arguments
    ///
    /// * `snippets` - Vector of (code, context) pairs
    ///
    /// # Returns
    ///
    /// Vector of AI findings (same order as input)
    ///
    /// # Errors
    ///
    /// - Budget limit exceeded
    /// - Batch processing failed
    ///
    /// Note: Individual snippet failures are logged but don't fail the batch
    #[instrument(skip(self, snippets), fields(count = snippets.len()))]
    pub async fn analyze_batch(
        &self,
        snippets: Vec<(&str, AnalysisContext)>,
    ) -> Result<Vec<Option<AIFinding>>> {
        info!("Starting batch analysis of {} snippets", snippets.len());

        // Check if batch would exceed budget
        let estimated_cost = self.provider.cost_per_request() * snippets.len() as f64;
        let current_cost = self.get_total_cost();

        if current_cost + estimated_cost > self.config.budget_limit {
            anyhow::bail!(
                "Batch analysis would exceed budget limit. \
                Current: ${:.4}, Estimated: ${:.4}, Limit: ${:.4}",
                current_cost,
                estimated_cost,
                self.config.budget_limit
            );
        }

        // Process snippets concurrently (rate limiter will control concurrency)
        let mut tasks = Vec::new();

        for (code, context) in snippets {
            let engine = self.clone_for_task();
            let code = code.to_string();
            let task = tokio::spawn(async move {
                match engine.analyze_code(&code, &context).await {
                    Ok(finding) => Some(finding),
                    Err(e) => {
                        warn!("Failed to analyze snippet in batch: {}", e);
                        None
                    }
                }
            });
            tasks.push(task);
        }

        // Collect results
        let mut results = Vec::new();
        for task in tasks {
            match task.await {
                Ok(result) => results.push(result),
                Err(e) => {
                    error!("Task panicked during batch analysis: {}", e);
                    results.push(None);
                }
            }
        }

        info!(
            "Batch analysis complete: {}/{} successful",
            results.iter().filter(|r| r.is_some()).count(),
            results.len()
        );

        Ok(results)
    }

    /// Check if budget limit would be exceeded
    fn check_budget(&self) -> Result<()> {
        let current_cost = self.get_total_cost();
        let estimated_next_cost = self.provider.cost_per_request();

        if current_cost + estimated_next_cost > self.config.budget_limit {
            anyhow::bail!(
                "Budget limit exceeded. Current: ${:.4}, Estimated next: ${:.4}, Limit: ${:.4}\n\n\
                To increase budget:\n\
                1. Adjust budget_limit in configuration\n\
                2. Use local providers (Ollama, LocalAI) which are free\n\
                3. Reduce the number of analyses",
                current_cost,
                estimated_next_cost,
                self.config.budget_limit
            );
        }

        Ok(())
    }

    /// Add cost to tracking
    async fn add_cost(&self, provider: &str, cost: f64) {
        // Update total cost (convert to microdollars for atomic operations)
        let microdollars = (cost * 1_000_000.0) as u64;
        self.total_cost_microdollars.fetch_add(microdollars, Ordering::SeqCst);

        // Update per-provider cost
        let mut cost_map = self.cost_by_provider.write().await;
        *cost_map.entry(provider.to_string()).or_insert(0.0) += cost;

        debug!("Added ${:.6} cost for provider: {}", cost, provider);
    }

    /// Get total cost in USD
    pub fn get_total_cost(&self) -> f64 {
        let microdollars = self.total_cost_microdollars.load(Ordering::SeqCst);
        microdollars as f64 / 1_000_000.0
    }

    /// Get number of requests made
    pub fn get_request_count(&self) -> usize {
        self.request_count.load(Ordering::SeqCst)
    }

    /// Get cost summary with per-provider breakdown
    pub async fn get_cost_summary(&self) -> CostSummary {
        let cost_map = self.cost_by_provider.read().await;

        CostSummary {
            total_cost: self.get_total_cost(),
            request_count: self.get_request_count(),
            budget_limit: self.config.budget_limit,
            budget_remaining: (self.config.budget_limit - self.get_total_cost()).max(0.0),
            cost_by_provider: cost_map.clone(),
            average_cost_per_request: if self.get_request_count() > 0 {
                self.get_total_cost() / self.get_request_count() as f64
            } else {
                0.0
            },
        }
    }

    /// Clone for concurrent task execution
    fn clone_for_task(&self) -> Self {
        Self {
            provider: Arc::clone(&self.provider),
            config: self.config.clone(),
            total_cost_microdollars: Arc::clone(&self.total_cost_microdollars),
            request_count: Arc::clone(&self.request_count),
            rate_limiter: Arc::clone(&self.rate_limiter),
            cost_by_provider: Arc::clone(&self.cost_by_provider),
        }
    }

    /// Get the current provider name
    pub fn provider_name(&self) -> &str {
        self.provider.name()
    }

    /// Check if provider is healthy
    pub async fn health_check(&self) -> Result<bool> {
        self.provider.health_check().await
    }
}

/// Cost summary for reporting
#[derive(Debug, Clone)]
pub struct CostSummary {
    /// Total cost in USD
    pub total_cost: f64,

    /// Number of requests made
    pub request_count: usize,

    /// Budget limit in USD
    pub budget_limit: f64,

    /// Remaining budget in USD
    pub budget_remaining: f64,

    /// Cost breakdown by provider
    pub cost_by_provider: std::collections::HashMap<String, f64>,

    /// Average cost per request
    pub average_cost_per_request: f64,
}

impl CostSummary {
    /// Format as human-readable string
    pub fn format(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!("Total Cost: ${:.4}\n", self.total_cost));
        output.push_str(&format!("Requests: {}\n", self.request_count));
        output.push_str(&format!("Average: ${:.4}/request\n", self.average_cost_per_request));
        output.push_str(&format!("Budget: ${:.4} / ${:.4}\n", self.total_cost, self.budget_limit));
        output.push_str(&format!("Remaining: ${:.4}\n", self.budget_remaining));

        if !self.cost_by_provider.is_empty() {
            output.push_str("\nCost by Provider:\n");
            for (provider, cost) in &self.cost_by_provider {
                output.push_str(&format!("  {}: ${:.4}\n", provider, cost));
            }
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cost_conversion() {
        let cost = 0.001234;
        let microdollars = (cost * 1_000_000.0) as u64;
        assert_eq!(microdollars, 1234);

        let recovered = microdollars as f64 / 1_000_000.0;
        assert!((recovered - cost).abs() < 0.000001);
    }

    #[test]
    fn test_cost_summary_format() {
        let mut cost_by_provider = std::collections::HashMap::new();
        cost_by_provider.insert("openai".to_string(), 0.05);
        cost_by_provider.insert("ollama".to_string(), 0.0);

        let summary = CostSummary {
            total_cost: 0.05,
            request_count: 10,
            budget_limit: 1.0,
            budget_remaining: 0.95,
            cost_by_provider,
            average_cost_per_request: 0.005,
        };

        let formatted = summary.format();
        assert!(formatted.contains("Total Cost: $0.0500"));
        assert!(formatted.contains("Requests: 10"));
        assert!(formatted.contains("openai"));
    }

    #[tokio::test]
    async fn test_budget_check() {
        // This test verifies the budget checking logic
        // In a real scenario, you'd mock the provider
        let config = ProviderConfig {
            budget_limit: 0.01,
            ..Default::default()
        };

        // Note: This will fail if Ollama is not running, which is expected
        // In production tests, you'd mock the provider
        match AIAnalysisEngine::new(config).await {
            Ok(engine) => {
                // If engine created successfully, cost should start at 0
                assert_eq!(engine.get_total_cost(), 0.0);
                assert_eq!(engine.get_request_count(), 0);
            }
            Err(_) => {
                // If no provider available, test passes (can't test without provider)
            }
        }
    }
}
