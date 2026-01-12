//! Azure OpenAI Provider (Stub - To be implemented)

use super::{AnalysisContext, LLMProvider, AzureSettings};
use crate::models::{ai_finding::AIFinding, Vulnerability};
use anyhow::Result;
use async_trait::async_trait;

pub struct AzureProvider {
    settings: AzureSettings,
}

impl AzureProvider {
    pub fn new(settings: &AzureSettings) -> Result<Self> {
        Ok(Self {
            settings: settings.clone(),
        })
    }
}

#[async_trait]
impl LLMProvider for AzureProvider {
    async fn analyze_code(&self, _code: &str, _context: &AnalysisContext) -> Result<AIFinding> {
        anyhow::bail!("Azure OpenAI provider not yet implemented")
    }

    async fn explain_vulnerability(&self, _vuln: &Vulnerability, _code: &str) -> Result<String> {
        anyhow::bail!("Azure OpenAI provider not yet implemented")
    }

    async fn generate_remediation(&self, _vuln: &Vulnerability) -> Result<String> {
        anyhow::bail!("Azure OpenAI provider not yet implemented")
    }

    fn name(&self) -> &str {
        "azure"
    }

    fn cost_per_request(&self) -> f64 {
        0.001
    }

    async fn health_check(&self) -> Result<bool> {
        Ok(false)
    }

    fn model(&self) -> &str {
        &self.settings.model
    }
}
