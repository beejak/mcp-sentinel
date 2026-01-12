//! Cohere Provider (Stub - To be implemented)

use super::{AnalysisContext, LLMProvider, CohereSettings};
use crate::models::{ai_finding::AIFinding, Vulnerability};
use anyhow::Result;
use async_trait::async_trait;

pub struct CohereProvider {
    settings: CohereSettings,
}

impl CohereProvider {
    pub fn new(settings: &CohereSettings) -> Result<Self> {
        Ok(Self {
            settings: settings.clone(),
        })
    }
}

#[async_trait]
impl LLMProvider for CohereProvider {
    async fn analyze_code(&self, _code: &str, _context: &AnalysisContext) -> Result<AIFinding> {
        anyhow::bail!("Cohere provider not yet implemented")
    }

    async fn explain_vulnerability(&self, _vuln: &Vulnerability, _code: &str) -> Result<String> {
        anyhow::bail!("Cohere provider not yet implemented")
    }

    async fn generate_remediation(&self, _vuln: &Vulnerability) -> Result<String> {
        anyhow::bail!("Cohere provider not yet implemented")
    }

    fn name(&self) -> &str {
        "cohere"
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
