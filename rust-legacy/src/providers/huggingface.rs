//! HuggingFace Provider (Stub - To be implemented)

use super::{AnalysisContext, LLMProvider, HuggingFaceSettings};
use crate::models::{ai_finding::AIFinding, Vulnerability};
use anyhow::Result;
use async_trait::async_trait;

pub struct HuggingFaceProvider {
    settings: HuggingFaceSettings,
}

impl HuggingFaceProvider {
    pub fn new(settings: &HuggingFaceSettings) -> Result<Self> {
        Ok(Self {
            settings: settings.clone(),
        })
    }
}

#[async_trait]
impl LLMProvider for HuggingFaceProvider {
    async fn analyze_code(&self, _code: &str, _context: &AnalysisContext) -> Result<AIFinding> {
        anyhow::bail!("HuggingFace provider not yet implemented")
    }

    async fn explain_vulnerability(&self, _vuln: &Vulnerability, _code: &str) -> Result<String> {
        anyhow::bail!("HuggingFace provider not yet implemented")
    }

    async fn generate_remediation(&self, _vuln: &Vulnerability) -> Result<String> {
        anyhow::bail!("HuggingFace provider not yet implemented")
    }

    fn name(&self) -> &str {
        "huggingface"
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
