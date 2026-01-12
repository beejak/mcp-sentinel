//! Scanning engines

pub mod static_analysis;
pub mod ai_analysis;
pub mod semantic;  // Phase 2.5: Tree-sitter AST-based analysis
pub mod semgrep;   // Phase 2.5: Semgrep integration (1000+ rules)

// Phase 3+ engines
// pub mod runtime_proxy;
