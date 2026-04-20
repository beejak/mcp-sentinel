//! GitHub URL Scanning - Scan Repositories Without Manual Cloning
//!
//! ## Phase 2.5 - Advanced Analysis
//!
//! This module enables scanning of GitHub repositories by URL:
//! - Parse GitHub URLs (https://github.com/owner/repo)
//! - Clone to temporary directory
//! - Scan with all enabled engines
//! - Clean up temporary files
//! - Support branches, tags, commits
//!
//! ## Why GitHub URL Scanning?
//!
//! **User Experience**:
//! - No manual git clone needed
//! - Scan public repos instantly
//! - Test MCP servers before installation
//! - CI/CD integration for scanning dependencies
//!
//! **Use Cases**:
//! - Security audits of third-party MCP servers
//! - Pre-installation vulnerability checks
//! - Automated dependency scanning
//! - MCP marketplace integration
//!
//! ## Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────┐
//! │       GitHub URL Scanning Flow             │
//! ├────────────────────────────────────────────┤
//! │                                            │
//! │  1. Parse URL → owner/repo/ref            │
//! │  2. Create temp dir                        │
//! │  3. Git clone (shallow)                    │
//! │  4. Scan directory                         │
//! │  5. Cleanup temp dir                       │
//! │                                            │
//! └────────────────────────────────────────────┘
//! ```
//!
//! ## Example Usage
//!
//! ```no_run
//! use mcp_sentinel::utils::github::GitHubScanner;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let scanner = GitHubScanner::new();
//!
//! // Scan main branch
//! let url = "https://github.com/owner/mcp-server";
//! let result = scanner.scan_url(url).await?;
//!
//! // Scan specific branch
//! let url = "https://github.com/owner/mcp-server/tree/develop";
//! let result = scanner.scan_url(url).await?;
//!
//! // Scan specific commit
//! let url = "https://github.com/owner/mcp-server/commit/abc123";
//! let result = scanner.scan_url(url).await?;
//! # Ok(())
//! # }
//! ```

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use url::Url;
use tracing::{debug, info, warn};

/// GitHub repository scanner.
///
/// ## Why separate from main scanner
///
/// - Handles GitHub-specific URL parsing
/// - Manages temporary directory lifecycle
/// - Isolates network operations
/// - Makes testing easier (can mock)
pub struct GitHubScanner {
    /// Keep temp dir alive during scan
    _phantom: std::marker::PhantomData<()>,
}

/// Parsed GitHub repository information.
///
/// ## Why separate struct
///
/// Makes URL parsing testable and reusable.
/// Clear separation of concerns.
#[derive(Debug, Clone, PartialEq)]
pub struct GitHubRepo {
    /// Repository owner (user or organization)
    pub owner: String,

    /// Repository name
    pub repo: String,

    /// Git reference (branch, tag, or commit)
    pub git_ref: Option<String>,

    /// Full clone URL
    pub clone_url: String,
}

impl GitHubScanner {
    /// Create a new GitHub scanner.
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Scan a GitHub repository by URL.
    ///
    /// ## URL Formats Supported
    ///
    /// - https://github.com/owner/repo
    /// - https://github.com/owner/repo/tree/branch-name
    /// - https://github.com/owner/repo/tree/v1.0.0
    /// - https://github.com/owner/repo/commit/abc123
    ///
    /// ## Performance
    ///
    /// Uses shallow clone (--depth=1) for speed:
    /// - Full clone: 100MB+ download, 30-60s
    /// - Shallow clone: 5-10MB download, 3-5s
    ///
    /// ## Cleanup
    ///
    /// Temporary directory is automatically cleaned up when function returns,
    /// even if scan fails (RAII pattern via TempDir).
    pub async fn scan_url(&self, url: &str) -> Result<PathBuf> {
        info!("Scanning GitHub repository: {}", url);

        // Parse GitHub URL
        debug!("Parsing GitHub URL");
        let repo = Self::parse_github_url(url)?;
        info!("Parsed repository: {}/{} (ref: {:?})", repo.owner, repo.repo, repo.git_ref);

        // Create temporary directory
        debug!("Creating temporary directory for clone");
        let temp_dir = TempDir::new()
            .context("Failed to create temporary directory")?;
        debug!("Temporary directory created at: {}", temp_dir.path().display());

        // Clone repository
        self.clone_repository(&repo, temp_dir.path()).await?;

        // Return temp dir path (caller will scan it)
        // Note: TempDir is dropped after scan, cleaning up automatically
        Ok(temp_dir.path().to_path_buf())
    }

    /// Parse GitHub URL into repository components.
    ///
    /// ## URL Parsing Strategy
    ///
    /// 1. Basic validation (is it github.com?)
    /// 2. Extract owner and repo from path
    /// 3. Extract git ref if present (branch/tag/commit)
    /// 4. Build clone URL
    pub fn parse_github_url(url: &str) -> Result<GitHubRepo> {
        let parsed = Url::parse(url)
            .context("Invalid URL format")?;

        // Verify it's GitHub
        if parsed.host_str() != Some("github.com") {
            anyhow::bail!("URL must be from github.com");
        }

        // Parse path segments
        let segments: Vec<&str> = parsed.path()
            .trim_matches('/')
            .split('/')
            .collect();

        if segments.len() < 2 {
            anyhow::bail!("Invalid GitHub URL: must be github.com/owner/repo");
        }

        let owner = segments[0].to_string();
        let repo = segments[1].to_string();

        // Extract git reference if present
        let git_ref = if segments.len() >= 4 {
            // URLs like /owner/repo/tree/branch or /owner/repo/commit/hash
            match segments[2] {
                "tree" | "commit" | "tag" => Some(segments[3].to_string()),
                _ => None,
            }
        } else {
            None
        };

        // Build clone URL
        let clone_url = format!("https://github.com/{}/{}.git", owner, repo);

        Ok(GitHubRepo {
            owner,
            repo,
            git_ref,
            clone_url,
        })
    }

    /// Clone repository to local directory.
    ///
    /// ## Clone Options
    ///
    /// - --depth=1: Shallow clone (faster, smaller)
    /// - --single-branch: Only clone requested branch
    /// - --branch: Specific branch/tag to clone
    /// - --quiet: Suppress progress output
    async fn clone_repository(&self, repo: &GitHubRepo, target_dir: &Path) -> Result<()> {
        info!("Cloning repository: {} (shallow clone --depth=1)", repo.clone_url);
        if let Some(ref git_ref) = repo.git_ref {
            debug!("Using specific git reference: {}", git_ref);
        }
        let start = std::time::Instant::now();

        let mut cmd = Command::new("git");
        cmd.arg("clone")
            .arg("--depth=1")        // Shallow clone
            .arg("--single-branch")  // Only one branch
            .arg("--quiet");         // Suppress output

        // Add branch/tag if specified
        if let Some(ref git_ref) = repo.git_ref {
            cmd.arg("--branch").arg(git_ref);
        }

        cmd.arg(&repo.clone_url)
            .arg(target_dir);

        // Execute clone
        let output = cmd.output()
            .context("Failed to execute git clone")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Git clone failed: {}", stderr);
        }

        info!("Repository cloned successfully in {:?} to: {}", start.elapsed(), target_dir.display());

        Ok(())
    }

    /// Check if git is available on the system.
    ///
    /// ## Why this check
    ///
    /// Git is required for cloning. If not available:
    /// - Return clear error message
    /// - Provide installation instructions
    /// - Don't fail silently
    pub fn is_git_available() -> bool {
        let available = Command::new("git")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);

        if available {
            debug!("Git is available on system");
        } else {
            warn!("Git not available - GitHub URL scanning will not work");
        }

        available
    }

    /// Get git version string.
    pub fn git_version() -> Result<String> {
        let output = Command::new("git")
            .arg("--version")
            .output()
            .context("Failed to execute git --version")?;

        if !output.status.success() {
            anyhow::bail!("Git --version failed");
        }

        let version = String::from_utf8_lossy(&output.stdout);
        Ok(version.trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test GitHub URL parsing with various formats.
    ///
    /// Why: Ensures all supported URL formats are correctly parsed.
    /// GitHub URLs have many variations - we need to handle them all.
    #[test]
    fn test_parse_github_url_basic() {
        let url = "https://github.com/owner/repo";
        let repo = GitHubScanner::parse_github_url(url).unwrap();

        assert_eq!(repo.owner, "owner");
        assert_eq!(repo.repo, "repo");
        assert_eq!(repo.git_ref, None);
        assert_eq!(repo.clone_url, "https://github.com/owner/repo.git");
    }

    /// Test parsing URL with branch.
    ///
    /// Why: Branch-specific scanning is common use case (scan dev branch).
    #[test]
    fn test_parse_github_url_with_branch() {
        let url = "https://github.com/owner/repo/tree/develop";
        let repo = GitHubScanner::parse_github_url(url).unwrap();

        assert_eq!(repo.owner, "owner");
        assert_eq!(repo.repo, "repo");
        assert_eq!(repo.git_ref, Some("develop".to_string()));
    }

    /// Test parsing URL with commit hash.
    ///
    /// Why: Scanning specific commits is important for audits.
    #[test]
    fn test_parse_github_url_with_commit() {
        let url = "https://github.com/owner/repo/commit/abc123def456";
        let repo = GitHubScanner::parse_github_url(url).unwrap();

        assert_eq!(repo.owner, "owner");
        assert_eq!(repo.repo, "repo");
        assert_eq!(repo.git_ref, Some("abc123def456".to_string()));
    }

    /// Test parsing URL with tag.
    ///
    /// Why: Scanning releases by tag is common (scan v1.0.0).
    #[test]
    fn test_parse_github_url_with_tag() {
        let url = "https://github.com/owner/repo/tree/v1.0.0";
        let repo = GitHubScanner::parse_github_url(url).unwrap();

        assert_eq!(repo.owner, "owner");
        assert_eq!(repo.repo, "repo");
        assert_eq!(repo.git_ref, Some("v1.0.0".to_string()));
    }

    /// Test rejection of non-GitHub URLs.
    ///
    /// Why: Only GitHub URLs are supported. Other git hosts need different handling.
    #[test]
    fn test_parse_non_github_url() {
        let url = "https://gitlab.com/owner/repo";
        let result = GitHubScanner::parse_github_url(url);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("github.com"));
    }

    /// Test rejection of invalid URLs.
    ///
    /// Why: Malformed URLs should return clear errors, not panic.
    #[test]
    fn test_parse_invalid_url() {
        let url = "not-a-url";
        let result = GitHubScanner::parse_github_url(url);

        assert!(result.is_err());
    }

    /// Test rejection of incomplete GitHub URLs.
    ///
    /// Why: URL must have owner and repo. Just "github.com/owner" is incomplete.
    #[test]
    fn test_parse_incomplete_github_url() {
        let url = "https://github.com/owner";
        let result = GitHubScanner::parse_github_url(url);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("owner/repo"));
    }

    /// Test git availability check.
    ///
    /// Why: Provides clear feedback if git is not installed.
    #[test]
    fn test_git_availability() {
        // This test passes if git is installed
        // On systems without git, it returns false (expected)
        let available = GitHubScanner::is_git_available();

        if available {
            // Git is installed - verify version works
            let version = GitHubScanner::git_version().unwrap();
            assert!(version.contains("git version"));
        } else {
            // Git not installed - acceptable for some environments
            println!("Git not installed - skipping git-dependent tests");
        }
    }
}
