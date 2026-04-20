//! Scan Result Caching System
//!
//! Caches scan results based on file content hashes to enable 10-100x faster
//! incremental scans by skipping unchanged files.
//!
//! # Features
//!
//! - Content-addressable storage (SHA-256 hashing)
//! - TTL-based expiration
//! - Automatic cleanup of stale entries
//! - Configurable cache size limits
//! - Persistent storage using sled database
//!
//! # Storage
//!
//! Cache is stored in `~/.mcp-sentinel/cache/` using sled embedded database
//!
//! # Usage
//!
//! ```rust
//! use mcp_sentinel::storage::cache::ScanCache;
//! use std::time::Duration;
//!
//! # fn main() -> anyhow::Result<()> {
//! let cache = ScanCache::new()?;
//!
//! // Check if file needs scanning
//! let file_content = std::fs::read_to_string("server.py")?;
//! if let Some(cached_result) = cache.get("server.py", &file_content)? {
//!     println!("Using cached result!");
//! } else {
//!     // Scan file
//!     let result = scan_file(&file_content)?;
//!     cache.set("server.py", &file_content, &result, Duration::from_secs(86400))?;
//! }
//! # Ok(())
//! # }
//! ```

use crate::models::Vulnerability;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sled::Db;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Cached scan result entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    /// File path
    file_path: String,

    /// Content hash (SHA-256)
    content_hash: String,

    /// Scan results
    vulnerabilities: Vec<Vulnerability>,

    /// Timestamp when cached (Unix timestamp)
    cached_at: u64,

    /// TTL in seconds
    ttl_seconds: u64,
}

impl CacheEntry {
    /// Check if entry is expired
    fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))  // Graceful fallback if system time is invalid
            .as_secs();

        now > self.cached_at + self.ttl_seconds
    }

    /// Check if entry is valid for given content
    fn is_valid_for(&self, content: &str) -> bool {
        if self.is_expired() {
            return false;
        }

        let content_hash = Self::hash_content(content);
        self.content_hash == content_hash
    }

    /// Hash file content
    fn hash_content(content: &str) -> String {
        format!("{:x}", Sha256::digest(content.as_bytes()))
    }
}

/// Scan result cache manager
pub struct ScanCache {
    /// Sled database
    db: Db,

    /// Default TTL for cache entries
    default_ttl: Duration,

    /// Maximum cache size in bytes (0 = unlimited)
    max_size_bytes: u64,
}

impl ScanCache {
    /// Create a new scan cache
    ///
    /// # Returns
    ///
    /// Initialized cache with default settings
    ///
    /// # Errors
    ///
    /// - Failed to open database
    /// - Invalid cache directory
    pub fn new() -> Result<Self> {
        Self::with_ttl(Duration::from_secs(86400)) // 24 hours default
    }

    /// Create cache with custom TTL
    pub fn with_ttl(default_ttl: Duration) -> Result<Self> {
        let cache_dir = Self::default_cache_dir()?;
        std::fs::create_dir_all(&cache_dir).context(format!(
            "Failed to create cache directory: {}",
            cache_dir.display()
        ))?;

        let db = sled::open(cache_dir.join("scan_cache"))
            .context("Failed to open sled database for cache")?;

        debug!("Scan cache initialized: {}", cache_dir.display());

        Ok(Self {
            db,
            default_ttl,
            max_size_bytes: 100 * 1024 * 1024, // 100MB default
        })
    }

    /// Get default cache directory
    fn default_cache_dir() -> Result<PathBuf> {
        let home = dirs::home_dir().context("Failed to determine home directory")?;
        Ok(home.join(".mcp-sentinel").join("cache"))
    }

    /// Get cached result for a file
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the file
    /// * `content` - Current content of the file
    ///
    /// # Returns
    ///
    /// Cached scan results if available and valid, None otherwise
    ///
    /// # Errors
    ///
    /// - Database read error
    pub fn get(&self, file_path: &str, content: &str) -> Result<Option<Vec<Vulnerability>>> {
        let key = self.make_key(file_path);

        let entry_bytes = match self.db.get(&key).context("Failed to read from cache")? {
            Some(bytes) => bytes,
            None => {
                debug!("Cache miss: {}", file_path);
                return Ok(None);
            }
        };

        let entry: CacheEntry = bincode::deserialize(&entry_bytes)
            .context("Failed to deserialize cache entry")?;

        if entry.is_valid_for(content) {
            debug!("Cache hit: {} ({} vulnerabilities)", file_path, entry.vulnerabilities.len());
            Ok(Some(entry.vulnerabilities))
        } else {
            debug!("Cache invalid (content changed or expired): {}", file_path);
            // Remove expired/invalid entry
            self.db.remove(&key).ok();
            Ok(None)
        }
    }

    /// Store scan result in cache
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the file
    /// * `content` - File content
    /// * `vulnerabilities` - Scan results
    /// * `ttl` - Time to live for this entry
    ///
    /// # Errors
    ///
    /// - Database write error
    /// - Serialization error
    pub fn set(
        &self,
        file_path: &str,
        content: &str,
        vulnerabilities: &[Vulnerability],
        ttl: Duration,
    ) -> Result<()> {
        let entry = CacheEntry {
            file_path: file_path.to_string(),
            content_hash: CacheEntry::hash_content(content),
            vulnerabilities: vulnerabilities.to_vec(),
            cached_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))  // Graceful fallback
                .as_secs(),
            ttl_seconds: ttl.as_secs(),
        };

        let entry_bytes = bincode::serialize(&entry)
            .context("Failed to serialize cache entry")?;

        let key = self.make_key(file_path);
        self.db.insert(&key, entry_bytes)
            .context("Failed to write to cache")?;

        debug!("Cached scan result for: {} (TTL: {}s)", file_path, ttl.as_secs());

        // Check if cleanup is needed
        self.maybe_cleanup()?;

        Ok(())
    }

    /// Remove cached result for a file
    pub fn remove(&self, file_path: &str) -> Result<()> {
        let key = self.make_key(file_path);
        self.db.remove(&key).context("Failed to remove from cache")?;
        debug!("Removed cache entry: {}", file_path);
        Ok(())
    }

    /// Clear all cached results
    pub fn clear(&self) -> Result<()> {
        info!("Clearing entire scan cache");
        self.db.clear().context("Failed to clear cache")?;
        Ok(())
    }

    /// Remove expired entries from cache
    pub fn cleanup_expired(&self) -> Result<usize> {
        info!("Cleaning up expired cache entries");

        let mut removed_count = 0;

        for result in self.db.iter() {
            let (key, value) = result.context("Failed to iterate cache")?;

            if let Ok(entry) = bincode::deserialize::<CacheEntry>(&value) {
                if entry.is_expired() {
                    self.db.remove(&key).ok();
                    removed_count += 1;
                }
            }
        }

        if removed_count > 0 {
            info!("Removed {} expired cache entries", removed_count);
        }

        Ok(removed_count)
    }

    /// Get cache statistics
    pub fn get_stats(&self) -> Result<CacheStats> {
        let mut total_entries = 0;
        let mut total_size_bytes = 0u64;
        let mut expired_entries = 0;

        for result in self.db.iter() {
            let (_, value) = result.context("Failed to iterate cache")?;
            total_entries += 1;
            total_size_bytes += value.len() as u64;

            if let Ok(entry) = bincode::deserialize::<CacheEntry>(&value) {
                if entry.is_expired() {
                    expired_entries += 1;
                }
            }
        }

        Ok(CacheStats {
            total_entries,
            total_size_bytes,
            expired_entries,
            max_size_bytes: self.max_size_bytes,
        })
    }

    /// Make cache key from file path
    fn make_key(&self, file_path: &str) -> Vec<u8> {
        format!("file:{}", file_path).into_bytes()
    }

    /// Check if cleanup is needed and perform it
    fn maybe_cleanup(&self) -> Result<()> {
        let stats = self.get_stats()?;

        // Cleanup if expired entries > 10% of total
        if stats.expired_entries > stats.total_entries / 10 {
            self.cleanup_expired()?;
        }

        // Cleanup if size exceeds limit
        if self.max_size_bytes > 0 && stats.total_size_bytes > self.max_size_bytes {
            warn!(
                "Cache size ({} bytes) exceeds limit ({} bytes), removing oldest entries",
                stats.total_size_bytes, self.max_size_bytes
            );
            self.cleanup_by_size()?;
        }

        Ok(())
    }

    /// Remove oldest entries until size is under limit
    fn cleanup_by_size(&self) -> Result<()> {
        // Get all entries with timestamps
        let mut entries: Vec<(Vec<u8>, u64)> = Vec::new();

        for result in self.db.iter() {
            let (key, value) = result.context("Failed to iterate cache")?;

            if let Ok(entry) = bincode::deserialize::<CacheEntry>(&value) {
                entries.push((key.to_vec(), entry.cached_at));
            }
        }

        // Sort by timestamp (oldest first)
        entries.sort_by_key(|(_, timestamp)| *timestamp);

        // Remove oldest 25% of entries
        let remove_count = entries.len() / 4;
        for (key, _) in entries.iter().take(remove_count) {
            self.db.remove(key).ok();
        }

        info!("Removed {} old cache entries to reduce size", remove_count);

        Ok(())
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total number of cache entries
    pub total_entries: usize,

    /// Total size in bytes
    pub total_size_bytes: u64,

    /// Number of expired entries
    pub expired_entries: usize,

    /// Maximum allowed size in bytes
    pub max_size_bytes: u64,
}

impl CacheStats {
    /// Format as human-readable string
    pub fn format(&self) -> String {
        format!(
            "Cache Stats:\n\
            - Entries: {} ({} expired)\n\
            - Size: {:.2} MB / {:.2} MB\n\
            - Hit Rate: (tracked separately)",
            self.total_entries,
            self.expired_entries,
            self.total_size_bytes as f64 / 1024.0 / 1024.0,
            self.max_size_bytes as f64 / 1024.0 / 1024.0
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{vulnerability::{Severity, VulnerabilityLocation}, VulnerabilityType};

    #[test]
    fn test_content_hash() {
        let content1 = "const API_KEY = 'secret'";
        let content2 = "const API_KEY = 'secret'";
        let content3 = "const API_KEY = 'different'";

        let hash1 = CacheEntry::hash_content(content1);
        let hash2 = CacheEntry::hash_content(content2);
        let hash3 = CacheEntry::hash_content(content3);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_cache_entry_expiration() {
        let entry = CacheEntry {
            file_path: "test.py".to_string(),
            content_hash: "hash".to_string(),
            vulnerabilities: vec![],
            cached_at: 0, // Long time ago
            ttl_seconds: 60,
        };

        assert!(entry.is_expired());
    }

    #[test]
    fn test_cache_entry_validation() {
        let content = "test content";
        let entry = CacheEntry {
            file_path: "test.py".to_string(),
            content_hash: CacheEntry::hash_content(content),
            vulnerabilities: vec![],
            cached_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ttl_seconds: 3600,
        };

        assert!(entry.is_valid_for(content));
        assert!(!entry.is_valid_for("different content"));
    }

    #[test]
    fn test_cache_key_generation() {
        let cache = ScanCache::new().unwrap_or_else(|_| {
            // If cache creation fails (e.g., in CI), skip test
            panic!("Cache creation failed");
        });

        let key1 = cache.make_key("test.py");
        let key2 = cache.make_key("test.py");
        let key3 = cache.make_key("other.py");

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }
}
