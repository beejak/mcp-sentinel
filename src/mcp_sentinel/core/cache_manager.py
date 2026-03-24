import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from mcp_sentinel.models.vulnerability import Vulnerability


class CacheManager:
    """
    Manages caching of scan results to improve performance.

    Stores scan results indexed by file path and content hash.
    If a file hasn't changed, returns cached results instead of re-scanning.
    """

    def __init__(self, cache_dir: Optional[Path] = None):
        """
        Initialize the cache manager.

        Args:
            cache_dir: Directory to store cache file. Defaults to .sentinel in current directory.
        """
        self.cache_dir = cache_dir or Path(".sentinel")
        self.cache_file = self.cache_dir / "cache.json"
        self.cache: dict[str, Any] = {}
        self._load_cache()

    def _load_cache(self) -> None:
        """Load cache from disk."""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, encoding="utf-8") as f:
                    self.cache = json.load(f)
            except Exception:
                # Corrupt cache, start fresh
                self.cache = {}
        else:
            self.cache = {}

    def _save_cache(self) -> None:
        """Save cache to disk."""
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, indent=2)
        except Exception:
            # Ignore save errors
            pass

    def get_cached_results(self, file_path: Path, content_hash: str) -> Optional[list[Vulnerability]]:
        """
        Get cached results for a file if content hash matches.

        Args:
            file_path: Path to the file
            content_hash: Hash of the file content

        Returns:
            List of cached vulnerabilities or None if cache miss
        """
        file_key = str(file_path.absolute())

        if file_key in self.cache:
            entry = self.cache[file_key]
            # Check if content hash matches
            if entry.get("hash") == content_hash:
                try:
                    # Deserialize vulnerabilities
                    vulns_data = entry.get("vulnerabilities", [])
                    return [Vulnerability(**v) for v in vulns_data]
                except Exception:
                    # Invalid cache entry
                    return None

        return None

    def update_cache(self, file_path: Path, content_hash: str, vulnerabilities: list[Vulnerability]) -> None:
        """
        Update cache with new results.

        Args:
            file_path: Path to the file
            content_hash: Hash of the file content
            vulnerabilities: List of detected vulnerabilities
        """
        file_key = str(file_path.absolute())

        # Serialize vulnerabilities using Pydantic's model_dump
        vulns_data = [v.model_dump(mode='json') for v in vulnerabilities]

        self.cache[file_key] = {
            "hash": content_hash,
            "timestamp": datetime.utcnow().isoformat(),
            "vulnerabilities": vulns_data
        }
        self._save_cache()

    @staticmethod
    def calculate_hash(content: str) -> str:
        """
        Calculate MD5 hash of content.

        Args:
            content: File content

        Returns:
            Hex digest of hash
        """
        return hashlib.md5(content.encode("utf-8")).hexdigest()
