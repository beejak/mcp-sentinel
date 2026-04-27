"""
Vulnerable MCP Project feed — JSON database published alongside vulnerablemcp.info.

Upstream: https://github.com/vineethsai/vulnerablemcp (data/vulnerabilities.json).
"""

from __future__ import annotations

import json
import re
import threading
import time
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from mcp_sentinel.models.vulnerability import Vulnerability

CVE_OR_ADVISORY_RE = re.compile(
    r"\b(?:CVE-\d{4}-\d+|TRA-\d{4}-\d+|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})\b",
    re.I,
)


def fetch_vulnerable_mcp_entries(*, url: str, timeout_seconds: float) -> list[dict[str, Any]]:
    """Download and parse the vulnerabilities JSON array."""
    req = Request(url, headers={"User-Agent": "mcp-sentinel-threat-intel/1.0"})
    with urlopen(req, timeout=timeout_seconds) as resp:  # noqa: S310 — intentional feed URL
        raw = resp.read().decode("utf-8")
    data = json.loads(raw)
    if not isinstance(data, list):
        return []
    return [x for x in data if isinstance(x, dict)]


_CACHE_LOCK = threading.Lock()
_CACHE: dict[str, Any] = {
    "entries": None,
    "cached_at_monotonic": 0.0,
    "ttl_seconds": 3600.0,
    "failure_until_monotonic": 0.0,
}


def get_cached_vulnerable_mcp_entries(
    *,
    url: str,
    timeout_seconds: float,
    cache_ttl_seconds: float,
    negative_cache_seconds: float = 300.0,
) -> list[dict[str, Any]]:
    """
    Return feed entries with in-process TTL caching and short negative caching on failure.
    """
    now = time.monotonic()
    with _CACHE_LOCK:
        if now < float(_CACHE["failure_until_monotonic"]):
            return []
        if (
            _CACHE["entries"] is not None
            and (now - float(_CACHE["cached_at_monotonic"])) < float(_CACHE["ttl_seconds"])
        ):
            return _CACHE["entries"]

    try:
        entries = fetch_vulnerable_mcp_entries(url=url, timeout_seconds=timeout_seconds)
    except (OSError, URLError, TimeoutError, json.JSONDecodeError, ValueError):
        with _CACHE_LOCK:
            _CACHE["failure_until_monotonic"] = now + negative_cache_seconds
        return []

    with _CACHE_LOCK:
        _CACHE["entries"] = entries
        _CACHE["cached_at_monotonic"] = time.monotonic()
        _CACHE["ttl_seconds"] = cache_ttl_seconds
        _CACHE["failure_until_monotonic"] = 0.0
    return entries


def _haystack_text(vuln: Vulnerability) -> str:
    parts: list[str] = [vuln.title, vuln.description, vuln.file_path]
    if vuln.code_snippet:
        parts.append(vuln.code_snippet)
    if vuln.metadata:
        parts.append(json.dumps(vuln.metadata, sort_keys=True))
    return " ".join(parts).lower()


def _summarize_record(entry: dict[str, Any]) -> dict[str, Any]:
    eid = entry.get("id")
    page = f"https://vulnerablemcp.info/vuln/{eid}.html" if isinstance(eid, str) and eid else None
    return {
        "id": eid,
        "title": entry.get("title"),
        "severity": entry.get("severity"),
        "category": entry.get("category"),
        "cveIds": list(entry.get("cveIds") or []),
        "url": entry.get("url"),
        "vulnerablemcp_page": page,
    }


def match_vulnerable_mcp_records(
    vuln: Vulnerability,
    entries: list[dict[str, Any]],
    *,
    max_matches: int = 5,
) -> list[dict[str, Any]]:
    """
    Match feed records to a finding using advisory IDs (CVE/TRA/GHSA), record id substring,
    and distinctive title or alias words (length >= 6) appearing in the finding text.
    """
    hay = _haystack_text(vuln)
    hay_advisories = {m.group(0).upper().replace("—", "-") for m in CVE_OR_ADVISORY_RE.finditer(hay)}

    matched: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add_from_entry(entry: dict[str, Any]) -> None:
        eid = entry.get("id")
        key = str(eid) if eid is not None else str(id(entry))
        if key in seen:
            return
        seen.add(key)
        matched.append(_summarize_record(entry))

    # 1) Direct advisory id match (CVE list in JSON is normalized uppercase in practice)
    for entry in entries:
        if len(matched) >= max_matches:
            break
        cves = entry.get("cveIds") or []
        if not isinstance(cves, list):
            continue
        normalized = {str(c).strip().upper() for c in cves if c}
        if hay_advisories & normalized:
            add_from_entry(entry)

    # 2) Record id appears in finding text (hyphenated slugs; long ids only)
    if len(matched) < max_matches:
        for entry in entries:
            if len(matched) >= max_matches:
                break
            eid = entry.get("id")
            if not isinstance(eid, str) or not eid:
                continue
            if eid in seen:
                continue
            if len(eid) >= 10 and eid.lower() in hay:
                add_from_entry(entry)

    # 3) Distinctive title / alias words (>= 6 chars) appear as substrings in hay
    if len(matched) < max_matches:
        for entry in entries:
            if len(matched) >= max_matches:
                break
            eid = entry.get("id")
            if isinstance(eid, str) and eid in seen:
                continue
            title = str(entry.get("title") or "")
            alt = entry.get("alternativeNames") or []
            alt_list = alt if isinstance(alt, list) else []
            blobs = [title, *[str(x) for x in alt_list if x]]
            words: list[str] = []
            for blob in blobs:
                words.extend(re.findall(r"[a-z]{6,}", blob.lower()))
            words = sorted(set(words), key=len, reverse=True)
            if any(w in hay for w in words[:5]):
                add_from_entry(entry)

    return matched[:max_matches]
