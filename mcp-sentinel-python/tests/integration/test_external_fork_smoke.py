"""
Optional smoke scans against shallow-cloned repos under tests/external/.

This module is **only collected** when ``MCP_SENTINEL_RUN_FORK_TESTS`` is ``1`` / ``true`` / ``yes``
(see ``pytest_ignore_collect`` in ``tests/conftest.py``).

1. Run ``scripts/clone_fork_test_targets.ps1`` (Windows) or ``scripts/clone_fork_test_targets.sh``.
2. ``set MCP_SENTINEL_RUN_FORK_TESTS=1`` then ``pytest tests/integration/test_external_fork_smoke.py -m external_forks --no-cov``.

Default ``pytest`` runs omit this file (no CI noise).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_sentinel.core.scanner import Scanner

TESTS_DIR = Path(__file__).resolve().parent.parent
EXTERNAL_ROOT = TESTS_DIR / "external"


def _cloned_git_roots() -> list[Path]:
    if not EXTERNAL_ROOT.is_dir():
        return []
    out: list[Path] = []
    for p in sorted(EXTERNAL_ROOT.iterdir()):
        if p.is_dir() and (p / ".git").exists():
            out.append(p)
    return out


@pytest.mark.external_forks
@pytest.mark.asyncio
async def test_smoke_scan_cloned_forks() -> None:
    roots = _cloned_git_roots()
    if not roots:
        pytest.skip(
            "No clones under tests/external/. Run scripts/clone_fork_test_targets.ps1 or .sh",
        )

    scanner = Scanner()
    for root in roots:
        result = await scanner.scan_directory(root)
        assert result.status == "completed", f"scan failed for {root}"
        assert result.statistics.scanned_files > 0, f"no files scanned under {root}"
