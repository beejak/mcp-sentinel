#!/usr/bin/env bash
# Shallow-clone manifest entries into tests/external/<repo>/
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$HERE/tests/external"
MANIFEST="$HERE/tests/fork_targets.manifest"

if [[ ! -f "$MANIFEST" ]]; then
  echo "Missing manifest: $MANIFEST" >&2
  exit 1
fi

mkdir -p "$DEST"

while IFS= read -r line || [[ -n "${line:-}" ]]; do
  line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [[ -z "$line" || "$line" =~ ^# ]] && continue
  if [[ ! "$line" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    echo "Skipping invalid line: $line" >&2
    continue
  fi
  owner="${line%%/*}"
  repo="${line#*/}"
  target="$DEST/$repo"
  if [[ -d "$target/.git" ]]; then
    echo "Already present: $target"
    git -C "$target" pull --ff-only 2>/dev/null || true
  else
    echo "Cloning $owner/$repo -> $target"
    git clone --depth 1 "https://github.com/$owner/$repo.git" "$target"
  fi
done < "$MANIFEST"

echo "Done. Optional smoke tests: MCP_SENTINEL_RUN_FORK_TESTS=1 pytest tests/integration/test_external_fork_smoke.py -m external_forks --no-cov"
