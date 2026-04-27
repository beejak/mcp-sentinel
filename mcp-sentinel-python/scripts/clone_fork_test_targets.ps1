# Shallow-clone manifest entries into tests/external/<repo>/
# Requires: git on PATH. Run from repo root or any cwd (script resolves paths).

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $PSScriptRoot
$destBase = Join-Path $here "tests/external"
$manifest = Join-Path $here "tests/fork_targets.manifest"

if (-not (Test-Path $manifest)) {
    Write-Error "Missing manifest: $manifest"
}

New-Item -ItemType Directory -Force -Path $destBase | Out-Null

Get-Content -LiteralPath $manifest | ForEach-Object {
    $line = $_.Trim()
    if (-not $line -or $line.StartsWith("#")) {
        return
    }
    if ($line -notmatch "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$") {
        Write-Warning "Skipping invalid line: $line"
        return
    }
    $parts = $line -split "/", 2
    $owner = $parts[0]
    $repo = $parts[1]
    $target = Join-Path $destBase $repo
    if (Test-Path (Join-Path $target ".git")) {
        Write-Host "Already present: $target"
        Push-Location $target
        try {
            git pull --ff-only 2>$null | Out-Null
        }
        finally {
            Pop-Location
        }
    }
    else {
        Write-Host "Cloning $owner/$repo -> $target"
        git clone --depth 1 "https://github.com/$owner/$repo.git" $target
    }
}

Write-Host "Done. Optional smoke tests: `$env:MCP_SENTINEL_RUN_FORK_TESTS='1'; pytest tests/integration/test_external_fork_smoke.py -m external_forks --no-cov"
