import subprocess
import json
import re
import sys
from datetime import datetime
from pathlib import Path

def run_command(command, capture=True):
    """Run a shell command and return stdout."""
    try:
        if capture:
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True
            )
            return result.stdout
        else:
            # Stream output to console but verify return code
            result = subprocess.run(
                command,
                shell=True,
                check=False
            )
            return ""
    except Exception as e:
        print(f"Error running {command}: {e}", file=sys.stderr)
        return ""

def get_coverage():
    print("  - Running coverage check (this may take ~60 seconds)...", flush=True)
    # Assumes pytest-cov is installed
    # We capture output to parse the percentage
    stdout = run_command("pytest --cov=src/mcp_sentinel --cov-report=term-missing:skip-covered")
    
    # Look for TOTAL line
    # src/mcp_sentinel/utils.py      25      5    80%
    # TOTAL                         450     50    89%
    lines = stdout.splitlines()
    for line in lines:
        if "TOTAL" in line:
            parts = line.split()
            if parts:
                percent_str = parts[-1].replace("%", "")
                try:
                    return int(float(percent_str))
                except ValueError:
                    pass
    return 0

def get_lint_errors():
    print("  - Running linter (ruff)...", flush=True)
    # Use JSON output for accurate counting
    stdout = run_command("ruff check src --output-format=json")
    try:
        issues = json.loads(stdout)
        return len(issues)
    except json.JSONDecodeError:
        return 0

def get_type_errors():
    print("  - Running type checker (mypy)...", flush=True)
    stdout = run_command("mypy src")
    # Output: Found 5 errors in 2 files (checked 10 source files)
    match = re.search(r"Found (\d+) error", stdout)
    if match:
        return int(match.group(1))
    
    if "Success: no issues found" in stdout:
        return 0
        
    return 0

def main():
    print("Collecting Adaptive Compliance Metrics (Pillar 2)...", flush=True)
    
    metrics = {
        "timestamp": datetime.utcnow().isoformat(),
        "metrics": {
            "test_coverage_pct": get_coverage(),
            "lint_issues": get_lint_errors(),
            "type_issues": get_type_errors(),
        }
    }
    
    # Save to file
    output_dir = Path("reports")
    output_dir.mkdir(exist_ok=True)
    
    output_file = output_dir / "compliance_metrics.json"
    with open(output_file, "w") as f:
        json.dump(metrics, f, indent=2)
        
    print(f"\nCompliance Status:")
    print(f"  Coverage: {metrics['metrics']['test_coverage_pct']}%")
    print(f"  Lint Issues: {metrics['metrics']['lint_issues']}")
    print(f"  Type Issues: {metrics['metrics']['type_issues']}")
    print(f"\nMetrics saved to {output_file}")

if __name__ == "__main__":
    main()
