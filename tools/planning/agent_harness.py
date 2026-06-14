#!/usr/bin/env python3
"""
Planning agent harness for OAuth detector enhancement.

This script performs lightweight planning tasks:
- Parses the enhancement plan document
- Emits a JSON task list suitable for human assignment or task-runner agents
- Optionally runs quick pytest selection for files matching oauth-related tests

Usage:
  python tools/planning/agent_harness.py --generate-tasks
  python tools/planning/agent_harness.py --run-tests

The harness is intentionally simple: it does not call external agent services.
It prepares artifacts used by CI or manual planning.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
PLAN_MD = ROOT / "docs" / "OAUTH_TOKEN_ENHANCEMENT_PLAN.md"
OUT_JSON = ROOT / "tools" / "planning" / "oauth_tasks.json"


def extract_sections(md_text: str) -> list[dict]:
    """Extract top-level sections and produce tasks by headings."""
    sections = []
    current = None
    for line in md_text.splitlines():
        h = re.match(r"^###\s+(.*)$", line)
        if h:
            if current:
                sections.append(current)
            current = {"title": h.group(1).strip(), "notes": []}
            continue
        if current is not None:
            if line.strip():
                current["notes"].append(line.strip())
    if current:
        sections.append(current)
    return sections


def generate_tasks(sections: list[dict]) -> list[dict]:
    tasks = []
    for sec in sections:
        title = sec["title"]
        notes = "\n".join(sec.get("notes", [])).strip()
        # Create subtasks by sentence
        sentences = re.split(r"(?<=[.!?])\\s+", notes)
        for i, s in enumerate(sentences):
            s = s.strip()
            if not s:
                continue
            task = {
                "id": f"task-{len(tasks)+1}",
                "section": title,
                "summary": s[:140],
                "detail": s,
                "assignee": None,
                "estimate_days": 0.5 if len(s) < 120 else 1.0,
                "labels": ["oauth", "detector", "planning"],
            }
            tasks.append(task)
    return tasks


def write_tasks(tasks: list[dict], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"tasks": tasks}, indent=2, ensure_ascii=False))
    print(f"Wrote {len(tasks)} tasks to {out_path}")


def run_pytest_short():
    print("Running pytest selection for oauth-related tests...")
    try:
        subprocess.check_call([sys.executable, "-m", "pytest", "tests/unit", "-k", "oauth or token or bearer", "-q"]) 
    except subprocess.CalledProcessError as e:
        print("Pytest returned non-zero exit code:", e.returncode)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generate-tasks", action="store_true", help="Generate task JSON from plan")
    parser.add_argument("--run-tests", action="store_true", help="Run pytest selection for oauth tests")
    args = parser.parse_args(argv)

    if args.generate_tasks:
        if not PLAN_MD.exists():
            print("Plan document not found at", PLAN_MD)
            return 2
        md = PLAN_MD.read_text()
        sections = extract_sections(md)
        tasks = generate_tasks(sections)
        write_tasks(tasks, OUT_JSON)

    if args.run_tests:
        run_pytest_short()

    if not (args.generate_tasks or args.run_tests):
        parser.print_help()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
