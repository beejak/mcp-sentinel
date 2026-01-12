#!/usr/bin/env python3
"""
Verify all Phase 4 dependencies are installed correctly.

Checks:
1. Tree-sitter languages available
2. Semgrep installed and runnable
3. Bandit installed and runnable
4. LangChain imports work (optional for AI engine)
5. API keys configured (optional)
"""

import sys
import subprocess
import shutil
import os
from pathlib import Path


def check_tree_sitter():
    """Verify tree-sitter languages."""
    try:
        import tree_sitter
        import tree_sitter_python
        import tree_sitter_javascript
        import tree_sitter_typescript
        print("[OK] Tree-sitter languages available")
        print(f"  - tree-sitter: {tree_sitter.__version__ if hasattr(tree_sitter, '__version__') else 'installed'}")
        print(f"  - tree-sitter-python: installed")
        print(f"  - tree-sitter-javascript: installed")
        print(f"  - tree-sitter-typescript: installed")
        return True
    except ImportError as e:
        print(f"[FAIL] Tree-sitter language missing: {e}")
        print("  Install: pip install tree-sitter tree-sitter-python tree-sitter-javascript tree-sitter-typescript")
        return False


def check_semgrep():
    """Verify Semgrep is installed."""
    if shutil.which("semgrep"):
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                print(f"[OK] Semgrep installed: {version}")
                return True
        except Exception as e:
            print(f"[FAIL] Semgrep error: {e}")
            return False
    else:
        print("[FAIL] Semgrep not found in PATH")
        print("  Install: pip install semgrep")
        return False


def check_bandit():
    """Verify Bandit is installed."""
    if shutil.which("bandit"):
        try:
            result = subprocess.run(
                ["bandit", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                print(f"[OK] Bandit installed: {version}")
                return True
        except Exception as e:
            print(f"[FAIL] Bandit error: {e}")
            return False
    else:
        print("[FAIL] Bandit not found in PATH")
        print("  Install: pip install bandit")
        return False


def check_langchain():
    """Verify LangChain is available (optional for AI engine)."""
    try:
        import langchain
        from langchain.chains import LLMChain
        print(f"[OK] LangChain available: {langchain.__version__}")
        return True
    except ImportError as e:
        print(f"[INFO] LangChain not installed (optional for AI engine)")
        print(f"  Install: pip install langchain langchain-openai langchain-anthropic")
        return False


def check_api_keys():
    """Check API key configuration (optional)."""
    keys = {
        "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY"),
        "ANTHROPIC_API_KEY": os.getenv("ANTHROPIC_API_KEY"),
        "GOOGLE_API_KEY": os.getenv("GOOGLE_API_KEY"),
    }

    configured = [k for k, v in keys.items() if v]

    if configured:
        print(f"[OK] API keys configured: {', '.join(configured)}")
    else:
        print("[INFO] No AI API keys configured (AI engine will use Ollama if available)")

    return True  # Not a failure


def main():
    """Run all checks."""
    print("=" * 60)
    print("MCP Sentinel - Phase 4 Dependency Verification")
    print("=" * 60)
    print()

    checks = [
        ("Tree-sitter", check_tree_sitter),
        ("Semgrep", check_semgrep),
        ("Bandit", check_bandit),
        ("LangChain (optional)", check_langchain),
        ("API Keys (optional)", check_api_keys),
    ]

    results = []
    for name, check_fn in checks:
        print(f"\nChecking {name}...")
        results.append(check_fn())

    print("\n" + "=" * 60)

    # Required checks: Tree-sitter, Semgrep, Bandit
    required_passed = results[0] and results[1] and results[2]

    if required_passed:
        print("[OK] All required dependencies verified successfully!")
        print("\nYou can now:")
        print("  - Start Phase 4.1 (SAST Engine)")
        print("  - Run: mcp-sentinel scan . --engines static,sast")
        return 0
    else:
        print("[FAIL] Some required dependencies are missing")
        print("\nRefer to documentation for installation instructions")
        return 1


if __name__ == "__main__":
    sys.exit(main())
