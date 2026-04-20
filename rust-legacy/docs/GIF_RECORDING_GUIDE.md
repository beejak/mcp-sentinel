# GIF Recording Guide for MCP Sentinel Demos

This guide explains how to create high-quality GIF demonstrations of MCP Sentinel v2.5.0 features.

## Tools Needed

### Option 1: asciinema + agg (Recommended)
Best for terminal recordings with perfect text rendering.

```bash
# Install asciinema (terminal recorder)
pip install asciinema

# Install agg (asciinema to GIF converter)
cargo install --git https://github.com/asciinema/agg
```

### Option 2: terminalizer
Easy to use, good for quick demos.

```bash
npm install -g terminalizer
```

### Option 3: VHS (by Charm)
Script-based, produces consistent results.

```bash
# Install VHS
go install github.com/charmbracelet/vhs@latest
```

---

## Demo Scenarios to Record

### Demo 1: Quick Scan (Basic)
**Filename:** `demo_01_quick_scan.gif`
**Duration:** ~15 seconds

```bash
# Show command and output
mcp-sentinel scan ./demo-server

# Expected output:
# - Scanning animation
# - Quick results
# - Severity breakdown
```

### Demo 2: GitHub URL Scanning (NEW!)
**Filename:** `demo_02_github_scanning.gif`
**Duration:** ~20 seconds

```bash
# Scan a GitHub repository directly
mcp-sentinel scan https://github.com/modelcontextprotocol/servers --fail-on high

# Shows:
# - GitHub URL parsing
# - Shallow clone progress
# - Scan results
# - Exit code behavior
```

### Demo 3: Semgrep Integration (NEW!)
**Filename:** `demo_03_semgrep.gif`
**Duration:** ~25 seconds

```bash
# Enable Semgrep for broader coverage
mcp-sentinel scan ./demo-server --enable-semgrep

# Shows:
# - Semgrep availability check
# - Running 1000+ rules
# - Additional findings
# - Coverage improvement
```

### Demo 4: HTML Report Generation (NEW!)
**Filename:** `demo_04_html_report.gif`
**Duration:** ~20 seconds

```bash
# Generate HTML report
mcp-sentinel scan ./demo-server --output html --output-file audit.html

# Then open in browser (show screenshot)
open audit.html
```

### Demo 5: Multi-Engine Comprehensive Scan (FLAGSHIP)
**Filename:** `demo_05_comprehensive.gif`
**Duration:** ~60 seconds

```bash
# The ultimate v2.5.0 showcase
mcp-sentinel scan ./demo-server \
  --mode deep \
  --enable-semgrep \
  --llm-provider ollama \
  --output html \
  --output-file comprehensive-audit.html

# Shows all phases:
# - Static analysis
# - Semantic (Tree-sitter) analysis
# - Semgrep SAST
# - AI analysis
# - HTML report generation
```

---

## Recording Instructions

### Using asciinema + agg (Best Quality)

1. **Start recording:**
```bash
asciinema rec demo.cast
```

2. **Run your demo commands**
   - Type slowly and clearly
   - Wait for animations to complete
   - Show meaningful output

3. **Stop recording:**
   Press `Ctrl+D`

4. **Convert to GIF:**
```bash
agg demo.cast demo.gif
```

5. **Optimize GIF size:**
```bash
# Install gifsicle
brew install gifsicle  # macOS
apt install gifsicle   # Linux

# Optimize
gifsicle -O3 --colors 256 demo.gif -o demo_optimized.gif
```

### Using terminalizer

1. **Record:**
```bash
terminalizer record demo
# Run commands
# Ctrl+D to stop
```

2. **Render to GIF:**
```bash
terminalizer render demo
```

### Using VHS (Script-Based)

1. **Create script** (`demo.tape`):
```vhs
Output demo.gif

Set FontSize 14
Set Width 1200
Set Height 600
Set Theme "Dracula"

Type "mcp-sentinel scan ./demo-server"
Enter
Sleep 5s
```

2. **Generate GIF:**
```bash
vhs demo.tape
```

---

## Best Practices

### Terminal Settings
```bash
# Set consistent terminal size
resize -s 30 100  # 30 rows, 100 columns

# Use a readable font size
# Recommended: 14-16pt

# Use high-contrast theme
# Recommended: Dracula, Monokai, One Dark
```

### Recording Tips

1. **Clean environment:**
   - Empty terminal history: `clear`
   - Show only relevant directories
   - Remove distracting prompts

2. **Timing:**
   - Type at moderate speed (not too fast)
   - Pause briefly before starting scan
   - Wait for all output to complete
   - Add 1-2 seconds at end before stopping

3. **Output:**
   - Let scan progress indicators animate
   - Show key results clearly
   - Don't cut off output mid-stream

4. **File size:**
   - Keep under 10MB for GitHub README
   - Optimize with gifsicle
   - Consider lower frame rate (10-15 fps)

---

## File Naming Convention

```
demo_XX_feature_name.gif
```

Examples:
- `demo_01_quick_scan.gif`
- `demo_02_github_scanning.gif`
- `demo_03_semgrep_integration.gif`
- `demo_04_html_report.gif`
- `demo_05_comprehensive_scan.gif`

---

## Upload to GitHub

Two options:

### Option 1: Store in Repository
```bash
# Add to assets directory
mkdir -p docs/assets/demos
mv demo_*.gif docs/assets/demos/

# Commit
git add docs/assets/demos/
git commit -m "Add demo GIFs for v2.5.0 features"
git push
```

### Option 2: Use GitHub Issues (Recommended for large files)
1. Create a GitHub issue (can be private)
2. Drag and drop GIF into comment
3. GitHub uploads and provides CDN URL
4. Copy URL for use in README
5. Close issue (URL persists)

---

## Example VHS Scripts

### Quick Scan Demo
```vhs
# demo_quick_scan.tape
Output docs/assets/demos/demo_01_quick_scan.gif

Set FontSize 14
Set Width 1200
Set Height 600
Set Theme "Dracula"

Type "# Quick scan of MCP server"
Enter
Sleep 1s

Type "mcp-sentinel scan ./demo-server"
Enter
Sleep 8s

Type "# ✅ Scan completed in 2.3 seconds"
Sleep 3s
```

### GitHub Scanning Demo
```vhs
# demo_github_scanning.tape
Output docs/assets/demos/demo_02_github_scanning.gif

Set FontSize 14
Set Width 1200
Set Height 600
Set Theme "Dracula"

Type "# Scan GitHub repository directly (no cloning!)"
Enter
Sleep 1s

Type "mcp-sentinel scan https://github.com/modelcontextprotocol/servers"
Enter
Sleep 15s

Type "# 🐙 Cloned and scanned in 8.5 seconds"
Sleep 3s
```

---

## Screenshots for HTML Reports

Since HTML reports are interactive, capture screenshots:

### Tool: Chrome DevTools
1. Open HTML report in Chrome
2. Press F12 (DevTools)
3. Ctrl+Shift+P → "Capture full size screenshot"
4. Save as PNG

### Tool: Firefox
1. Open HTML report
2. F12 → "..." menu → "Take a screenshot" → "Save full page"

### Recommended screenshots:
- `screenshot_html_dashboard.png` - Full report overview
- `screenshot_html_risk_score.png` - Risk scoring section
- `screenshot_html_vulnerability_card.png` - Expanded vulnerability details

---

## Sample Demo Server Setup

Create a demo server with known vulnerabilities for consistent recordings:

```bash
# Clone or create demo server
mkdir demo-server
cd demo-server

# Create example files with vulnerabilities
cat > server.py << 'EOF'
import os
import subprocess

def read_file(filename):
    # Path traversal vulnerability
    path = os.path.join("/data", filename)
    with open(path) as f:
        return f.read()

def execute(cmd):
    # Command injection
    subprocess.run(cmd, shell=True)

# Hardcoded API key
API_KEY = "sk-proj-abc123def456..."
EOF
```

---

## Testing Your GIF

Before committing:
1. ✅ View in browser (drag and drop into Chrome)
2. ✅ Check file size (< 10MB ideally)
3. ✅ Verify text is readable at 100% zoom
4. ✅ Ensure important output is visible
5. ✅ Test autoplay in README preview

---

## Maintenance

Update GIFs when:
- Major version releases (v3.0.0, etc.)
- UI changes significantly
- New flagship features added
- Community requests better examples

Keep old GIFs tagged by version:
```
demo_01_quick_scan_v2.5.0.gif
demo_01_quick_scan_v3.0.0.gif
```

---

## Resources

- asciinema: https://asciinema.org/
- agg: https://github.com/asciinema/agg
- terminalizer: https://github.com/faressoft/terminalizer
- VHS: https://github.com/charmbracelet/vhs
- gifsicle: https://www.lcdf.org/gifsicle/

---

## Questions?

Open an issue: https://github.com/beejak/MCP_Scanner/issues
