#!/bin/bash

# ============================================================================
# MCP Sentinel - GitHub Upload Script
# ============================================================================
# This script will help you upload MCP Sentinel to GitHub
#
# Usage:
#   1. Create a new repository on GitHub named "mcp-sentinel"
#   2. Replace YOUR_USERNAME below with your actual GitHub username
#   3. Run this script: bash UPLOAD_TO_GITHUB.sh
# ============================================================================

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║         MCP Sentinel - GitHub Upload Script              ║"
echo "║                   Version 3.0.0                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ============================================================================
# STEP 1: Configuration
# ============================================================================

echo -e "${YELLOW}Step 1: Configuration${NC}"
echo ""
read -p "Enter your GitHub username: " GITHUB_USERNAME

if [ -z "$GITHUB_USERNAME" ]; then
    echo -e "${RED}Error: GitHub username is required${NC}"
    exit 1
fi

REPO_NAME="mcp-sentinel"
GITHUB_URL="https://github.com/$GITHUB_USERNAME/$REPO_NAME.git"

echo -e "${GREEN}✓ Repository URL: $GITHUB_URL${NC}"
echo ""

# ============================================================================
# STEP 2: Verify Repository Status
# ============================================================================

echo -e "${YELLOW}Step 2: Verifying repository status...${NC}"
echo ""

# Check if we're in a git repository
if [ ! -d .git ]; then
    echo -e "${RED}Error: Not in a git repository. Please run from the project root.${NC}"
    exit 1
fi

# Check for uncommitted changes
if [ -n "$(git status --porcelain)" ]; then
    echo -e "${YELLOW}Warning: You have uncommitted changes${NC}"
    git status --short
    echo ""
    read -p "Commit these changes before upload? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        git add .
        git commit -m "chore: prepare for GitHub upload"
    fi
fi

echo -e "${GREEN}✓ Repository is clean${NC}"
echo ""

# ============================================================================
# STEP 3: Check for Existing Remote
# ============================================================================

echo -e "${YELLOW}Step 3: Checking remote configuration...${NC}"
echo ""

if git remote | grep -q "^origin$"; then
    CURRENT_ORIGIN=$(git remote get-url origin)
    echo -e "${YELLOW}Warning: Remote 'origin' already exists: $CURRENT_ORIGIN${NC}"
    read -p "Remove existing remote and add new one? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        git remote remove origin
        echo -e "${GREEN}✓ Removed existing remote${NC}"
    else
        echo -e "${RED}Aborted${NC}"
        exit 1
    fi
fi

# ============================================================================
# STEP 4: Add GitHub Remote
# ============================================================================

echo -e "${YELLOW}Step 4: Adding GitHub remote...${NC}"
echo ""

git remote add origin "$GITHUB_URL"
echo -e "${GREEN}✓ Added remote: $GITHUB_URL${NC}"
echo ""

# ============================================================================
# STEP 5: Pre-Upload Instructions
# ============================================================================

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║            IMPORTANT: Create GitHub Repository            ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
echo "Before pushing, please:"
echo ""
echo "1. Go to: ${BLUE}https://github.com/new${NC}"
echo ""
echo "2. Fill in:"
echo "   - Repository name: ${GREEN}$REPO_NAME${NC}"
echo "   - Description: ${GREEN}Enterprise-grade security scanner for MCP servers${NC}"
echo "   - Visibility: ${GREEN}Public${NC} (recommended)"
echo "   - ${YELLOW}DON'T${NC} initialize with README, .gitignore, or license"
echo ""
echo "3. Click ${GREEN}Create repository${NC}"
echo ""
read -p "Press Enter when you've created the repository on GitHub..."
echo ""

# ============================================================================
# STEP 6: Push to GitHub
# ============================================================================

echo -e "${YELLOW}Step 6: Pushing to GitHub...${NC}"
echo ""

echo "Current branch: $(git branch --show-current)"
echo "Commits to push:"
git log --oneline -3
echo ""

read -p "Push to GitHub now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Pushing to GitHub..."
    git push -u origin master

    if [ $? -eq 0 ]; then
        echo ""
        echo -e "${GREEN}"
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║                    SUCCESS!                               ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        echo ""
        echo "Your repository is now on GitHub!"
        echo ""
        echo "Repository URL: ${BLUE}https://github.com/$GITHUB_USERNAME/$REPO_NAME${NC}"
        echo ""
        echo -e "${YELLOW}Next steps:${NC}"
        echo ""
        echo "1. View your repo:"
        echo "   ${BLUE}https://github.com/$GITHUB_USERNAME/$REPO_NAME${NC}"
        echo ""
        echo "2. Create a release:"
        echo "   ${BLUE}https://github.com/$GITHUB_USERNAME/$REPO_NAME/releases/new${NC}"
        echo "   - Tag: ${GREEN}v3.0.0-alpha${NC}"
        echo "   - Title: ${GREEN}MCP Sentinel v3.0.0 Alpha - Secrets Detection${NC}"
        echo ""
        echo "3. Enable GitHub Actions:"
        echo "   ${BLUE}https://github.com/$GITHUB_USERNAME/$REPO_NAME/actions${NC}"
        echo ""
        echo "4. Add topics for discoverability:"
        echo "   ${GREEN}security, scanner, mcp, python, secrets-detection${NC}"
        echo ""
        echo -e "${GREEN}🎉 Congratulations! Your project is live!${NC}"
    else
        echo ""
        echo -e "${RED}Error: Failed to push to GitHub${NC}"
        echo ""
        echo "Possible issues:"
        echo "- Make sure the repository exists on GitHub"
        echo "- Check your GitHub authentication (SSH key or token)"
        echo "- Verify the repository URL is correct"
        exit 1
    fi
else
    echo ""
    echo -e "${YELLOW}Push cancelled. You can push manually later with:${NC}"
    echo "  git push -u origin master"
fi

echo ""
