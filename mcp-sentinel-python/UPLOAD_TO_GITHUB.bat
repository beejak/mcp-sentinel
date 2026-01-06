@echo off
REM ============================================================================
REM MCP Sentinel - GitHub Upload Script (Windows)
REM ============================================================================
REM This script will help you upload MCP Sentinel to GitHub
REM
REM Usage:
REM   1. Create a new repository on GitHub named "mcp-sentinel"
REM   2. Run this script: UPLOAD_TO_GITHUB.bat
REM ============================================================================

title MCP Sentinel - GitHub Upload
color 0A

echo.
echo ============================================================
echo          MCP Sentinel - GitHub Upload Script
echo                   Version 3.0.0
echo ============================================================
echo.

REM ============================================================================
REM STEP 1: Configuration
REM ============================================================================

echo Step 1: Configuration
echo.
set /p GITHUB_USERNAME="Enter your GitHub username: "

if "%GITHUB_USERNAME%"=="" (
    echo Error: GitHub username is required
    pause
    exit /b 1
)

set REPO_NAME=mcp-sentinel
set GITHUB_URL=https://github.com/%GITHUB_USERNAME%/%REPO_NAME%.git

echo.
echo Repository URL: %GITHUB_URL%
echo.

REM ============================================================================
REM STEP 2: Verify Repository Status
REM ============================================================================

echo Step 2: Verifying repository status...
echo.

if not exist .git (
    echo Error: Not in a git repository. Please run from the project root.
    pause
    exit /b 1
)

git status --short
echo.

REM ============================================================================
REM STEP 3: Check for Existing Remote
REM ============================================================================

echo Step 3: Checking remote configuration...
echo.

git remote | find "origin" >nul
if %errorlevel% equ 0 (
    echo Warning: Remote 'origin' already exists
    git remote get-url origin
    set /p REMOVE_REMOTE="Remove existing remote and add new one? (y/n): "
    if /i "%REMOVE_REMOTE%"=="y" (
        git remote remove origin
        echo Removed existing remote
    ) else (
        echo Aborted
        pause
        exit /b 1
    )
)

REM ============================================================================
REM STEP 4: Add GitHub Remote
REM ============================================================================

echo.
echo Step 4: Adding GitHub remote...
echo.

git remote add origin %GITHUB_URL%
echo Added remote: %GITHUB_URL%
echo.

REM ============================================================================
REM STEP 5: Pre-Upload Instructions
REM ============================================================================

echo.
echo ============================================================
echo         IMPORTANT: Create GitHub Repository
echo ============================================================
echo.
echo Before pushing, please:
echo.
echo 1. Go to: https://github.com/new
echo.
echo 2. Fill in:
echo    - Repository name: %REPO_NAME%
echo    - Description: Enterprise-grade security scanner for MCP servers
echo    - Visibility: Public (recommended)
echo    - DON'T initialize with README, .gitignore, or license
echo.
echo 3. Click "Create repository"
echo.
pause

REM ============================================================================
REM STEP 6: Push to GitHub
REM ============================================================================

echo.
echo Step 6: Pushing to GitHub...
echo.

echo Current branch:
git branch --show-current
echo.

echo Commits to push:
git log --oneline -3
echo.

set /p PUSH_NOW="Push to GitHub now? (y/n): "
if /i "%PUSH_NOW%"=="y" (
    echo.
    echo Pushing to GitHub...
    git push -u origin master

    if %errorlevel% equ 0 (
        echo.
        echo ============================================================
        echo                       SUCCESS!
        echo ============================================================
        echo.
        echo Your repository is now on GitHub!
        echo.
        echo Repository URL: https://github.com/%GITHUB_USERNAME%/%REPO_NAME%
        echo.
        echo Next steps:
        echo.
        echo 1. View your repo:
        echo    https://github.com/%GITHUB_USERNAME%/%REPO_NAME%
        echo.
        echo 2. Create a release:
        echo    https://github.com/%GITHUB_USERNAME%/%REPO_NAME%/releases/new
        echo    - Tag: v3.0.0-alpha
        echo    - Title: MCP Sentinel v3.0.0 Alpha - Secrets Detection
        echo.
        echo 3. Enable GitHub Actions:
        echo    https://github.com/%GITHUB_USERNAME%/%REPO_NAME%/actions
        echo.
        echo 4. Add topics:
        echo    security, scanner, mcp, python, secrets-detection
        echo.
        echo Congratulations! Your project is live!
    ) else (
        echo.
        echo Error: Failed to push to GitHub
        echo.
        echo Possible issues:
        echo - Make sure the repository exists on GitHub
        echo - Check your GitHub authentication
        echo - Verify the repository URL is correct
    )
) else (
    echo.
    echo Push cancelled. You can push manually later with:
    echo   git push -u origin master
)

echo.
pause
