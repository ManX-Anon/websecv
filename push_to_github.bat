@echo off
REM Batch script to push project to GitHub
REM Make sure Git is installed before running this script

echo Checking Git installation...

git --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Git is not installed or not in PATH
    echo Please install Git from: https://git-scm.com/download/win
    pause
    exit /b 1
)

echo Git found!
echo.
echo Initializing Git repository...
git init

echo.
echo Adding remote repository...
git remote remove origin 2>nul
git remote add origin https://github.com/ManX-Anon/websecv.git

echo.
echo Adding all files...
git add .

echo.
echo Committing changes...
git commit -m "Initial commit: BurpSuite-like Web Application Vulnerability Scanner

Features:
- HTTP/HTTPS Proxy with TLS interception
- Intelligent web crawler with SPA support
- Active and passive vulnerability scanner
- Repeater tool for manual request editing
- Intruder/Fuzzer with multiple attack strategies
- Sequencer for token entropy analysis
- Collaborator/OAST service
- Extender API for custom plugins
- Comprehensive reporting (HTML, JSON, PDF)
- CI/CD integration support"

echo.
echo Setting default branch to main...
git branch -M main

echo.
echo Pushing to GitHub...
echo Note: You may be prompted for GitHub credentials
echo.

git push -u origin main

if errorlevel 1 (
    echo.
    echo Push failed. Please check:
    echo 1. Your GitHub credentials/authentication
    echo 2. Repository permissions
    echo 3. If the repository already exists and has content
    echo.
    echo For authentication, you may need to use a Personal Access Token:
    echo https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token
) else (
    echo.
    echo Successfully pushed to GitHub!
    echo Repository: https://github.com/ManX-Anon/websecv
)

pause

