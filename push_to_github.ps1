# PowerShell script to push project to GitHub
# Make sure Git is installed before running this script

Write-Host "Checking Git installation..." -ForegroundColor Yellow

# Check if git is available
try {
    $gitVersion = git --version
    Write-Host "Git found: $gitVersion" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Git is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Git from: https://git-scm.com/download/win" -ForegroundColor Yellow
    exit 1
}

Write-Host "`nInitializing Git repository..." -ForegroundColor Yellow
git init

Write-Host "`nAdding remote repository..." -ForegroundColor Yellow
git remote add origin https://github.com/ManX-Anon/websecv.git

# Remove if already exists and re-add
git remote remove origin 2>$null
git remote add origin https://github.com/ManX-Anon/websecv.git

Write-Host "`nAdding all files..." -ForegroundColor Yellow
git add .

Write-Host "`nCommitting changes..." -ForegroundColor Yellow
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

Write-Host "`nSetting default branch to main..." -ForegroundColor Yellow
git branch -M main

Write-Host "`nPushing to GitHub..." -ForegroundColor Yellow
Write-Host "Note: You may be prompted for GitHub credentials" -ForegroundColor Cyan

git push -u origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nSuccessfully pushed to GitHub!" -ForegroundColor Green
    Write-Host "Repository: https://github.com/ManX-Anon/websecv" -ForegroundColor Cyan
} else {
    Write-Host "`nPush failed. Please check:" -ForegroundColor Red
    Write-Host "1. Your GitHub credentials/authentication" -ForegroundColor Yellow
    Write-Host "2. Repository permissions" -ForegroundColor Yellow
    Write-Host "3. If the repository already exists and has content" -ForegroundColor Yellow
    Write-Host "`nFor authentication, you may need to use a Personal Access Token:" -ForegroundColor Cyan
    Write-Host "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token" -ForegroundColor Cyan
}

