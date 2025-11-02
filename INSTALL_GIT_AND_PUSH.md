# Quick Guide: Push to GitHub

## Step 1: Install Git

1. Download Git for Windows: https://git-scm.com/download/win
2. Run the installer with default settings
3. **Important:** During installation, select "Git from the command line and also from 3rd-party software"
4. Restart your terminal/PowerShell after installation

## Step 2: Push to GitHub

After Git is installed, open PowerShell in this directory and run:

```powershell
# Initialize git repository
git init

# Add remote repository
git remote add origin https://github.com/ManX-Anon/websecv.git

# Add all files
git add .

# Commit changes
git commit -m "Initial commit: BurpSuite-like Web Application Vulnerability Scanner"

# Set main branch
git branch -M main

# Push to GitHub
git push -u origin main
```

## Authentication

When pushing, GitHub will ask for credentials. You have two options:

### Option 1: Personal Access Token (Recommended)
1. Go to: https://github.com/settings/tokens
2. Click "Generate new token (classic)"
3. Select scopes: `repo` (full control of private repositories)
4. Generate and copy the token
5. When prompted for password, paste the token

### Option 2: Use the Automated Script
After installing Git, simply run:
```powershell
.\push_to_github.ps1
```

## Alternative: Use GitHub Desktop

1. Download GitHub Desktop: https://desktop.github.com/
2. Sign in with your GitHub account
3. File → Add Local Repository
4. Select this folder
5. Publish repository to GitHub

## If Repository Already Exists

If the GitHub repository already has content (like a README), you may need to pull first:

```bash
git pull origin main --allow-unrelated-histories
git push -u origin main
```

