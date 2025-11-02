# Git Setup Instructions

To push this project to GitHub, follow these steps:

## 1. Install Git

If Git is not installed, download and install it from:
https://git-scm.com/download/win

## 2. Initialize Git Repository

```bash
git init
```

## 3. Add Remote Repository

```bash
git remote add origin https://github.com/ManX-Anon/websecv.git
```

## 4. Create .gitignore (if needed)

The project already has a `.gitignore` file with appropriate exclusions.

## 5. Add and Commit Files

```bash
git add .
git commit -m "Initial commit: BurpSuite-like Web Application Vulnerability Scanner"
```

## 6. Push to GitHub

```bash
git branch -M main
git push -u origin main
```

## If Authentication is Required

If you encounter authentication issues, you may need to:

1. **Use Personal Access Token (Recommended)**:
   - Go to GitHub Settings → Developer settings → Personal access tokens
   - Generate a new token with `repo` permissions
   - Use the token as password when prompted

2. **Or use SSH**:
   ```bash
   git remote set-url origin git@github.com:ManX-Anon/websecv.git
   ```

## Alternative: Using GitHub Desktop

You can also use GitHub Desktop application for a GUI-based approach:
https://desktop.github.com/

