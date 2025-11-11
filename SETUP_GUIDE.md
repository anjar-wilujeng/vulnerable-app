# Setup Guide: SonarQube SAST Testing

## Quick Start Guide for SonarQube Free Tier

### Prerequisites

1. **GitHub Account** - You'll host your code here
2. **SonarQube Cloud Account** - Free tier for testing
3. **Git** installed on your machine

### Step-by-Step Setup

#### 1. Prepare Your GitHub Repository

```bash
# Initialize git repository locally
cd vulnerable-app
git init

# Add all files
git add .

# Commit
git commit -m "Initial commit: Vulnerable app for SAST testing"

# Create a new repository on GitHub (via web interface)
# Then connect your local repo:
git remote add origin https://github.com/YOUR_USERNAME/vulnerable-app.git
git branch -M main
git push -u origin main
```

#### 2. Set Up SonarQube Cloud

1. **Go to SonarCloud**
   - Visit: https://sonarcloud.io
   - Click "Log in" and use GitHub to sign in

2. **Import Project**
   - Click the "+" icon or "Analyze new project"
   - Select your `vulnerable-app` repository
   - Choose "Free plan" (includes up to 50k lines of code)

3. **Configure Project**
   - Set project key: `vulnerable-app-sast-demo` (or your choice)
   - Set organization (usually your GitHub username)
   - Click "Set Up"

4. **Choose Analysis Method**
   - Select "With GitHub Actions" (recommended)
   - SonarCloud will show you the configuration

5. **Get Your Token**
   - SonarCloud will generate a `SONAR_TOKEN`
   - Copy this token (you'll need it in the next step)

#### 3. Configure GitHub Secrets

1. Go to your GitHub repository
2. Click "Settings" → "Secrets and variables" → "Actions"
3. Click "New repository secret"
4. Add the following secret:
   - Name: `SONAR_TOKEN`
   - Value: (paste the token from SonarCloud)
5. Click "Add secret"

#### 4. Update SonarQube Configuration

Edit `.github/workflows/sonarqube.yml` and update:

```yaml
-Dsonar.organization=YOUR_ORGANIZATION_KEY  # Replace with your organization
```

You can find your organization key in SonarCloud under your profile.

#### 5. Push to GitHub and Trigger Scan

```bash
# Make a small change (if needed) or just push
git add .
git commit -m "Configure SonarQube scanning"
git push origin main
```

The GitHub Action will automatically trigger and send your code to SonarQube for analysis.

#### 6. View Results

1. Go to https://sonarcloud.io
2. Click on your project
3. You should see:
   - **Security Vulnerabilities**: 50+ issues
   - **Code Smells**: 30+ issues
   - **Security Hotspots**: Multiple items
   - **Coverage**: N/A (no tests)

### Understanding Your SonarQube Dashboard

#### Main Metrics

- **Bugs**: 0 (we intentionally avoided runtime bugs)
- **Vulnerabilities**: 50+ (this is what we want to see!)
- **Security Hotspots**: 20+ (areas to review)
- **Code Smells**: 30+ (bad practices)
- **Coverage**: 0% (no tests in this demo)
- **Duplications**: Low (minimal duplicate code)

#### Key Vulnerability Categories You'll See

1. **SQL Injection** (High Severity)
   - Location: `database.py`, `app.py`
   - Count: ~8-10 instances

2. **Command Injection** (Critical Severity)
   - Location: `app.py`, `file_ops.py`
   - Count: ~5-7 instances

3. **Hardcoded Credentials** (High Severity)
   - Location: `auth.py`, `crypto.py`, `app.py`
   - Count: ~15-20 instances

4. **Weak Cryptography** (Medium-High Severity)
   - Location: `crypto.py`, `auth.py`
   - Count: ~10-15 instances

5. **Path Traversal** (High Severity)
   - Location: `file_ops.py`, `app.py`
   - Count: ~3-5 instances

6. **Insecure Deserialization** (Critical Severity)
   - Location: `file_ops.py`, `app.py`
   - Count: ~3-4 instances

### Free Tier Limits

✅ **Your project is within limits:**
- Total lines: ~2,500 lines
- Limit: 50,000 lines
- Usage: ~5% of available quota

You can scan:
- ✅ This private project (within 50k lines)
- ✅ Unlimited public projects
- ✅ Pull request analysis
- ✅ Main branch analysis
- ✅ Up to 5 users

### Manual Scanning (Alternative Method)

If you prefer to scan locally instead of using GitHub Actions:

#### Install SonarScanner

**macOS:**
```bash
brew install sonar-scanner
```

**Linux:**
```bash
# Download from: https://docs.sonarqube.org/latest/analysis/scan/sonarscanner/
# Extract and add to PATH
```

**Windows:**
```bash
# Download from: https://docs.sonarqube.org/latest/analysis/scan/sonarscanner/
# Extract and add to PATH
```

#### Run Scanner

```bash
sonar-scanner \
  -Dsonar.projectKey=vulnerable-app-sast-demo \
  -Dsonar.organization=YOUR_ORGANIZATION \
  -Dsonar.sources=. \
  -Dsonar.host.url=https://sonarcloud.io \
  -Dsonar.login=YOUR_SONAR_TOKEN
```

### Analyzing Specific Vulnerabilities

#### Example: SQL Injection in database.py

SonarQube will flag lines like:
```python
query = "SELECT * FROM users WHERE username = '" + username + "'"
```

**Why it's vulnerable:**
- Direct string concatenation
- No input validation
- Allows SQL injection attacks

**How to fix:**
```python
# Use parameterized queries
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))
```

#### Example: Command Injection in app.py

SonarQube will flag:
```python
result = os.popen(f'ping -c 1 {host}').read()
```

**Why it's vulnerable:**
- User input directly in command
- Allows arbitrary command execution

**How to fix:**
```python
# Use subprocess with list arguments
import subprocess
result = subprocess.run(['ping', '-c', '1', host], 
                       capture_output=True, 
                       timeout=5)
```

### Troubleshooting

#### Issue: SonarQube scan fails

**Solution:**
1. Check your `SONAR_TOKEN` is correct in GitHub secrets
2. Verify organization key in workflow file
3. Check GitHub Actions logs for specific errors

#### Issue: No vulnerabilities detected

**Solution:**
1. Ensure Python language is enabled in SonarQube
2. Check file extensions are `.py`
3. Verify files are not excluded in `.gitignore` or `sonar-project.properties`

#### Issue: Over 50k lines limit

**Solution:**
- This project is only ~2,500 lines, well under the limit
- If you add more code, use exclusions in `sonar-project.properties`

### Next Steps

1. **Review Each Vulnerability**
   - Click on each issue in SonarQube
   - Read the explanation
   - Understand why it's dangerous

2. **Learn Secure Coding**
   - Compare vulnerable code with secure alternatives
   - Read OWASP guidelines
   - Practice writing secure code

3. **Experiment**
   - Try adding new vulnerabilities
   - See if SonarQube detects them
   - Learn what patterns trigger alerts

4. **Create a Fixed Version**
   - Make a new branch: `git checkout -b secure-version`
   - Fix all vulnerabilities
   - Scan again and compare results

### Additional Resources

- **SonarQube Documentation**: https://docs.sonarqube.org/
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **Python Security**: https://bandit.readthedocs.io/
- **Secure Coding Guide**: https://cheatsheetseries.owasp.org/

### Support

If you encounter issues:
1. Check SonarQube community forums
2. Review GitHub Actions logs
3. Verify all configuration files are correct
4. Ensure your repository is accessible to SonarQube

---

**Remember**: This is a learning tool. Never use this vulnerable code in production!
