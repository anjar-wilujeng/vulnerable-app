# Vulnerable Application for SonarQube SAST Testing

⚠️ **WARNING: This application contains intentional security vulnerabilities for testing purposes only!**

**DO NOT deploy this application to production or any public-facing environment!**

## Overview

This is a deliberately vulnerable Python Flask application designed for testing SonarQube's SAST (Static Application Security Testing) capabilities within the free tier limits (up to 50k lines of code).

## Purpose

- Test SonarQube's vulnerability detection capabilities
- Learn about common security vulnerabilities
- Practice secure coding by understanding what NOT to do
- Training and educational purposes only

## Vulnerabilities Included

This application contains examples of the following vulnerability types:

### 1. Injection Vulnerabilities
- **SQL Injection** - Direct string concatenation in SQL queries
- **Command Injection** - Unsanitized user input in system commands
- **XML External Entity (XXE)** - Parsing XML without disabling external entities
- **Server-Side Template Injection (SSTI)** - User input in templates
- **Log Injection** - Unsanitized input in log files

### 2. Authentication & Session Management
- **Hardcoded Credentials** - Passwords and secrets in source code
- **Weak Password Hashing** - Using MD5/SHA1 instead of bcrypt/argon2
- **Weak Password Policies** - Insufficient password requirements
- **Predictable Session Tokens** - Time-based or sequential tokens
- **No Session Expiration** - Sessions that never timeout
- **Session Fixation** - Session tokens not regenerated on login

### 3. Cryptographic Issues
- **Weak Encryption** - XOR cipher, Caesar cipher, Base64
- **ECB Mode** - Electronic Codebook mode for AES
- **Insecure Random** - Using `random` instead of `secrets`
- **Hardcoded Keys** - Encryption keys in source code
- **No Salt** - Password hashing without salts
- **Weak Key Derivation** - Single iteration hashing

### 4. Access Control
- **Missing Authentication** - Admin endpoints without auth
- **Missing Authorization** - No role-based access control
- **Insecure Direct Object Reference (IDOR)** - Direct access to objects by ID
- **Path Traversal** - Unrestricted file system access

### 5. Security Misconfiguration
- **Debug Mode Enabled** - Flask debug mode in production
- **Verbose Error Messages** - Exposing stack traces
- **Information Disclosure** - Leaking system information
- **Missing Security Headers** - No HSTS, CSP, etc.
- **Insecure SSL/TLS** - Disabled certificate verification

### 6. Sensitive Data Exposure
- **Passwords in Logs** - Plain text passwords in log files
- **API Keys in Code** - Hardcoded API keys
- **Credit Card Data** - Storing sensitive data unencrypted
- **Database Credentials** - Hardcoded connection strings

### 7. Deserialization Issues
- **Insecure Pickle** - Deserializing untrusted data
- **YAML Load** - Using unsafe YAML loader
- **eval()/exec()** - Executing arbitrary code

### 8. Business Logic Vulnerabilities
- **Race Conditions** - Non-atomic file operations
- **Resource Exhaustion** - No limits on memory allocation
- **Missing Rate Limiting** - No API rate limits

### 9. CSRF (Cross-Site Request Forgery)
- **No CSRF Tokens** - Missing CSRF protection on state-changing operations

### 10. Open Redirect
- **Unvalidated Redirects** - Redirecting to user-supplied URLs

## File Structure

```
vulnerable-app/
├── app.py              # Main Flask application with multiple vulnerabilities
├── auth.py             # Authentication with weak implementations
├── database.py         # Database operations with SQL injection
├── file_ops.py         # File operations with path traversal
├── crypto.py           # Weak cryptographic implementations
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

## Setup Instructions

### Prerequisites
- Python 3.8+
- SonarQube (local or cloud instance)
- Git

### Installation

1. Clone this repository:
```bash
git clone <your-repo-url>
cd vulnerable-app
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

⚠️ **DO NOT RUN THE APPLICATION** - This is for SAST scanning only!

## SonarQube Setup

### 1. Create a SonarQube Project

1. Sign up for SonarQube Cloud (free tier) at https://sonarcloud.io
2. Create a new project and link it to your GitHub repository
3. Get your project key and authentication token

### 2. Configure sonar-project.properties

Create a `sonar-project.properties` file:

```properties
sonar.projectKey=your_project_key
sonar.organization=your_organization
sonar.sources=.
sonar.python.version=3.8,3.9,3.10,3.11
sonar.exclusions=venv/**,**/__pycache__/**
```

### 3. Run SonarQube Scanner

Using SonarScanner CLI:
```bash
sonar-scanner \
  -Dsonar.projectKey=your_project_key \
  -Dsonar.organization=your_organization \
  -Dsonar.sources=. \
  -Dsonar.host.url=https://sonarcloud.io \
  -Dsonar.login=your_token
```

Or using GitHub Actions (see below).

## GitHub Actions Integration

Create `.github/workflows/sonarqube.yml`:

```yaml
name: SonarQube Analysis

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  sonarqube:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
      with:
        fetch-depth: 0
    
    - name: SonarQube Scan
      uses: SonarSource/sonarcloud-github-action@master
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

## Expected SonarQube Findings

SonarQube should detect:
- 50+ security vulnerabilities
- 30+ code smells
- Multiple security hotspots
- Hardcoded credentials
- SQL injection points
- Command injection vulnerabilities
- Weak cryptographic implementations
- And many more...

## Line Count

Current line count: ~2,500 lines (well within the 50k limit)

You can check line count with:
```bash
find . -name "*.py" -exec wc -l {} + | tail -1
```

## Learning Resources

After scanning with SonarQube, you can:
1. Review each vulnerability detected
2. Read SonarQube's explanations
3. Learn how to fix each issue
4. Compare with secure coding practices

## Security Warnings

🔴 **CRITICAL REMINDERS:**
- This application is INTENTIONALLY INSECURE
- NEVER deploy to production
- NEVER expose to the internet
- NEVER use any code from this project in real applications
- Use only for security testing and educational purposes
- Keep this repository private if you're not comfortable with public exposure

## Contributing

If you'd like to add more vulnerability examples:
1. Ensure they're well-documented
2. Add comments explaining the vulnerability
3. Keep within the 50k line limit
4. Test with SonarQube to ensure detection

## License

This project is for educational purposes only. Use at your own risk.

## Disclaimer

The creators of this application are not responsible for any misuse. This tool is provided for legitimate security testing and educational purposes only. Users must comply with all applicable laws and regulations.
