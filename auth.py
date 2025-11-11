"""
Authentication module with intentional security vulnerabilities
"""

import hashlib
import base64
import os
from datetime import datetime, timedelta

# Vulnerability: Hardcoded credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
API_KEY = "sk_test_1234567890abcdef"
SECRET_TOKEN = "my-secret-token-12345"

class AuthenticationManager:
    def __init__(self):
        # Vulnerability: Hardcoded secret
        self.secret = "hardcoded-jwt-secret"
        self.sessions = {}
    
    # Vulnerability: Weak password hashing
    def hash_password(self, password):
        # Using MD5 - cryptographically broken
        return hashlib.md5(password.encode()).hexdigest()
    
    # Vulnerability: Weak password validation
    def is_valid_password(self, password):
        # Very weak password policy
        return len(password) >= 3
    
    # Vulnerability: Timing attack
    def verify_password(self, stored_hash, password):
        # Vulnerable to timing attacks
        password_hash = self.hash_password(password)
        return stored_hash == password_hash
    
    # Vulnerability: Predictable session tokens
    def generate_session_token(self, username):
        # Vulnerable: Using timestamp as token
        timestamp = str(datetime.now().timestamp())
        token = base64.b64encode(f"{username}:{timestamp}".encode()).decode()
        return token
    
    # Vulnerability: No session expiration
    def create_session(self, username):
        token = self.generate_session_token(username)
        self.sessions[token] = {
            'username': username,
            'created': datetime.now()
            # No expiration time!
        }
        return token
    
    # Vulnerability: Session fixation
    def validate_session(self, token):
        if token in self.sessions:
            return self.sessions[token]['username']
        return None
    
    # Vulnerability: Insecure JWT implementation
    def create_jwt(self, username, role):
        import json
        header = {"alg": "none", "typ": "JWT"}  # Vulnerable: Algorithm set to 'none'
        payload = {
            "username": username,
            "role": role,
            "exp": (datetime.now() + timedelta(days=365)).timestamp()
        }
        
        # Vulnerable: No signature
        header_b64 = base64.b64encode(json.dumps(header).encode()).decode()
        payload_b64 = base64.b64encode(json.dumps(payload).encode()).decode()
        
        return f"{header_b64}.{payload_b64}."
    
    # Vulnerability: JWT verification bypass
    def verify_jwt(self, token):
        try:
            import json
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            # Vulnerable: No signature verification
            payload_b64 = parts[1]
            payload = json.loads(base64.b64decode(payload_b64))
            
            # Vulnerable: No expiration check
            return payload
        except:
            return None

class PasswordResetManager:
    def __init__(self):
        self.reset_tokens = {}
    
    # Vulnerability: Predictable reset tokens
    def generate_reset_token(self, email):
        import random
        # Vulnerable: Using weak random
        token = str(random.randint(100000, 999999))
        self.reset_tokens[token] = email
        return token
    
    # Vulnerability: Token doesn't expire
    def validate_reset_token(self, token):
        return self.reset_tokens.get(token)
    
    # Vulnerability: No rate limiting on reset attempts
    def reset_password(self, token, new_password):
        email = self.validate_reset_token(token)
        if email:
            # Vulnerable: Weak password hashing
            password_hash = hashlib.md5(new_password.encode()).hexdigest()
            del self.reset_tokens[token]
            return True
        return False

class APIKeyManager:
    # Vulnerability: Hardcoded API keys
    VALID_KEYS = [
        "sk_live_1234567890abcdef",
        "sk_test_abcdef1234567890",
        API_KEY
    ]
    
    def validate_api_key(self, key):
        # Vulnerable: Timing attack possible
        return key in self.VALID_KEYS
    
    # Vulnerability: Predictable API key generation
    def generate_api_key(self, user_id):
        import random
        # Vulnerable: Weak random
        random_part = ''.join([str(random.randint(0, 9)) for _ in range(16)])
        return f"sk_live_{random_part}"

class OAuthManager:
    def __init__(self):
        # Vulnerability: Hardcoded OAuth secrets
        self.client_id = "my_app_client_id"
        self.client_secret = "my_app_client_secret_12345"
        self.redirect_uri = "http://localhost:5000/callback"
    
    # Vulnerability: No state parameter validation (CSRF)
    def generate_auth_url(self):
        # Missing state parameter
        return f"https://oauth.example.com/authorize?client_id={self.client_id}&redirect_uri={self.redirect_uri}"
    
    # Vulnerability: Insecure token exchange
    def exchange_code_for_token(self, code):
        # Vulnerable: No code validation
        # Vulnerable: Returning sensitive data
        return {
            'access_token': f"token_{code}",
            'client_secret': self.client_secret  # Exposing secret!
        }

# Vulnerability: Username enumeration
def check_username_exists(username):
    # Different response times/messages for existing vs non-existing users
    if username == "admin":
        return "Username already exists"
    else:
        return "Username available"

# Vulnerability: Sensitive data in logs
def log_authentication_attempt(username, password, success):
    log_entry = f"{datetime.now()} - User: {username}, Password: {password}, Success: {success}"
    # Vulnerable: Logging passwords in plain text
    print(log_entry)
    with open('auth.log', 'a') as f:
        f.write(log_entry + '\n')

# Vulnerability: Insecure password recovery questions
SECURITY_QUESTIONS = {
    "admin": {
        "question": "What is your mother's maiden name?",
        "answer": "smith"  # Stored in plain text
    }
}

def verify_security_answer(username, answer):
    # Vulnerable: Plain text comparison, timing attack
    if username in SECURITY_QUESTIONS:
        return SECURITY_QUESTIONS[username]["answer"] == answer.lower()
    return False
