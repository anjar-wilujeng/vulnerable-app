"""
Cryptography module with intentional security vulnerabilities
"""

import hashlib
import base64
import random
import string

# Vulnerability: Weak encryption
class WeakEncryption:
    def __init__(self):
        # Vulnerability: Hardcoded encryption key
        self.key = "my_secret_key_123"
    
    # Vulnerability: XOR cipher (very weak)
    def xor_encrypt(self, plaintext, key=None):
        if key is None:
            key = self.key
        
        result = []
        for i, char in enumerate(plaintext):
            key_char = key[i % len(key)]
            result.append(chr(ord(char) ^ ord(key_char)))
        
        return ''.join(result)
    
    def xor_decrypt(self, ciphertext, key=None):
        # XOR is symmetric
        return self.xor_encrypt(ciphertext, key)
    
    # Vulnerability: Caesar cipher (trivially broken)
    def caesar_encrypt(self, plaintext, shift=3):
        result = []
        for char in plaintext:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result.append(chr((ord(char) - base + shift) % 26 + base))
            else:
                result.append(char)
        return ''.join(result)
    
    # Vulnerability: Base64 encoding treated as encryption
    def base64_encrypt(self, plaintext):
        # This is encoding, not encryption!
        return base64.b64encode(plaintext.encode()).decode()
    
    def base64_decrypt(self, ciphertext):
        return base64.b64decode(ciphertext).decode()

class WeakHashing:
    # Vulnerability: Using MD5
    @staticmethod
    def md5_hash(data):
        return hashlib.md5(data.encode()).hexdigest()
    
    # Vulnerability: Using SHA1
    @staticmethod
    def sha1_hash(data):
        return hashlib.sha1(data.encode()).hexdigest()
    
    # Vulnerability: No salt in password hashing
    @staticmethod
    def hash_password_no_salt(password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    # Vulnerability: Weak salt
    @staticmethod
    def hash_password_weak_salt(password):
        salt = "fixed_salt"  # Same salt for all passwords
        return hashlib.sha256((salt + password).encode()).hexdigest()
    
    # Vulnerability: Fast hashing for passwords
    @staticmethod
    def hash_password_fast(password):
        # SHA256 is too fast for passwords, should use bcrypt/scrypt/argon2
        return hashlib.sha256(password.encode()).hexdigest()

class InsecureRandomness:
    # Vulnerability: Using random instead of secrets
    @staticmethod
    def generate_token(length=32):
        # Vulnerable: random is not cryptographically secure
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
    
    # Vulnerability: Predictable random with seed
    @staticmethod
    def generate_seeded_token():
        random.seed(12345)  # Predictable seed
        return random.randint(100000, 999999)
    
    # Vulnerability: Using timestamp as seed
    @staticmethod
    def generate_time_seeded_token():
        import time
        random.seed(int(time.time()))
        return ''.join(random.choices(string.ascii_letters, k=16))
    
    # Vulnerability: Weak random for cryptographic purposes
    @staticmethod
    def generate_encryption_key():
        # Using random for crypto key generation
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

class InsecureCrypto:
    # Vulnerability: ECB mode (Electronic Codebook)
    @staticmethod
    def aes_ecb_encrypt(plaintext, key):
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        
        cipher = AES.new(key.encode()[:16], AES.MODE_ECB)  # ECB mode is insecure
        padded = pad(plaintext.encode(), AES.block_size)
        return base64.b64encode(cipher.encrypt(padded)).decode()
    
    # Vulnerability: No IV (Initialization Vector)
    @staticmethod
    def encrypt_without_iv(plaintext, key):
        # Deterministic encryption - same plaintext produces same ciphertext
        return WeakHashing.sha256_hash(key + plaintext)
    
    # Vulnerability: Reused IV
    @staticmethod
    def encrypt_with_static_iv(plaintext, key):
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        
        # Vulnerable: Same IV for all encryptions
        static_iv = b'1234567890123456'
        cipher = AES.new(key.encode()[:16], AES.MODE_CBC, static_iv)
        padded = pad(plaintext.encode(), AES.block_size)
        return base64.b64encode(cipher.encrypt(padded)).decode()

class SSLInsecurity:
    # Vulnerability: Disabling SSL certificate verification
    @staticmethod
    def make_insecure_request(url):
        import requests
        # Vulnerable: verify=False disables SSL verification
        response = requests.get(url, verify=False)
        return response.text
    
    # Vulnerability: Using old SSL/TLS versions
    @staticmethod
    def get_ssl_context():
        import ssl
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)  # Allows old versions
        context.check_hostname = False  # Vulnerable
        context.verify_mode = ssl.CERT_NONE  # Vulnerable
        return context

class TokenGeneration:
    # Vulnerability: Predictable session tokens
    @staticmethod
    def generate_session_id(username):
        import time
        # Vulnerable: Predictable based on username and time
        timestamp = int(time.time())
        token = f"{username}_{timestamp}"
        return base64.b64encode(token.encode()).decode()
    
    # Vulnerability: Short random tokens
    @staticmethod
    def generate_short_token():
        # Only 6 digits - easily brute forced
        return str(random.randint(100000, 999999))
    
    # Vulnerability: Sequential tokens
    counter = 1000
    
    @classmethod
    def generate_sequential_token(cls):
        cls.counter += 1
        return f"TOKEN_{cls.counter}"

class DataProtection:
    # Vulnerability: Storing sensitive data in plain text
    @staticmethod
    def store_credit_card(card_number, cvv, expiry):
        data = {
            'card_number': card_number,  # Plain text!
            'cvv': cvv,  # Plain text!
            'expiry': expiry
        }
        import json
        with open('credit_cards.json', 'w') as f:
            json.dump(data, f)
    
    # Vulnerability: Reversible encoding of passwords
    @staticmethod
    def store_password(username, password):
        # Base64 is easily reversed
        encoded_password = base64.b64encode(password.encode()).decode()
        return {username: encoded_password}
    
    # Vulnerability: Exposing private keys
    PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdef...
-----END RSA PRIVATE KEY-----"""
    
    @staticmethod
    def get_private_key():
        return DataProtection.PRIVATE_KEY

# Vulnerability: Home-grown crypto
def custom_encryption(plaintext, key):
    # Never roll your own crypto!
    result = []
    for i, char in enumerate(plaintext):
        # Simple substitution with XOR and rotation
        encrypted = (ord(char) ^ ord(key[i % len(key)])) + i
        result.append(chr(encrypted % 256))
    return ''.join(result)

# Vulnerability: Weak key derivation
def derive_key_weak(password, salt):
    # Single iteration of SHA256 is not sufficient
    return hashlib.sha256((password + salt).encode()).digest()

# Vulnerability: Information leakage through timing
def constant_time_compare_vulnerable(a, b):
    # Vulnerable to timing attacks - stops at first mismatch
    if len(a) != len(b):
        return False
    
    for i in range(len(a)):
        if a[i] != b[i]:
            return False  # Early return leaks information
    
    return True

# Vulnerability: Weak PRNG seeding
def initialize_random():
    import time
    # Vulnerable: Time-based seed is predictable
    random.seed(int(time.time()))

# Vulnerability: Cryptographic key in source code
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_SECRET_KEY = "sk_live_51H1234567890abcdef"
DATABASE_PASSWORD = "SuperSecretP@ssw0rd123"
API_SECRET = "my_api_secret_key_12345"

# Vulnerability: Encryption without authentication
def encrypt_only(plaintext, key):
    # Missing MAC/HMAC - vulnerable to tampering
    return WeakEncryption().xor_encrypt(plaintext, key)
