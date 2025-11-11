"""
Vulnerable Flask Application for SonarQube SAST Testing
WARNING: This code contains intentional security vulnerabilities for testing purposes only!
DO NOT use in production!
"""

import os
import pickle
import sqlite3
import subprocess
from flask import Flask, request, render_template_string, session, redirect, url_for
import hashlib

app = Flask(__name__)
app.secret_key = "hardcoded-secret-key-123"  # Vulnerability: Hardcoded secret

# Vulnerability: SQL Injection
def check_user_credentials(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable SQL query - direct string concatenation
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result

# Vulnerability: Command Injection
@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host', '')
    # Vulnerable: Direct command execution without sanitization
    result = os.popen(f'ping -c 1 {host}').read()
    return result

# Vulnerability: Path Traversal
@app.route('/read-file', methods=['GET'])
def read_file():
    filename = request.args.get('file', '')
    # Vulnerable: No path validation
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return content
    except Exception as e:
        return str(e)

# Vulnerability: Server-Side Template Injection (SSTI)
@app.route('/greet', methods=['GET'])
def greet():
    name = request.args.get('name', 'Guest')
    # Vulnerable: User input directly in template
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

# Vulnerability: Insecure Deserialization
@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    data = request.data
    # Vulnerable: Unpickling untrusted data
    obj = pickle.loads(data)
    return str(obj)

# Vulnerability: Weak Cryptography
def weak_hash_password(password):
    # Vulnerable: Using MD5 for password hashing
    return hashlib.md5(password.encode()).hexdigest()

# Vulnerability: Missing Authentication
@app.route('/admin/delete-user', methods=['POST'])
def delete_user():
    user_id = request.form.get('user_id')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE id={user_id}")
    conn.commit()
    conn.close()
    return "User deleted"

# Vulnerability: Information Disclosure
@app.route('/debug')
def debug_info():
    # Vulnerable: Exposing sensitive system information
    info = {
        'env': dict(os.environ),
        'secret_key': app.secret_key,
        'debug': app.debug
    }
    return str(info)

# Vulnerability: Open Redirect
@app.route('/redirect')
def redirect_url():
    target = request.args.get('url', '/')
    # Vulnerable: No validation of redirect URL
    return redirect(target)

# Vulnerability: XML External Entity (XXE)
@app.route('/parse-xml', methods=['POST'])
def parse_xml():
    import xml.etree.ElementTree as ET
    xml_data = request.data
    # Vulnerable: Parsing XML without disabling external entities
    root = ET.fromstring(xml_data)
    return ET.tostring(root)

# Vulnerability: Insufficient logging
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Vulnerable: Password in plain text, weak hashing
    hashed_password = weak_hash_password(password)
    
    user = check_user_credentials(username, hashed_password)
    
    if user:
        session['user'] = username
        # No logging of authentication attempts
        return "Login successful"
    return "Login failed"

# Vulnerability: CSRF - Missing CSRF protection
@app.route('/change-password', methods=['POST'])
def change_password():
    new_password = request.form.get('new_password')
    username = session.get('user')
    
    if username:
        hashed = weak_hash_password(new_password)
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute(f"UPDATE users SET password='{hashed}' WHERE username='{username}'")
        conn.commit()
        conn.close()
        return "Password changed"
    return "Not logged in"

# Vulnerability: Race Condition
counter_file = 'counter.txt'

@app.route('/increment')
def increment_counter():
    # Vulnerable: Race condition in file access
    if os.path.exists(counter_file):
        with open(counter_file, 'r') as f:
            count = int(f.read())
    else:
        count = 0
    
    count += 1
    
    with open(counter_file, 'w') as f:
        f.write(str(count))
    
    return str(count)

# Vulnerability: Insecure Random
import random

@app.route('/generate-token')
def generate_token():
    # Vulnerable: Using insecure random for security token
    token = ''.join([str(random.randint(0, 9)) for _ in range(10)])
    return token

# Vulnerability: Resource Exhaustion (DoS)
@app.route('/allocate')
def allocate_memory():
    size = int(request.args.get('size', 1000))
    # Vulnerable: No limit on resource allocation
    data = 'x' * size * 1024 * 1024  # Allocate size MB
    return f"Allocated {size} MB"

# Vulnerability: Improper Error Handling
@app.route('/divide')
def divide():
    try:
        a = int(request.args.get('a', 0))
        b = int(request.args.get('b', 0))
        result = a / b
        return str(result)
    except Exception as e:
        # Vulnerable: Exposing full error details
        return f"Error: {str(e)}, Type: {type(e)}"

# Vulnerability: Missing Rate Limiting
@app.route('/api/data', methods=['GET'])
def get_data():
    # Vulnerable: No rate limiting
    return {"data": "sensitive information"}

if __name__ == '__main__':
    # Vulnerability: Debug mode enabled, binding to all interfaces
    app.run(host='0.0.0.0', debug=True, port=5000)
