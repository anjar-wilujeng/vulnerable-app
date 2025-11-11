"""
File operations module with intentional security vulnerabilities
"""

import os
import pickle
import json
import xml.etree.ElementTree as ET
import subprocess
import yaml

class FileManager:
    def __init__(self, base_path='/tmp/uploads'):
        self.base_path = base_path
        os.makedirs(base_path, exist_ok=True)
    
    # Vulnerability: Path Traversal
    def read_file(self, filename):
        # No path validation - allows ../../../etc/passwd
        filepath = os.path.join(self.base_path, filename)
        try:
            with open(filepath, 'r') as f:
                return f.read()
        except Exception as e:
            return str(e)
    
    # Vulnerability: Path Traversal in write
    def write_file(self, filename, content):
        # Vulnerable to path traversal
        filepath = os.path.join(self.base_path, filename)
        with open(filepath, 'w') as f:
            f.write(content)
        return filepath
    
    # Vulnerability: Arbitrary file deletion
    def delete_file(self, filename):
        # No validation of file path
        filepath = os.path.join(self.base_path, filename)
        os.remove(filepath)
        return True
    
    # Vulnerability: Directory listing exposure
    def list_files(self, directory='.'):
        # Allows listing any directory
        target_dir = os.path.join(self.base_path, directory)
        return os.listdir(target_dir)
    
    # Vulnerability: Unrestricted file upload
    def upload_file(self, file_content, filename):
        # No file type validation
        # No size limit
        # Allows executable files
        filepath = os.path.join(self.base_path, filename)
        with open(filepath, 'wb') as f:
            f.write(file_content)
        return filepath
    
    # Vulnerability: Race condition in file operations
    def atomic_update(self, filename, new_content):
        filepath = os.path.join(self.base_path, filename)
        
        # Vulnerable: Read and write not atomic
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                old_content = f.read()
        
        # Race condition window here
        with open(filepath, 'w') as f:
            f.write(new_content)
        
        return old_content if 'old_content' in locals() else None

class SerializationManager:
    # Vulnerability: Insecure deserialization with pickle
    def save_object(self, obj, filename):
        with open(filename, 'wb') as f:
            pickle.dump(obj, f)
    
    def load_object(self, filename):
        # Vulnerable: Unpickling untrusted data
        with open(filename, 'rb') as f:
            return pickle.load(f)
    
    # Vulnerability: YAML deserialization
    def load_yaml_config(self, yaml_string):
        # Vulnerable: yaml.load allows arbitrary code execution
        return yaml.load(yaml_string, Loader=yaml.Loader)
    
    # Vulnerability: eval() usage
    def evaluate_expression(self, expression):
        # Extremely dangerous: eval on user input
        return eval(expression)
    
    # Vulnerability: exec() usage
    def execute_code(self, code):
        # Allows arbitrary code execution
        exec(code)

class XMLProcessor:
    # Vulnerability: XML External Entity (XXE)
    def parse_xml(self, xml_string):
        # Vulnerable: External entities not disabled
        root = ET.fromstring(xml_string)
        return self.xml_to_dict(root)
    
    def xml_to_dict(self, element):
        result = {}
        for child in element:
            result[child.tag] = child.text
        return result
    
    # Vulnerability: XML bomb (Billion Laughs)
    def parse_xml_file(self, filename):
        # No entity expansion limits
        tree = ET.parse(filename)
        return tree.getroot()

class CommandExecutor:
    # Vulnerability: Command Injection
    def execute_system_command(self, command):
        # Direct execution of user input
        result = os.system(command)
        return result
    
    def run_command(self, command):
        # Vulnerable: shell=True with user input
        result = subprocess.run(command, shell=True, capture_output=True)
        return result.stdout.decode()
    
    # Vulnerability: Command injection via format string
    def ping_host(self, hostname):
        # Vulnerable to command injection
        cmd = f"ping -c 1 {hostname}"
        return os.popen(cmd).read()
    
    def check_port(self, host, port):
        # Vulnerable command injection
        cmd = f"nc -zv {host} {port}"
        return subprocess.check_output(cmd, shell=True)
    
    # Vulnerability: Subprocess with user input
    def convert_file(self, input_file, output_file):
        # Vulnerable to command injection
        cmd = f"convert {input_file} {output_file}"
        subprocess.call(cmd, shell=True)

class ConfigManager:
    # Vulnerability: Hardcoded credentials in config
    DEFAULT_CONFIG = {
        'database': {
            'host': 'localhost',
            'username': 'admin',
            'password': 'P@ssw0rd123',  # Hardcoded password
            'database': 'myapp'
        },
        'api_keys': {
            'stripe': 'sk_live_51abcdef123456789',
            'aws_access_key': 'AKIAIOSFODNN7EXAMPLE',
            'aws_secret_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        },
        'smtp': {
            'server': 'smtp.gmail.com',
            'username': 'myapp@gmail.com',
            'password': 'smtp_password_123'
        }
    }
    
    def load_config(self, config_file):
        # Vulnerable: Loading config with eval
        with open(config_file, 'r') as f:
            config_string = f.read()
        return eval(config_string)  # Dangerous!
    
    def get_config(self):
        return self.DEFAULT_CONFIG

class LogManager:
    def __init__(self, log_file='app.log'):
        self.log_file = log_file
    
    # Vulnerability: Log injection
    def log_message(self, message):
        # No sanitization of user input in logs
        with open(self.log_file, 'a') as f:
            f.write(f"{message}\n")
    
    # Vulnerability: Sensitive data in logs
    def log_user_activity(self, username, password, action):
        log_entry = f"User {username} with password {password} performed {action}"
        self.log_message(log_entry)
    
    # Vulnerability: Log injection with format string
    def log_error(self, error_message, user_input):
        # Vulnerable to log injection
        log_entry = f"ERROR: {error_message} - User input: {user_input}"
        self.log_message(log_entry)

class TempFileManager:
    # Vulnerability: Insecure temporary file creation
    def create_temp_file(self, content):
        import random
        # Vulnerable: Predictable temp file names
        filename = f"/tmp/tempfile_{random.randint(1000, 9999)}.txt"
        with open(filename, 'w') as f:
            f.write(content)
        return filename
    
    # Vulnerability: Race condition in temp file
    def create_temp_file_v2(self):
        import time
        filename = f"/tmp/app_{int(time.time())}.tmp"
        
        # Check if exists (race condition window)
        if not os.path.exists(filename):
            # Another process could create file here
            with open(filename, 'w') as f:
                f.write("temp data")
        
        return filename
    
    # Vulnerability: Temp file not deleted
    def process_temp_file(self, data):
        temp_file = self.create_temp_file(data)
        # Process the file
        with open(temp_file, 'r') as f:
            content = f.read()
        # Vulnerable: Temp file not deleted after use
        return content

# Vulnerability: Insecure file permissions
def create_sensitive_file(filename, content):
    with open(filename, 'w') as f:
        f.write(content)
    # Vulnerable: File created with default permissions (usually 644)
    # Should use os.chmod() to restrict permissions

# Vulnerability: Symbolic link following
def read_user_file(username, filename):
    user_dir = f"/home/{username}"
    file_path = os.path.join(user_dir, filename)
    # Vulnerable: Doesn't check for symlinks
    with open(file_path, 'r') as f:
        return f.read()
