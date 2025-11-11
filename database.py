"""
Database utilities with intentional SQL injection vulnerabilities
"""

import sqlite3
import hashlib

class UserDatabase:
    def __init__(self, db_name='users.db'):
        self.db_name = db_name
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                role TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    # Vulnerability: SQL Injection
    def get_user_by_username(self, username):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        # Vulnerable query
        query = "SELECT * FROM users WHERE username = '" + username + "'"
        cursor.execute(query)
        result = cursor.fetchone()
        conn.close()
        return result
    
    # Vulnerability: SQL Injection in UPDATE
    def update_user_email(self, username, email):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        # Vulnerable update query
        query = f"UPDATE users SET email = '{email}' WHERE username = '{username}'"
        cursor.execute(query)
        conn.commit()
        conn.close()
    
    # Vulnerability: SQL Injection in DELETE
    def delete_user(self, user_id):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        query = "DELETE FROM users WHERE id = " + str(user_id)
        cursor.execute(query)
        conn.commit()
        conn.close()
    
    # Vulnerability: Weak password hashing
    def create_user(self, username, password, email, role='user'):
        # Using MD5 for password hashing
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Still vulnerable to SQL injection
        query = f"INSERT INTO users (username, password, email, role) VALUES ('{username}', '{password_hash}', '{email}', '{role}')"
        cursor.execute(query)
        conn.commit()
        conn.close()
    
    # Vulnerability: Information disclosure
    def get_all_users(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        results = cursor.fetchall()
        conn.close()
        return results
    
    # Vulnerability: SQL Injection in search
    def search_users(self, search_term):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        # Vulnerable LIKE query
        query = f"SELECT * FROM users WHERE username LIKE '%{search_term}%' OR email LIKE '%{search_term}%'"
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        return results

class ProductDatabase:
    def __init__(self, db_name='products.db'):
        self.db_name = db_name
    
    # Vulnerability: SQL Injection with ORDER BY
    def get_products_sorted(self, sort_by):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        # Vulnerable: sort_by comes from user input
        query = f"SELECT * FROM products ORDER BY {sort_by}"
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        return results
    
    # Vulnerability: SQL Injection with LIMIT
    def get_products_paginated(self, limit, offset):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        query = f"SELECT * FROM products LIMIT {limit} OFFSET {offset}"
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        return results
    
    # Vulnerability: Blind SQL Injection
    def check_product_exists(self, product_name):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        query = f"SELECT COUNT(*) FROM products WHERE name = '{product_name}'"
        cursor.execute(query)
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0
