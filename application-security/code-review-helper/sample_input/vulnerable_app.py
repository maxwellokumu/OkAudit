"""
Vulnerable Demo Application — FOR TESTING ONLY.
This file intentionally contains security vulnerabilities for code-review-helper sample_input.
DO NOT deploy or use this code in any real application.
"""

import hashlib
import os
import pickle
import sqlite3
import yaml
from flask import Flask, redirect, request

app = Flask(__name__)

# Vulnerability 1: Hardcoded secrets (CWE-798)
password = "sup3rs3cret123"
api_key = "sk-1234567890abcdef1234567890abcdef"
secret = "my-jwt-secret-key"

# Vulnerability 2: Debug mode enabled (CWE-489)
DEBUG = True


def get_user(username: str):
    """Fetch user from database — SQL injection vulnerability."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Vulnerability 3: SQL injection via string formatting (CWE-89)
    query = "SELECT * FROM users WHERE username = '%s'" % username
    cursor.execute(query)
    return cursor.fetchone()


def hash_password(pwd: str) -> str:
    """Hash a password — uses weak algorithm."""
    # Vulnerability 4: Weak cryptography (CWE-327)
    return hashlib.md5(pwd.encode()).hexdigest()


def compute_signature(data: str) -> str:
    """Compute a digital signature — also weak."""
    return hashlib.sha1(data.encode()).hexdigest()


def run_command(cmd: str):
    """Execute dynamic code — dangerous."""
    # Vulnerability 2: eval/exec usage (CWE-95)
    result = eval(cmd)
    return result


def load_user_data(serialised: bytes):
    """Deserialise user session — insecure."""
    # Vulnerability 6: Insecure deserialization (CWE-502)
    return pickle.loads(serialised)


def load_config(config_str: str):
    """Load YAML config — unsafe loader."""
    # Vulnerability 6: yaml.load without Loader (CWE-502)
    return yaml.load(config_str)


@app.route("/file")
def serve_file():
    """Serve a user-requested file — path traversal vulnerability."""
    filename = request.args.get("name", "")
    # Vulnerability 7: Path traversal via user-controlled input (CWE-22)
    file_path = os.path.join("/var/www/static", filename)
    with open(file_path) as f:
        return f.read()


@app.route("/login", methods=["POST"])
def login():
    """Process login and redirect — open redirect vulnerability."""
    next_url = request.args.get("next", "/dashboard")
    username = request.form.get("username")
    # ... authentication logic ...
    # Vulnerability 8: Open redirect (CWE-601)
    return redirect(request.args.get("next"))


@app.route("/search")
def search():
    """Search endpoint with SQL injection."""
    term = request.args.get("q", "")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # Another SQL injection example using f-string
    cur.execute(f"SELECT * FROM products WHERE name LIKE '%{term}%'")
    return str(cur.fetchall())


if __name__ == "__main__":
    # Vulnerability 5: Debug mode in app.run (CWE-489)
    app.run(host="0.0.0.0", port=5000, debug=True)
