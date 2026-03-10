import os
import sqlite3
import secrets
import smtplib
import hashlib
import hmac
import time
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_file, jsonify
)

from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes


# ==========================================================
# APPLICATION CONFIGURATION
# ==========================================================

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "encrypted_files")
DECRYPTED_FOLDER = os.path.join(BASE_DIR, "decrypted_files")
DB_NAME = os.path.join(BASE_DIR, "advanced_encryption.db")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)
os.makedirs("static/css", exist_ok=True)
os.makedirs("static/img", exist_ok=True)


# ==========================================================
# DATABASE
# ==========================================================

def get_db():
    return sqlite3.connect(DB_NAME)


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password_hash TEXT,
            salt BLOB,
            is_verified INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS otp_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            otp_code TEXT,
            created_at TIMESTAMP,
            expires_at TIMESTAMP,
            is_used INTEGER DEFAULT 0,
            attempts INTEGER DEFAULT 0,
            purpose TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS file_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            original_filename TEXT,
            stored_filename TEXT,
            operation TEXT,
            category TEXT,
            stored_path TEXT,
            file_size INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS shared_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            owner_id INTEGER,
            share_token TEXT UNIQUE,
            shared_with_email TEXT,
            is_public INTEGER DEFAULT 0,
            access_count INTEGER DEFAULT 0,
            expires_at TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


# ==========================================================
# PASSWORD SECURITY
# ==========================================================

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        200000
    ).hex()


def verify_password_hash(stored_hash, salt, password):
    new_hash = hash_password(password, salt)
    return hmac.compare_digest(stored_hash, new_hash)


# ==========================================================
# EMAIL SYSTEM
# ==========================================================

EMAIL_USER = os.environ.get("MAIL_USERNAME")
EMAIL_PASS = os.environ.get("MAIL_PASSWORD")


def send_email(to_email, subject, html):
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_USER
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(html, "html"))

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, to_email, msg.as_string())
        server.quit()

        return True

    except Exception as e:
        print("EMAIL ERROR:", e)
        return False


# ==========================================================
# ENCRYPTION SYSTEM
# ==========================================================

SALT_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 16
CHUNK_SIZE = 64 * 1024
PBKDF2_ITERATIONS = 200000


def encrypt_file(input_path, output_path, password):

    salt = get_random_bytes(SALT_SIZE)
    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)
    iv = get_random_bytes(IV_SIZE)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:

        outfile.write(salt)
        outfile.write(iv)

        while True:

            chunk = infile.read(CHUNK_SIZE)

            if len(chunk) == 0:
                break

            if len(chunk) % 16 != 0:
                chunk += b' ' * (16 - len(chunk) % 16)

            outfile.write(cipher.encrypt(chunk))


def decrypt_file(input_path, output_path, password):

    with open(input_path, "rb") as infile:

        salt = infile.read(SALT_SIZE)
        iv = infile.read(IV_SIZE)

        key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        with open(output_path, "wb") as outfile:

            while True:

                chunk = infile.read(CHUNK_SIZE)

                if len(chunk) == 0:
                    break

                data = cipher.decrypt(chunk)

                if len(chunk) < CHUNK_SIZE:
                    data = data.rstrip(b' ')

                outfile.write(data)


# ==========================================================
# BASIC ROUTES
# ==========================================================

@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db()
        c = conn.cursor()

        c.execute(
            "SELECT id, password_hash, salt FROM users WHERE username=?",
            (username,)
        )

        user = c.fetchone()
        conn.close()

        if not user:
            flash("Invalid username")
            return render_template("login.html")

        user_id, stored_hash, salt = user

        if verify_password_hash(stored_hash, salt, password):

            session["user_id"] = user_id
            session["verified"] = True

            return redirect(url_for("dashboard"))

        flash("Invalid password")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template("dashboard.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ==========================================================
# START SERVER
# ==========================================================

init_db()

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
