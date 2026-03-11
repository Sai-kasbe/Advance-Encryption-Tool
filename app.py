import os
import sqlite3
import secrets
import time
import re
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import requests

app = Flask(__name__)

# -----------------------------
# CONFIGURATION
# -----------------------------
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("SECRET_KEY environment variable is required for security.")

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Set to True if using HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "advanced_encryption.db")


# -----------------------------
# DATABASE
# -----------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        created_at TEXT
    )
    """)

    conn.commit()
    conn.close()


# -----------------------------
# EMAIL (RESEND API)
# -----------------------------

def send_email(to_email, subject, html):
    api_key = os.environ.get("RESEND_API_KEY")

    if not api_key:
        print("WARNING: RESEND_API_KEY not set. Email not sent.")
        return False

    url = "https://api.resend.com/emails"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    data = {
        "from": "Encryption Tool <onboarding@resend.dev>",
        "to": [to_email],
        "subject": subject,
        "html": html
    }

    try:
        r = requests.post(url, headers=headers, json=data)

        if r.status_code in [200, 201]:
            print("EMAIL SENT")
            return True

        print("EMAIL ERROR:", r.text)
        return False

    except Exception as e:
        print("EMAIL ERROR:", e)
        return False


# -----------------------------
# DECORATORS
# -----------------------------

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


# -----------------------------
# HOME
# -----------------------------

@app.route("/")
def home():
    return redirect(url_for("login"))


# -----------------------------
# LOGIN
# -----------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            flash("Username and password are required")
            return render_template("login.html")

        conn = get_db()
        c = conn.cursor()

        c.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        )

        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))

        flash("Invalid username or password")

    return render_template("login.html")


# -----------------------------
# SIGNUP
# -----------------------------

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        if not session.get("email_verified"):
            flash("Please verify email OTP first")
            return render_template("signup.html")

        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        # Basic Validation
        if not username or not email or not password:
            flash("All fields are required")
            return render_template("signup.html")
        
        if len(password) < 8:
            flash("Password must be at least 8 characters")
            return render_template("signup.html")

        conn = get_db()
        c = conn.cursor()

        try:
            # Hash password before storing
            hashed_password = generate_password_hash(password)
            
            c.execute(
                "INSERT INTO users(username, email, password, created_at) VALUES(?, ?, ?, ?)",
                (username, email, hashed_password, str(datetime.now()))
            )

            conn.commit()

        except sqlite3.IntegrityError:
            flash("User already exists")
            conn.close()
            return render_template("signup.html")

        conn.close()

        # Clear OTP session data
        session.pop("email_verified", None)
        session.pop("signup_email", None)
        session.pop("signup_otp", None)
        session.pop("signup_otp_time", None)

        flash("Account created successfully")
        return redirect(url_for("login"))

    return render_template("signup.html")


# -----------------------------
# DASHBOARD
# -----------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session["username"])


# -----------------------------
# ENCRYPT
# -----------------------------

@app.route("/encrypt-images")
@login_required
def encrypt_images():
    return render_template("encrypt_images.html")

@app.route("/encrypt-documents")
@login_required
def encrypt_documents():
    return render_template("encrypt_documents.html")

@app.route("/encrypt-media")
@login_required
def encrypt_media():
    return render_template("encrypt_media.html")


# -----------------------------
# DECRYPT
# -----------------------------

@app.route("/decrypt-images")
@login_required
def decrypt_images():
    return render_template("decrypt_images.html")

@app.route("/decrypt-documents")
@login_required
def decrypt_documents():
    return render_template("decrypt_documents.html")

@app.route("/decrypt-media")
@login_required
def decrypt_media():
    return render_template("decrypt_media.html")


# -----------------------------
# DOWNLOAD
# -----------------------------

@app.route("/download-decrypted")
@login_required
def download_decrypted():
    return render_template("download_decrypted.html")

@app.route("/download-success")
@login_required
def download_success():
    return render_template("download_success.html")


# -----------------------------
# SHARE
# -----------------------------

@app.route("/share-file")
@login_required
def share_file():
    return render_template("share_file.html")

@app.route("/share-success")
@login_required
def share_success():
    return render_template("share_success.html")

@app.route("/my-shares")
@login_required
def my_shares():
    return render_template("my_shares.html")

@app.route("/view-shared-file")
@login_required
def view_shared_file():
    return render_template("view_shared_file.html")


# -----------------------------
# OTP
# -----------------------------

@app.route("/api/send_email_otp", methods=["POST"])
def send_email_otp():
    data = request.get_json()
    email = data.get("email")

    if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"sent": False, "error": "Invalid email"})

    otp = str(secrets.randbelow(999999)).zfill(6)

    session["signup_email"] = email
    session["signup_otp"] = otp
    session["signup_otp_time"] = time.time()

    html = f"<h2>Your OTP</h2><h1>{otp}</h1>"

    email_sent = send_email(email, "Your OTP Code", html)

    if not email_sent:
        return jsonify({"sent": False})

    return jsonify({"sent": True})


@app.route("/api/verify_email_otp", methods=["POST"])
def verify_email_otp():
    data = request.get_json()
    otp = data.get("otp")

    stored_otp = session.get("signup_otp")
    otp_time = session.get("signup_otp_time", 0)

    valid = (
        otp == stored_otp
        and time.time() - otp_time < 120
    )

    if valid:
        session["email_verified"] = True
        # Clear OTP after successful verification
        session.pop("signup_otp", None)
        session.pop("signup_otp_time", None)
    else:
        flash("Invalid or expired OTP")

    return jsonify({"valid": valid})


# -----------------------------
# LOGOUT
# -----------------------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# -----------------------------
# SERVER
# -----------------------------

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
