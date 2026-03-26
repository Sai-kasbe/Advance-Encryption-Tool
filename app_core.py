from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import os
import psycopg2
import secrets
import hashlib
import random
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "secret")

DATABASE_URL = os.environ.get("DATABASE_URL")
EMAIL_USER = os.environ.get("EMAIL_USER")
EMAIL_PASS = os.environ.get("EMAIL_PASS")

# ===============================
# DATABASE
# ===============================
def get_db():
    return psycopg2.connect(DATABASE_URL)

def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password_hash TEXT,
        salt TEXT,
        is_verified BOOLEAN DEFAULT FALSE
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS otp_codes (
        id SERIAL PRIMARY KEY,
        email TEXT,
        otp TEXT,
        expires_at TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()

init_db()

# ===============================
# PASSWORD
# ===============================
def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

# ===============================
# EMAIL SENDER
# ===============================
def send_email_otp(email, otp):
    msg = MIMEText(f"Your OTP is: {otp}")
    msg["Subject"] = "OTP Verification"
    msg["From"] = EMAIL_USER
    msg["To"] = email

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(EMAIL_USER, EMAIL_PASS)
    server.send_message(msg)
    server.quit()

# ===============================
# OTP GENERATE
# ===============================
def create_otp(email):
    otp = str(random.randint(100000, 999999))
    expires = datetime.now() + timedelta(minutes=5)

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO otp_codes (email, otp, expires_at)
        VALUES (%s, %s, %s)
    """, (email, otp, expires))

    conn.commit()
    conn.close()

    send_email_otp(email, otp)

    return otp

# ===============================
# VERIFY OTP
# ===============================
def verify_otp(email, otp):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT otp, expires_at FROM otp_codes
        WHERE email=%s ORDER BY id DESC LIMIT 1
    """, (email,))

    row = cur.fetchone()
    conn.close()

    if not row:
        return False

    db_otp, expiry = row

    if datetime.now() > expiry:
        return False

    return db_otp == otp

# ===============================
# ROUTES
# ===============================
@app.route("/")
def home():
    return redirect(url_for("login"))

# ===============================
# SIGNUP
# ===============================
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        otp = request.form.get("otp")

        if not verify_otp(email, otp):
            return "Invalid OTP"

        salt = secrets.token_hex(8)
        password_hash = hash_password(password, salt)

        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO users (username, email, password_hash, salt, is_verified)
            VALUES (%s, %s, %s, %s, TRUE)
        """, (username, email, password_hash, salt))

        conn.commit()
        conn.close()

        return redirect(url_for("login"))

    return render_template("signup.html")

# ===============================
# SEND OTP API
# ===============================
@app.route("/api/send_email_otp", methods=["POST"])
def send_email_otp_api():
    data = request.get_json()
    email = data.get("email")

    try:
        create_otp(email)
        return jsonify({"sent": True})
    except Exception as e:
        return jsonify({"sent": False, "error": str(e)})

# ===============================
# LOGIN
# ===============================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cur = conn.cursor()

        cur.execute("SELECT id, password_hash, salt FROM users WHERE username=%s", (username,))
        user = cur.fetchone()

        conn.close()

        if user:
            user_id, db_hash, salt = user
            if hash_password(password, salt) == db_hash:
                session["user_id"] = user_id
                session["username"] = username
                return redirect(url_for("dashboard"))

    return render_template("login.html")

# ===============================
# DASHBOARD
# ===============================
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["username"])

# ===============================
# LOGOUT
# ===============================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))
