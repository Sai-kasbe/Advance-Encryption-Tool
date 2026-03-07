import os
import sqlite3
import secrets
import smtplib
import hashlib
import hmac
import time
import requests
import json
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_file, jsonify
)

from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# ============================================
# CONFIGURATION
# ============================================

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Session hardening
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8)
)

if os.environ.get("FLASK_ENV") == "production":
    app.config["SESSION_COOKIE_SECURE"] = True

# Folders
UPLOAD_FOLDER = "encrypted_files"
DECRYPTED_FOLDER = "decrypted_files"
DB_NAME = "advanced_encryption.db"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)
os.makedirs("templates", exist_ok=True)
os.makedirs("static/css", exist_ok=True)
os.makedirs("static/img", exist_ok=True)

# AES constants
CHUNK_SIZE = 64 * 1024
SALT_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 16
PBKDF2_ITERATIONS = 200_000

# Email configuration
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False

app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_USERNAME")

EMAIL_USER = app.config["MAIL_USERNAME"]
EMAIL_PASS = app.config["MAIL_PASSWORD"]


# Security controls
MAX_LOGIN_ATTEMPTS = 5
OTP_TTL_MIN = 10
MAX_UPLOAD_MB = 500
# FILE CATEGORIES - NEW!
CATEGORY_EXTENSIONS = {
    'images': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg', '.ico'],
    'documents': ['.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx', '.csv', '.txt', '.odt'],
    'media': ['.mp4', '.mp3', '.avi', '.mov', '.wav', '.mkv', '.flac', '.m4a', '.wmv', '.webm']
}

# Helper function to detect file category
def get_file_category(filename: str) -> str:
    """Detect file category based on extension"""
    ext = os.path.splitext(filename.lower())[1]
    for category, extensions in CATEGORY_EXTENSIONS.items():
        if ext in extensions:
            return category
    return 'general'


# ============================================
# DATABASE UTILITIES
# ============================================

def db():
    return sqlite3.connect(DB_NAME)



def add_column_if_not_exists(cursor, table_name, column_def):
    try:
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_def}")
    except Exception:
        # Column already exists (or SQLite limitation)
        pass


def get_db():
    return sqlite3.connect(DB_NAME)


def add_column_if_not_exists(cursor, table_name, column_def):
    try:
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_def}")
    except Exception:
        pass  # already exists


def init_db():
    conn = get_db()
    c = conn.cursor()

    # ✅ USERS
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt BLOB NOT NULL,
            is_verified INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ✅ OTP
    c.execute("""
        CREATE TABLE IF NOT EXISTS otp_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            otp_code TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            is_used INTEGER DEFAULT 0,
            attempts INTEGER DEFAULT 0,
            purpose TEXT DEFAULT 'login',
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # ✅ FILE HISTORY
    c.execute("""
        CREATE TABLE IF NOT EXISTS file_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            original_filename TEXT,
            stored_filename TEXT,
            operation TEXT,
            category TEXT DEFAULT 'general',
            password_hint TEXT,
            shareable INTEGER DEFAULT 0,
            stored_path TEXT,
            file_size INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # ✅ Add integrity fields (fix dashboard crash)
    add_column_if_not_exists(c, "file_history", "integrity_hash TEXT")
    add_column_if_not_exists(c, "file_history", "integrity_status TEXT DEFAULT 'ok'")

    # ✅ SHARED FILES
    c.execute("""
        CREATE TABLE IF NOT EXISTS shared_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            owner_id INTEGER NOT NULL,
            shared_with_email TEXT,
            share_token TEXT UNIQUE NOT NULL,
            is_public INTEGER DEFAULT 0,
            access_count INTEGER DEFAULT 0,
            expires_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (file_id) REFERENCES file_history(id),
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    """)

    # ✅ Add advanced sharing fields
    add_column_if_not_exists(c, "shared_files", "revoked INTEGER DEFAULT 0")
    add_column_if_not_exists(c, "shared_files", "one_time INTEGER DEFAULT 0")
    add_column_if_not_exists(c, "shared_files", "max_downloads INTEGER DEFAULT 0")
    add_column_if_not_exists(c, "shared_files", "download_count INTEGER DEFAULT 0")
    add_column_if_not_exists(c, "shared_files", "pin_hash TEXT")

    # ✅ INDEXES
    c.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_otp_user ON otp_codes(user_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_hist_user ON file_history(user_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_share_token ON shared_files(share_token)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_owner_id ON shared_files(owner_id)")

    conn.commit()
    conn.close()
    conn = get_db()
    c = conn.cursor()
    c.execute("PRAGMA table_info(file_history)")
    print([x[1] for x in c.fetchall()])
    conn.close()

    from app import db

    conn = db()
    c = conn.cursor()
    conn.commit()
    conn.close()



# ============================================
# SECURITY UTILITIES
# ============================================

def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000).hex()

def verify_password_hash(stored_hash: str, salt: bytes, password: str) -> bool:
    return hmac.compare_digest(stored_hash, hash_password(password, salt))

# ============================================
# EMAIL & OTP UTILITIES
# ============================================


def send_email(to_email, subject, html_body):
    if not EMAIL_USER or not EMAIL_PASS:
        print("[ERROR] EMAIL_USER or EMAIL_PASS not configured.")
        return False

    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_USER
        msg["To"] = to_email
        msg["Subject"] = subject

        msg.attach(MIMEText(html_body, "html"))

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, to_email, msg.as_string())
        server.quit()

        return True

    except Exception as e:
        print(f"❌ Email send failed: {e}")
        return False


def send_otp(email: str, otp: str, purpose: str = "login") -> bool:
    subject = "Your OTP Code - Advanced Encryption Tool"
    body = f"""
        <h3>Your OTP Code</h3>
        <p>Your OTP code for <strong>{purpose}</strong>:</p>
        <h1 style="color: #17a2b8; font-size: 32px; letter-spacing: 5px;">{otp}</h1>
        <p>This code will expire in {OTP_TTL_MIN} minutes.</p>
    """
    return send_email(email, subject, body)

def create_otp(user_id: int, purpose: str = "login") -> str:
    otp = str(secrets.randbelow(1_000_000)).zfill(6)
    expires_at = datetime.now() + timedelta(minutes=OTP_TTL_MIN)

    conn = db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO otp_codes (user_id, otp_code, expires_at, purpose) VALUES (?, ?, ?, ?)",
        (user_id, otp, expires_at, purpose)
    )
    conn.commit()
    conn.close()

    return otp


def validate_otp(user_id, otp, purpose="login"):
    conn = db()
    c = conn.cursor()

    c.execute("""
        SELECT otp_code, expires_at, is_used, attempts
        FROM otp_codes
        WHERE user_id = ? AND purpose = ?
        ORDER BY created_at DESC
        LIMIT 1
    """, (user_id, purpose))

    row = c.fetchone()
    conn.close()

    if not row:
        return False

    otp_code, expires_at, is_used, attempts = row

    # ✅ Convert expires_at safely (SQLite returns string)
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)

    # ✅ Expiry check
    if datetime.now() > expires_at:
        return False

    # ✅ OTP already used
    if is_used == 1:
        return False

    # ✅ attempt limit
    if attempts >= 5:
        return False

    return str(otp_code) == str(otp)


    c.execute("UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?", (otp_id,))
    conn.commit()

    if hmac.compare_digest(stored_otp, otp):
        c.execute("UPDATE otp_codes SET is_used = 1 WHERE id = ?", (otp_id,))
        conn.commit()
        conn.close()
        return True

    conn.close()
    return False


def generate_otp():
    """Generate 6-digit OTP for email verification"""
    return str(secrets.randbelow(900000) + 100000)

def send_otp_email(email: str, otp: str, purpose: str = "verification") -> bool:
    """Send OTP via email"""
    subject = f"Your OTP Code - Advanced Encryption Tool"
    body = f"""
        <h3>Email Verification OTP</h3>
        <p>Your OTP code for <strong>{purpose}</strong>:</p>
        <h1 style="color: #00f5ff; font-size: 32px; letter-spacing: 5px;">{otp}</h1>
        <p>This code will expire in 2 minutes.</p>
        <p style="color: #dc3545; font-weight: bold;">⚠️ Do not share this code with anyone!</p>
    """
    return send_email(email, subject, body)

# ============================================
# ENCRYPTION/DECRYPTION UTILITIES
# ============================================

def encrypt_file(input_path: str, output_path: str, password: str) -> None:
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
            elif len(chunk) % 16 != 0:
                chunk += b' ' * (16 - len(chunk) % 16)
            outfile.write(cipher.encrypt(chunk))

def decrypt_file(input_path: str, output_path: str, password: str) -> None:
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

                decrypted_chunk = cipher.decrypt(chunk)

                if len(chunk) < CHUNK_SIZE:
                    decrypted_chunk = decrypted_chunk.rstrip(b' ')

                outfile.write(decrypted_chunk)

def log_file_operation(user_id: int, original_filename: str, stored_filename: str, operation: str,
                       category: str = 'general', hint: str = "", shareable: bool = False,
                       stored_path: str = "", file_size: int = 0,
                       integrity_hash: str = None, integrity_status: str = None) -> None:
    conn = db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO file_history (
            user_id, original_filename, stored_filename, operation, category,
            password_hint, shareable, stored_path, file_size,
            integrity_hash, integrity_status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id, original_filename, stored_filename, operation, category,
        hint, 1 if shareable else 0, stored_path, file_size,
        integrity_hash, integrity_status
    ))
    conn.commit()
    conn.close()



# ============================================
# ROUTES - AUTHENTICATION
# ============================================

@app.route("/")
def index():
    if "user_id" in session and session.get("verified"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        # CHECK EMAIL OTP VERIFICATION ONLY
        if not session.get("email_otp_verified"):
            flash("Email OTP must be verified before signup!", "error")
            return render_template("signup.html")

        # Get form data (NO MOBILE)
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Basic validation
        if not username or not email or not password:
            flash("All fields are required.", "error")
            return render_template("signup.html")

        # Username validation (letters only)
        if not username.isalpha():
            flash("Username must contain only letters.", "error")
            return render_template("signup.html")

        # Password match validation
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("signup.html")

        # Check if user already exists
        conn = db()
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username = ? OR email = ?",
                  (username, email))

        if c.fetchone():
            flash("Username or email already exists.", "error")
            conn.close()
            return render_template("signup.html")

        # Hash password
        salt = secrets.token_bytes(32)
        pwd_hash = hash_password(password, salt)

        # Create user account (NO MOBILE FIELD)
        try:
            c.execute("""
                INSERT INTO users (username, email, password_hash, salt)
                VALUES (?, ?, ?, ?)
            """, (username, email, pwd_hash, salt))
            conn.commit()
            conn.close()

            # Clear session OTP data
            session.pop("email_otp", None)
            session.pop("email_otp_time", None)
            session.pop("email_otp_verified", None)

            flash("Account created successfully! Please login.", "success")
            return redirect(url_for("login"))

        except Exception as err:
            conn.close()
            flash(f"Error creating account: {err}", "error")
            return render_template("signup.html")

    return render_template("signup.html")



# OTP API Endpoints for Signup
@app.route("/api/send_email_otp", methods=["POST"])
def send_email_otp_api():
    data = request.get_json()
    email = data.get("email", "")
    otp = generate_otp()
    session["email_otp"] = otp
    session["email_otp_time"] = time.time()
    send_otp_email(email, otp)
    return jsonify(sent=True)

@app.route("/api/verify_email_otp", methods=["POST"])
def verify_email_otp_api():
    data = request.get_json()
    otp = data.get("otp", "")
    valid = ('email_otp' in session and
             session.get('email_otp') == otp and
             time.time() - session.get('email_otp_time', 0) < 120)
    if valid:
        session["email_otp_verified"] = True
    return jsonify(valid=valid)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("login.html")

        conn = db()
        c = conn.cursor()
        c.execute("SELECT id, email, password_hash, salt FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()

        if not row:
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        user_id, email, stored_hash, salt = row

        if not verify_password_hash(stored_hash, salt, password):
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        # Send OTP
        otp = create_otp(user_id, "login")
        send_otp(email, otp, "login")

        session["pending_user_id"] = user_id
        session["pending_email"] = email
        session["pending_username"] = username

        flash("OTP sent to your registered email.", "info")
        return redirect(url_for("verify_otp_page"))

    return render_template("login.html")

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp_page():
    if "pending_user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        user_id = session["pending_user_id"]

        if validate_otp(user_id, otp, "login"):
            username = session.get("pending_username", "User")

            # Mark user as verified
            conn = db()
            c = conn.cursor()
            c.execute("UPDATE users SET is_verified = 1 WHERE id = ?", (user_id,))
            conn.commit()
            conn.close()

            # Clear pending session data
            session.pop("pending_user_id", None)
            session.pop("pending_email", None)
            session.pop("pending_username", None)

            # Set active session
            session["user_id"] = user_id
            session["username"] = username
            session["verified"] = True
            session.permanent = True

            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid or expired OTP. Please try again.", "error")

    return render_template("verify_otp_page.html")

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        if not email:
            flash("Email is required.", "error")
            return render_template("forgot_password.html")

        conn = db()
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email = ?", (email,))
        row = c.fetchone()
        conn.close()

        if not row:
            flash("Email not found.", "error")
            return render_template("forgot_password.html")

        user_id = row[0]
        otp = create_otp(user_id, "forgot_password")
        send_otp(email, otp, "password reset")

        session["reset_user_id"] = user_id
        session["reset_email"] = email

        flash("OTP sent to your email.", "info")
        return redirect(url_for("verify_forgot_password_otp"))

    return render_template("forgot_password.html")

@app.route("/verify-forgot-password-otp", methods=["GET", "POST"])
def verify_forgot_password_otp():
    if "reset_user_id" not in session:
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        user_id = session["reset_user_id"]

        if validate_otp(user_id, otp, "forgot_password"):
            flash("OTP verified. Please set a new password.", "success")
            return redirect(url_for("reset_password"))
        else:
            flash("Invalid or expired OTP.", "error")

    return render_template("verify_forgot_password_otp.html")

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if "reset_user_id" not in session:
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not new_password or not confirm_password:
            flash("Both password fields are required.", "error")
            return render_template("reset_password.html")

        if new_password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("reset_password.html")

        user_id = session["reset_user_id"]

        # Update password
        salt = secrets.token_bytes(32)
        pwd_hash = hash_password(new_password, salt)

        conn = db()
        c = conn.cursor()
        c.execute("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
                 (pwd_hash, salt, user_id))
        conn.commit()
        conn.close()

        # Clear reset session
        session.pop("reset_user_id", None)
        session.pop("reset_email", None)

        flash("Password reset successfully! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")

@app.route("/forgot-username", methods=["GET", "POST"])
def forgot_username():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        if not email:
            flash("Email is required.", "error")
            return render_template("forgot_username.html")

        conn = db()
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE email = ?", (email,))
        row = c.fetchone()
        conn.close()

        if not row:
            flash("Email not found.", "error")
            return render_template("forgot_username.html")

        username = row[0]

        # Send username via email
        subject = "Your Username - Advanced Encryption Tool"
        body = f"""
            <h3>Username Recovery</h3>
            <p>Your username is:</p>
            <h2 style="color: #17a2b8; letter-spacing: 2px;">{username}</h2>
            <p>You can now use this username to login.</p>
        """

        if send_email(email, subject, body):
            flash("Username sent to your email!", "success")
            return redirect(url_for("login"))
        else:
            flash("Failed to send email. Please try again.", "error")

    return render_template("forgot_username.html")

# ============================================
# ROUTES - DASHBOARD & FILE OPERATIONS
# ============================================

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session or not session.get("verified"):
        return redirect(url_for("login"))

    user_id = session["user_id"]
    username = session.get("username", "User")

    conn = db()
    c = conn.cursor()

    # Get statistics
    c.execute("SELECT COUNT(*) FROM file_history WHERE user_id = ? AND operation = 'encrypt'", (user_id,))
    encrypt_count = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM file_history WHERE user_id = ? AND operation = 'decrypt'", (user_id,))
    decrypt_count = c.fetchone()[0]

    c.execute("SELECT SUM(file_size) FROM file_history WHERE user_id = ?", (user_id,))
    total_bytes = c.fetchone()[0] or 0
    total_size = f"{total_bytes / (1024 * 1024):.2f} MB" if total_bytes > 0 else "0 MB"

    # Get recent history with category
    c.execute("""
        SELECT id, original_filename, operation, category, timestamp,
               stored_path, integrity_status
        FROM file_history
        WHERE user_id = ?
        ORDER BY timestamp DESC
        LIMIT 20
    """, (user_id,))

    history = []
    for row in c.fetchall():
        history.append({
            'id': row[0],
            'filename': row[1],
            'operation': row[2],
            'category': row[3] or 'general',
            'timestamp': row[4],
            'stored_path': row[5],
            'integrity_status': row[6]
        })

    conn.close()

    return render_template("dashboard.html", username=username, encrypt_count=encrypt_count,
                           decrypt_count=decrypt_count, total_size=total_size, history=history)


# ============================================
# ENCRYPTION ROUTES BY CATEGORY
# ============================================

@app.route("/encrypt-images", methods=["GET", "POST"])
def encrypt_images():
    if "user_id" not in session or not session.get("verified"):
        return redirect(url_for("login"))

    if request.method == "POST":
        return handle_encrypt("images")

    return render_template("encrypt_images.html")


@app.route("/encrypt-documents", methods=["GET", "POST"])
def encrypt_documents():
    if "user_id" not in session or not session.get("verified"):
        return redirect(url_for("login"))

    if request.method == "POST":
        return handle_encrypt("documents")

    return render_template("encrypt_documents.html")


@app.route("/encrypt-media", methods=["GET", "POST"])
def encrypt_media():
    if "user_id" not in session or not session.get("verified"):
        return redirect(url_for("login"))

    if request.method == "POST":
        return handle_encrypt("media")

    return render_template("encrypt_media.html")

def handle_encrypt(category: str):
    """Handle encryption for any category"""
    if "file" not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for(f"encrypt_{category}"))

    file = request.files["file"]
    password = request.form.get("password", "")
    hint = request.form.get("hint", "")
    shareable = request.form.get("shareable") == "on"

    if file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for(f"encrypt_{category}"))

    if not password:
        flash("Password is required for encryption.", "error")
        return redirect(url_for(f"encrypt_{category}"))

    original_filename = secure_filename(file.filename)
    detected_category = get_file_category(original_filename)

    # Validate file type matches category
    if detected_category != category:
        flash(f"Invalid file type for {category}. Please select the correct file type.", "error")
        return redirect(url_for(f"encrypt_{category}"))

    timestamp = int(time.time())
    temp_filename = f"temp_{timestamp}_{original_filename}"
    temp_path = os.path.join(UPLOAD_FOLDER, temp_filename)

    encrypted_filename = f"{original_filename}.enc"
    encrypted_path = os.path.join(UPLOAD_FOLDER, f"enc_{timestamp}_{encrypted_filename}")

    try:
        file.save(temp_path)
        file_size = os.path.getsize(temp_path)
        encrypt_file(temp_path, encrypted_path, password)
        os.remove(temp_path)

        # Compute integrity hash of encrypted file
        with open(encrypted_path, "rb") as f:
            file_bytes = f.read()
        integrity_hash = hashlib.sha256(file_bytes).hexdigest()
        integrity_status = "ok"

        # Log with category and hint
        log_file_operation(
            session["user_id"],
            original_filename,
            encrypted_filename,
            "encrypt",
            category,
            hint,
            shareable,
            encrypted_path,
            file_size,
            integrity_hash=integrity_hash,
            integrity_status=integrity_status,
        )

        flash(f"File encrypted successfully! Category: {category}", "success")
        return send_file(encrypted_path, as_attachment=True, download_name=encrypted_filename)
    except Exception as err:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        flash(f"Encryption failed: {err}", "error")
        return redirect(url_for(f"encrypt_{category}"))


# ============================================
# DECRYPTION ROUTES BY CATEGORY
# ============================================

@app.route("/decrypt-images", methods=["GET", "POST"])
def decrypt_images():
    if "user_id" not in session or not session.get("verified"):
        return redirect(url_for("login"))

    if request.method == "POST":
        return handle_decrypt("images")

    return render_template("decrypt_images.html")


@app.route("/decrypt-documents", methods=["GET", "POST"])
def decrypt_documents():
    if "user_id" not in session or not session.get("verified"):
        return redirect(url_for("login"))

    if request.method == "POST":
        return handle_decrypt("documents")

    return render_template("decrypt_documents.html")


@app.route("/decrypt-media", methods=["GET", "POST"])
def decrypt_media():
    if "user_id" not in session or not session.get("verified"):
        return redirect(url_for("login"))

    if request.method == "POST":
        return handle_decrypt("media")

    return render_template("decrypt_media.html")


def handle_decrypt(category: str):
    """Handle decryption for any category - WITH EMAIL OTP VERIFICATION"""

    # ✅ Ensure user is logged in and verified
    if "user_id" not in session or not session.get("verified"):
        return redirect(url_for("login"))

    # ✅ FIX: define user_id properly
    user_id = session["user_id"]

    if "file" not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for(f"decrypt_{category}"))

    file = request.files["file"]
    password = request.form.get("password", "")

    if file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for(f"decrypt_{category}"))

    if not password:
        flash("Password is required for decryption.", "error")
        return redirect(url_for(f"decrypt_{category}"))

    original_filename = secure_filename(file.filename)

    if not original_filename.endswith(".enc"):
        flash("Only .enc files can be decrypted.", "error")
        return redirect(url_for(f"decrypt_{category}"))

    # ✅ Save encrypted file temporarily
    timestamp = int(time.time())
    temp_enc_filename = f"temp_enc_{timestamp}_{original_filename}"
    temp_enc_path = os.path.join(DECRYPTED_FOLDER, temp_enc_filename)
    file.save(temp_enc_path)

    # ✅ Optional: integrity check (compare stored file hash)
    conn = db()
    c = conn.cursor()
    c.execute("""
        SELECT integrity_hash, stored_path
        FROM file_history
        WHERE user_id = ? AND original_filename = ? AND operation = 'encrypt'
        ORDER BY timestamp DESC
        LIMIT 1
    """, (user_id, original_filename))
    row = c.fetchone()
    conn.close()

    if row and row[0]:
        saved_hash, stored_path = row
        try:
            with open(stored_path, "rb") as f:
                current_bytes = f.read()
            current_hash = hashlib.sha256(current_bytes).hexdigest()
        except FileNotFoundError:
            current_hash = None

        if not current_hash or current_hash != saved_hash:
            flash("Integrity check failed: encrypted file was modified or is missing.", "error")
            if os.path.exists(temp_enc_path):
                os.remove(temp_enc_path)
            return redirect(url_for("dashboard"))

    # ✅ Store decryption details in session (for OTP verification step)
    session["decrypt_file_path"] = temp_enc_path
    session["decrypt_password"] = password
    session["decrypt_original_filename"] = original_filename
    session["decrypt_category"] = category

    # ✅ Get user email and send OTP
    conn = db()
    c = conn.cursor()
    c.execute("SELECT email FROM users WHERE id = ?", (user_id,))
    user_row = c.fetchone()
    conn.close()

    if not user_row:
        flash("User email not found.", "error")
        return redirect(url_for("dashboard"))

    user_email = user_row[0]

    # ✅ Generate and send OTP
    otp = create_otp(user_id, "decrypt")
    send_otp(user_email, otp, "file decryption")

    flash(f"OTP sent to {user_email}. Please verify to decrypt file.", "info")
    return redirect(url_for("verify_decrypt_page"))




# ============================================
# DOWNLOAD HISTORY
# ============================================

@app.route("/download-history/<int:file_id>")
def download_history(file_id):
    if "user_id" not in session or not session.get("verified"):
        return redirect(url_for("login"))

    conn = db()
    c = conn.cursor()
    c.execute("""
        SELECT stored_path, stored_filename
        FROM file_history
        WHERE id = ? AND user_id = ?
    """, (file_id, session["user_id"]))

    row = c.fetchone()
    conn.close()

    if not row or not row[0]:
        flash("File not found or has been deleted.", "error")
        return redirect(url_for("dashboard"))

    file_path, filename = row

    if not os.path.exists(file_path):
        flash("File has been removed from server storage.", "error")
        return redirect(url_for("dashboard"))

    return send_file(file_path, as_attachment=True, download_name=filename)


@app.route("/verify-decrypt", methods=["GET", "POST"])
def verify_decrypt_page():
    if "user_id" not in session or not session.get("verified"):
        return redirect(url_for("login"))

    # ✅ Ensure decrypt request exists
    if "decrypt_file_path" not in session:
        flash("No decryption request found.", "error")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        user_id = session["user_id"]

        if not otp:
            flash("Please enter OTP.", "error")
            return render_template("verify_decrypt.html")

        # ✅ Validate OTP
        if validate_otp(user_id, otp, "decrypt"):
            temp_enc_path = session.get("decrypt_file_path")
            password = session.get("decrypt_password")
            original_filename = session.get("decrypt_original_filename")
            category = session.get("decrypt_category", "general")

            if not temp_enc_path or not password or not original_filename:
                flash("Invalid decrypt session. Please try again.", "error")
                return redirect(url_for("dashboard"))

            # ✅ Ensure encrypted file exists
            if not os.path.exists(temp_enc_path):
                flash("Encrypted file not found. Please re-upload and try again.", "error")
                return redirect(url_for("dashboard"))

            # Remove .enc to get original filename
            decrypted_filename = original_filename.replace(".enc", "")
            timestamp = int(time.time())

            # Store decrypted file temporarily
            temp_dec_filename = f"dec_{timestamp}_{decrypted_filename}"
            decrypted_path = os.path.join(DECRYPTED_FOLDER, temp_dec_filename)

            try:
                # ✅ Decrypt the file
                decrypt_file(temp_enc_path, decrypted_path, password)

                # ✅ Clean temp encrypted file after success
                if os.path.exists(temp_enc_path):
                    os.remove(temp_enc_path)

                file_size = os.path.getsize(decrypted_path)

                # ✅ Integrity status can be logged as ok after decrypt success
                integrity_status = "ok"

                # ✅ Log operation
                conn = db()
                c = conn.cursor()
                c.execute("""
                    INSERT INTO file_history (
                        user_id, original_filename, stored_filename, operation,
                        category, stored_path, file_size, integrity_status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user_id,
                    original_filename,
                    decrypted_filename,
                    "decrypt",
                    category,
                    decrypted_path,
                    file_size,
                    integrity_status
                ))
                conn.commit()
                file_id = c.lastrowid
                conn.close()

                # ✅ Store in session for download
                session["pending_download"] = {
                    "file_id": file_id,
                    "path": decrypted_path,
                    "filename": decrypted_filename
                }

                # ✅ Clear decrypt session
                session.pop("decrypt_file_path", None)
                session.pop("decrypt_password", None)
                session.pop("decrypt_original_filename", None)
                session.pop("decrypt_category", None)

                flash("✅ OTP verified. File decrypted successfully!", "success")
                return redirect(url_for("download_success", file_id=file_id, filename=decrypted_filename))

            except Exception as err:
                # ✅ Clean files if decrypt fails
                if os.path.exists(temp_enc_path):
                    os.remove(temp_enc_path)
                if os.path.exists(decrypted_path):
                    os.remove(decrypted_path)

                flash(f"❌ Decryption failed: {err}. Check password or file integrity.", "error")
                return redirect(url_for("dashboard"))

        else:
            flash("❌ Invalid or expired OTP. Please try again.", "error")

    return render_template("verify_decrypt.html")



# NEW ROUTE: Download success page
@app.route("/download-success")
def download_success():
    if "user_id" not in session or not session.get("verified"):
        return redirect(url_for("login"))

    if "pending_download" not in session:
        flash("Download session expired.", "error")
        return redirect(url_for("dashboard"))

    pending = session["pending_download"]

    # ✅ Always trust session more than URL params
    file_id = pending.get("file_id")
    filename = pending.get("filename", "file")

    if not file_id:
        flash("Invalid download session.", "error")
        return redirect(url_for("dashboard"))

    return render_template("download_success.html", file_id=file_id, filename=filename)



# NEW ROUTE: Actually download the file
@app.route("/download-decrypted/<int:file_id>")
def download_decrypted_file(file_id):
    if "user_id" not in session or not session.get("verified"):
        return redirect(url_for("login"))

    if "pending_download" not in session:
        flash("Download session expired.", "error")
        return redirect(url_for("dashboard"))

    download_data = session["pending_download"]

    if download_data["file_id"] != file_id:
        flash("Invalid download request.", "error")
        return redirect(url_for("dashboard"))

    file_path = download_data["path"]
    filename = download_data["filename"]

    if not os.path.exists(file_path):
        flash("File not found or has been deleted.", "error")
        return redirect(url_for("dashboard"))

    # Clear download session
    session.pop("pending_download", None)

    return send_file(file_path, as_attachment=True, download_name=filename)


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


# ============================================
# FILE SHARING ROUTES
# ============================================

@app.route("/share-file/<int:file_id>", methods=["GET", "POST"])
def share_file(file_id):
    if "user_id" not in session or not session.get("verified"):
        return redirect(url_for("login"))

    conn = db()
    c = conn.cursor()

    # ✅ Verify file belongs to logged-in user
    c.execute("""
        SELECT original_filename
        FROM file_history
        WHERE id = ? AND user_id = ?
    """, (file_id, session["user_id"]))

    row = c.fetchone()

    if not row:
        conn.close()
        flash("File not found or you don't have permission.", "error")
        return redirect(url_for("dashboard"))

    filename = row[0]

    # ✅ POST: Create share link
    if request.method == "POST":
        share_type = request.form.get("share_type", "public")
        shared_with_email = request.form.get("shared_with_email", "").strip()
        expiry_days = int(request.form.get("expiry_days", 7))

        # ✅ Optional advanced fields (your current share_file.html doesn't include these, safe defaults)
        pin = request.form.get("pin", "").strip()
        one_time = 1 if request.form.get("one_time") == "on" else 0
        max_downloads = int(request.form.get("max_downloads", 0))

        # ✅ Validation (private share must have email)
        if share_type == "private" and not shared_with_email:
            conn.close()
            flash("Email is required for private sharing.", "error")
            return redirect(url_for("share_file", file_id=file_id))

        # ✅ Create token + expiry BEFORE insert
        share_token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(days=expiry_days)

        # ✅ Hash PIN (never store plain pin)
        pin_hash = generate_password_hash(pin) if pin else None

        # ✅ Insert only once
        c.execute("""
            INSERT INTO shared_files (
                file_id, owner_id, shared_with_email, share_token,
                is_public, access_count, expires_at, created_at,
                revoked, one_time, max_downloads, download_count, pin_hash
            )
            VALUES (?, ?, ?, ?, ?, 0, ?, CURRENT_TIMESTAMP, 0, ?, ?, 0, ?)
        """, (
            file_id,
            session["user_id"],
            shared_with_email if share_type == "private" else None,
            share_token,
            1 if share_type == "public" else 0,
            expires_at,
            one_time,
            max_downloads,
            pin_hash
        ))

        conn.commit()
        conn.close()

        # ✅ NOW create share_link safely (after token exists)
        share_link = url_for("access_shared_file", token=share_token, _external=True)

        flash("✅ File shared successfully!", "success")
        return render_template(
            "share_success.html",
            share_link=share_link,
            filename=filename,
            expiry_days=expiry_days
        )

    # ✅ GET: Show Share form
    conn.close()
    return render_template("share_file.html", file_id=file_id, filename=filename)


@app.route("/shared/<token>")
def access_shared_file(token):
    conn = db()
    c = conn.cursor()

    # Get share details
    c.execute("""
        SELECT sf.id, sf.file_id, sf.owner_id, sf.shared_with_email, sf.is_public, 
               sf.expires_at, fh.original_filename, fh.stored_path, fh.category,
               u.username as owner_name
        FROM shared_files sf
        JOIN file_history fh ON sf.file_id = fh.id
        JOIN users u ON sf.owner_id = u.id
        WHERE sf.share_token = ?
    """, (token,))

    share_data = c.fetchone()

    if not share_data:
        conn.close()
        flash("Invalid or expired share link.", "error")
        return redirect(url_for("login"))

    (share_id, file_id, owner_id, shared_with_email, is_public,
     expires_at, filename, stored_path, category, owner_name) = share_data

    # Check expiry
    if datetime.now() > datetime.fromisoformat(expires_at):
        conn.close()
        flash("This share link has expired.", "error")
        return redirect(url_for("login"))

    # Check access permissions
    if not is_public and shared_with_email:
        # Private share - verify user email
        if "user_id" not in session:
            flash("Please login to access this shared file.", "info")
            return redirect(url_for("login"))

        c.execute("SELECT email FROM users WHERE id = ?", (session["user_id"],))
        user_email = c.fetchone()[0]

        if user_email != shared_with_email:
            conn.close()
            flash("You don't have permission to access this file.", "error")
            return redirect(url_for("dashboard"))

    # Increment access count
    c.execute("UPDATE shared_files SET access_count = access_count + 1 WHERE id = ?", (share_id,))
    conn.commit()
    conn.close()

    return render_template("view_shared_file.html",
                           filename=filename,
                           category=category,
                           owner_name=owner_name,
                           token=token,
                           file_id=file_id)


@app.route("/download-shared/<token>")
def download_shared_file(token):
    conn = db()
    c = conn.cursor()

    c.execute("""
        SELECT sf.expires_at, sf.revoked, sf.one_time, sf.max_downloads, sf.download_count,
               fh.stored_path, fh.stored_filename
        FROM shared_files sf
        JOIN file_history fh ON sf.file_id = fh.id
        WHERE sf.share_token = ?
    """, (token,))
    result = c.fetchone()

    if not result:
        conn.close()
        flash("Invalid share link.", "error")
        return redirect(url_for("login"))

    expires_at, revoked, one_time, max_downloads, download_count, stored_path, filename = result

    # Check revoked
    if revoked == 1:
        conn.close()
        flash("This share link has been revoked.", "error")
        return redirect(url_for("login"))

    # Check expiry
    if datetime.now() > datetime.fromisoformat(str(expires_at)):
        conn.close()
        flash("This share link has expired.", "error")
        return redirect(url_for("login"))

    # Check one-time / max downloads
    if one_time == 1 and download_count >= 1:
        conn.close()
        flash("This link was one-time use only.", "error")
        return redirect(url_for("login"))

    if max_downloads and max_downloads > 0 and download_count >= max_downloads:
        conn.close()
        flash("Download limit reached for this share link.", "error")
        return redirect(url_for("login"))

    if not os.path.exists(stored_path):
        conn.close()
        flash("File not found on server.", "error")
        return redirect(url_for("dashboard"))

    # ✅ Increase download count
    c.execute("""
        UPDATE shared_files
        SET download_count = download_count + 1,
            access_count = access_count + 1
        WHERE share_token = ?
    """, (token,))
    conn.commit()
    conn.close()

    return send_file(stored_path, as_attachment=True, download_name=filename)



@app.route("/my-shares")
def my_shares():
    if "user_id" not in session or not session.get("verified"):
        return redirect(url_for("login"))

    conn = db()
    c = conn.cursor()

    c.execute("""
        SELECT sf.id, sf.share_token, sf.is_public, sf.shared_with_email,
               sf.access_count, sf.expires_at, sf.created_at,
               fh.original_filename, fh.category
        FROM shared_files sf
        JOIN file_history fh ON sf.file_id = fh.id
        WHERE sf.owner_id = ?
        ORDER BY sf.created_at DESC
    """, (session["user_id"],))

    shares = []
    for row in c.fetchall():
        token = row[1]
        share_link = url_for('access_shared_file', token=token, _external=True)

        shares.append({
            "id": row[0],
            "token": token,  # ✅ ADD THIS
            "share_link": share_link,
            "is_public": row[2],
            "shared_with": row[3] or "Anyone with link",
            "access_count": row[4],
            "expires_at": row[5],
            "created_at": row[6],
            "filename": row[7],
            "category": row[8],
        })
    print("✅ TOTAL SHARES FOUND:", len(shares))
    conn.close()
    return render_template("my_shares.html", shares=shares)



@app.route("/revoke-share/<int:share_id>")
def revoke_share(share_id):
    if "user_id" not in session or not session.get("verified"):
        return redirect(url_for("login"))

    conn = db()
    c = conn.cursor()

    c.execute("""
        UPDATE shared_files
        SET revoked = 1
        WHERE id = ? AND owner_id = ?
    """, (share_id, session["user_id"]))

    conn.commit()
    conn.close()

    flash("✅ Share link revoked successfully!", "success")
    return redirect(url_for("my_shares"))


# ============================================
# RUN APPLICATION
# ============================================

if __name__ == "__main__":
    print("=" * 80)
    print("🚀 ADVANCED ENCRYPTION TOOL - COMPLETE VERSION")
    print("=" * 80)
    print("✅ Database initializing...")

    init_db()

    print("✅ Database initialized")
    print("✅ All features loaded:")
    print("   • Logo on all pages")
    print("   • Show password toggles")
    print("   • Forgot password/username")
    print("   • Mobile number required")
    print("   • Original filename preservation")
    print("=" * 80)
    print("🌐 Starting Flask server...")
    print("📱 Open: http://localhost:5000")
    print("📱 Mobile: http://10.144.122.240:5000")
    print("=" * 80)

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)



