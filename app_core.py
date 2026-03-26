from flask import Flask, render_template, session, redirect, url_for, send_file
import os
import secrets
from datetime import timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8)
)

# ===============================
# ROUTES
# ===============================

@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session.get("username"))

# ENCRYPT
@app.route("/encrypt_images")
def encrypt_images():
    return render_template("encrypt_images.html")

@app.route("/encrypt_documents")
def encrypt_documents():
    return render_template("encrypt_documents.html")

@app.route("/encrypt_media")
def encrypt_media():
    return render_template("encrypt_media.html")

# DECRYPT
@app.route("/decrypt_images")
def decrypt_images():
    return render_template("decrypt_images.html")

@app.route("/decrypt_documents")
def decrypt_documents():
    return render_template("decrypt_documents.html")

@app.route("/decrypt_media")
def decrypt_media():
    return render_template("decrypt_media.html")

# DOWNLOAD
@app.route("/download/<filename>")
def download_file(filename):
    path = os.path.join("decrypted_files", filename)
    return send_file(path, as_attachment=True)

@app.route("/download_success")
def download_success():
    return render_template("download_success.html")

# SHARE
@app.route("/share/<int:file_id>")
def share_file(file_id):
    return render_template("share_file.html", file_id=file_id)

@app.route("/share_success")
def share_success():
    return render_template("share_success.html")

@app.route("/my_shares")
def my_shares():
    return render_template("my_shares.html", shares=[])

# USER
@app.route("/forgot-username")
def forgot_username():
    return render_template("forgot_username.html")

@app.route("/reset-password")
def reset_password():
    return render_template("reset_password.html")

@app.route("/verify-forgot-password-otp")
def verify_forgot_password_otp():
    return render_template("verify_forgot_password_otp.html")

# LOGOUT
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))
