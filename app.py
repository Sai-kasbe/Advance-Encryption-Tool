import os
import sqlite3
import secrets
from datetime import timedelta
from flask import Flask

# IMPORTANT: import your existing app code
from app import app as flask_app   # rename your old file to app_core.py

# ================================
# RENDER COMPATIBILITY FIX
# ================================

def create_app():
    app = flask_app

    # SECRET KEY (Render ENV)
    app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

    # SESSION CONFIG (important for Render)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8)
    )

    if os.environ.get("RENDER"):
        app.config["SESSION_COOKIE_SECURE"] = True

    # DATABASE PATH FIX (Render disk)
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DB_PATH = os.path.join(BASE_DIR, "advanced_encryption.db")

    app.config["DATABASE"] = DB_PATH

    # Ensure folders exist
    os.makedirs(os.path.join(BASE_DIR, "encrypted_files"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "decrypted_files"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "static"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "templates"), exist_ok=True)

    return app
# ===============================
# DASHBOARD
# ===============================
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session.get("username"))


# ===============================
# ENCRYPT ROUTES
# ===============================
@app.route("/encrypt_images", methods=["GET", "POST"])
def encrypt_images():
    return render_template("encrypt_images.html")

@app.route("/encrypt_documents", methods=["GET", "POST"])
def encrypt_documents():
    return render_template("encrypt_documents.html")

@app.route("/encrypt_media", methods=["GET", "POST"])
def encrypt_media():
    return render_template("encrypt_media.html")


# ===============================
# DECRYPT ROUTES
# ===============================
@app.route("/decrypt_images", methods=["GET", "POST"])
def decrypt_images():
    return render_template("decrypt_images.html")

@app.route("/decrypt_documents", methods=["GET", "POST"])
def decrypt_documents():
    return render_template("decrypt_documents.html")

@app.route("/decrypt_media", methods=["GET", "POST"])
def decrypt_media():
    return render_template("decrypt_media.html")


# ===============================
# DOWNLOAD ROUTES
# ===============================
@app.route("/download/<filename>")
def download_file(filename):
    path = os.path.join("decrypted_files", filename)
    return send_file(path, as_attachment=True)


@app.route("/download_success")
def download_success():
    return render_template("download_success.html")


@app.route("/download_decrypted")
def download_decrypted():
    return render_template("download_decrypted.html")


# ===============================
# SHARE SYSTEM
# ===============================
@app.route("/share/<int:file_id>", methods=["GET", "POST"])
def share_file(file_id):
    return render_template("share_file.html", file_id=file_id, filename="file.enc")


@app.route("/share_success")
def share_success():
    return render_template("share_success.html", filename="file.enc", share_link="demo-link", expiry_days=7)


@app.route("/my_shares")
def my_shares():
    return render_template("my_shares.html", shares=[])


@app.route("/view/<token>")
def view_shared_file(token):
    return render_template("view_shared_file.html")


# ===============================
# PASSWORD & USER
# ===============================
@app.route("/forgot-username", methods=["GET", "POST"])
def forgot_username():
    return render_template("forgot_username.html")


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    return render_template("reset_password.html")


@app.route("/verify-forgot-password-otp", methods=["GET", "POST"])
def verify_forgot_password_otp():
    return render_template("verify_forgot_password_otp.html")


@app.route("/verify-decrypt")
def verify_decrypt():
    return render_template("verify_decrypt.html")


@app.route("/verify-decrypt-page")
def verify_decrypt_page():
    return render_template("verify_decrypt_page.html")


# ===============================
# LOGOUT
# ===============================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

app = create_app()

# ================================
# IMPORTANT: FOR GUNICORN
# ================================
import os
from app_core import app   # ✅ correct import (no circular issue)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
