import os
import sqlite3
import secrets
import time
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import requests

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(16))

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
# HOME
# -----------------------------

@app.route("/")
def home():
    return redirect(url_for("login"))


# -----------------------------
# LOGIN
# -----------------------------

@app.route("/login", methods=["GET","POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db()
        c = conn.cursor()

        c.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username,password)
        )

        user = c.fetchone()
        conn.close()

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))

        flash("Invalid username or password")

    return render_template("login.html")


# -----------------------------
# SIGNUP
# -----------------------------

@app.route("/signup", methods=["GET","POST"])
def signup():

    if request.method == "POST":

        if not session.get("email_verified"):
            flash("Please verify email OTP first")
            return render_template("signup.html")

        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        conn = get_db()
        c = conn.cursor()

        try:

            c.execute(
                "INSERT INTO users(username,email,password,created_at) VALUES(?,?,?,?)",
                (username,email,password,str(datetime.now()))
            )

            conn.commit()

        except:
            flash("User already exists")
            return render_template("signup.html")

        conn.close()

        session.pop("email_verified", None)

        flash("Account created successfully")

        return redirect(url_for("login"))

    return render_template("signup.html")


# -----------------------------
# DASHBOARD
# -----------------------------

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template("dashboard.html", username=session["username"])


# -----------------------------
# ENCRYPT
# -----------------------------

@app.route("/encrypt-images")
def encrypt_images():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("encrypt_images.html")


@app.route("/encrypt-documents")
def encrypt_documents():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("encrypt_documents.html")


@app.route("/encrypt-media")
def encrypt_media():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("encrypt_media.html")


# -----------------------------
# DECRYPT
# -----------------------------

@app.route("/decrypt-images")
def decrypt_images():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("decrypt_images.html")


@app.route("/decrypt-documents")
def decrypt_documents():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("decrypt_documents.html")


@app.route("/decrypt-media")
def decrypt_media():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("decrypt_media.html")


# -----------------------------
# DOWNLOAD
# -----------------------------

@app.route("/download-decrypted")
def download_decrypted():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("download_decrypted.html")


@app.route("/download-success")
def download_success():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("download_success.html")


# -----------------------------
# SHARE
# -----------------------------

@app.route("/share-file")
def share_file():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("share_file.html")


@app.route("/share-success")
def share_success():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("share_success.html")


@app.route("/my-shares")
def my_shares():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("my_shares.html")


@app.route("/view-shared-file")
def view_shared_file():
    return render_template("view_shared_file.html")


# -----------------------------
# OTP
# -----------------------------

@app.route("/api/send_email_otp", methods=["POST"])
def send_email_otp():

    data = request.get_json()

    email = data.get("email")

    otp = str(secrets.randbelow(999999)).zfill(6)

    session["signup_email"] = email
    session["signup_otp"] = otp
    session["signup_otp_time"] = time.time()

    html = f"<h2>Your OTP</h2><h1>{otp}</h1>"

    email_sent = send_email(email,"Your OTP Code",html)

    if not email_sent:
        return jsonify({"sent":False})

    return jsonify({"sent":True})


@app.route("/api/verify_email_otp", methods=["POST"])
def verify_email_otp():

    data = request.get_json()

    otp = data.get("otp")

    valid = (
        otp == session.get("signup_otp")
        and time.time() - session.get("signup_otp_time",0) < 120
    )

    if valid:
        session["email_verified"] = True

    return jsonify({"valid":valid})


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

init_db()

if __name__ == "__main__":

    port = int(os.environ.get("PORT",5000))

    app.run(host="0.0.0.0",port=port,debug=False)
