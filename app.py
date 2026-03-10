import os
import sqlite3
import secrets
import smtplib
import time
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash, jsonify
)

# -------------------------------------
# APP CONFIG
# -------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(16))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "advanced_encryption.db")

MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")

# -------------------------------------
# DATABASE
# -------------------------------------

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


# -------------------------------------
# EMAIL FUNCTION
# -------------------------------------

def send_email(to_email, subject, html):

    msg = MIMEMultipart()
    msg["From"] = MAIL_USERNAME
    msg["To"] = to_email
    msg["Subject"] = subject

    msg.attach(MIMEText(html, "html"))

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()

    server.login(MAIL_USERNAME, MAIL_PASSWORD)

    server.sendmail(MAIL_USERNAME, to_email, msg.as_string())

    server.quit()


# -------------------------------------
# HOME
# -------------------------------------

@app.route("/")
def home():
    return redirect(url_for("login"))


# -------------------------------------
# LOGIN
# -------------------------------------

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


# -------------------------------------
# SIGNUP
# -------------------------------------

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


# -------------------------------------
# DASHBOARD
# -------------------------------------

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        username=session["username"]
    )


# -------------------------------------
# OTP SEND
# -------------------------------------

@app.route("/api/send_email_otp", methods=["POST"])
def send_email_otp():

    data = request.get_json()
    email = data.get("email")

    otp = str(secrets.randbelow(999999)).zfill(6)

    session["signup_email"] = email
    session["signup_otp"] = otp
    session["signup_otp_time"] = time.time()

    subject = "Your OTP Code"

    html = f"""
    <h2>Your OTP Code</h2>
    <h1>{otp}</h1>
    <p>This OTP expires in 2 minutes</p>
    """

    try:
        send_email(email, subject, html)
    except:
        print("Email failed")

    return jsonify({"sent": True})


# -------------------------------------
# OTP VERIFY
# -------------------------------------

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

    return jsonify({"valid": valid})


# -------------------------------------
# FORGOT PASSWORD
# -------------------------------------

@app.route("/forgot-password", methods=["GET","POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form.get("email")

        conn = get_db()
        c = conn.cursor()

        c.execute("SELECT * FROM users WHERE email=?", (email,))
        user = c.fetchone()
        conn.close()

        if not user:
            flash("Email not found")
            return render_template("forgot_password.html")

        flash("Password reset email sent (demo)")
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


# -------------------------------------
# FORGOT USERNAME
# -------------------------------------

@app.route("/forgot-username", methods=["GET","POST"])
def forgot_username():

    if request.method == "POST":

        email = request.form.get("email")

        conn = get_db()
        c = conn.cursor()

        c.execute("SELECT username FROM users WHERE email=?", (email,))
        user = c.fetchone()
        conn.close()

        if not user:
            flash("Email not found")
            return render_template("forgot_username.html")

        flash(f"Your username is: {user['username']}")
        return redirect(url_for("login"))

    return render_template("forgot_username.html")


# -------------------------------------
# LOGOUT
# -------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# -------------------------------------
# ERROR HANDLER
# -------------------------------------

@app.errorhandler(500)
def error_500(e):
    return redirect(url_for("login"))


# -------------------------------------
# START SERVER
# -------------------------------------

init_db()

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
