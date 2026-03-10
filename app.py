import os
import sqlite3
import secrets
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash

# ----------------------------------
# APP CONFIG
# ----------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "advanced_encryption.db")


# ----------------------------------
# DATABASE
# ----------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        created_at TEXT
    )
    """)

    conn.commit()
    conn.close()


# ----------------------------------
# ROUTES
# ----------------------------------

@app.route("/")
def home():
    return redirect(url_for("login"))


# ----------------------------------
# SIGNUP
# ----------------------------------

@app.route("/signup", methods=["GET","POST"])
def signup():

    if request.method == "POST":

        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        conn = get_db()
        c = conn.cursor()

        try:
            c.execute(
                "INSERT INTO users (username,email,password,created_at) VALUES (?,?,?,?)",
                (username,email,password,str(datetime.now()))
            )
            conn.commit()

        except:
            flash("User already exists")
            return render_template("signup.html")

        conn.close()

        flash("Account created successfully")
        return redirect(url_for("login"))

    return render_template("signup.html")


# ----------------------------------
# LOGIN
# ----------------------------------

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

        flash("Invalid credentials")

    return render_template("login.html")


# ----------------------------------
# DASHBOARD
# ----------------------------------

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template("dashboard.html", username=session["username"])


# ----------------------------------
# FORGOT PASSWORD
# ----------------------------------

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

        flash("Password reset instructions sent (demo)")
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


# ----------------------------------
# FORGOT USERNAME
# ----------------------------------

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


# ----------------------------------
# LOGOUT
# ----------------------------------

@app.route("/logout")
def logout():

    session.clear()
    return redirect(url_for("login"))


# ----------------------------------
# START APP
# ----------------------------------

init_db()

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
