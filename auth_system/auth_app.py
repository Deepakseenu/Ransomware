#!/usr/bin/env python3
"""
auth_app.py - Secure Auth System with OTP via Email
Run: python3 auth_app.py
"""

import os
import sqlite3
import secrets
import smtplib
import jwt
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from werkzeug.security import generate_password_hash, check_password_hash

# -----------------------------
# Paths and Config
# -----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "db.sqlite3")

# --- Configuration ---
# SECRET_KEY is regenerated each run (keeps tokens JWT-bound to this run)
SECRET_KEY = secrets.token_hex(32)
JWT_EXP_MINUTES = int(os.environ.get("AUTH_JWT_EXP_MINUTES", "10"))

# Gmail SMTP (replace with env or configure .env in production)
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")  # set via env or .env
SMTP_PASS = os.environ.get("SMTP_PASS", "")  # set via env or .env
FROM_EMAIL = os.environ.get("FROM_EMAIL") or SMTP_USER

# Show OTP in console for testing (set AUTH_DEBUG_PRINT_TOKEN=1 to enable)
DEBUG_PRINT_OTP = bool(int(os.environ.get("AUTH_DEBUG_PRINT_TOKEN", "0")))

# -----------------------------
# Flask setup
# -----------------------------
app = Flask(__name__, template_folder="templates")
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

FAILED = {}
MAX_FAIL = 5
BLOCK_MINUTES = 15

# -----------------------------
# DB Helpers
# -----------------------------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = sqlite3.connect(DB_PATH, check_same_thread=False)
        db.row_factory = sqlite3.Row
        g._database = db
    return db

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        otp_hash TEXT NOT NULL,
        jwt_token TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        expires_at TEXT NOT NULL,
        used INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

# -----------------------------
# Security Helpers
# -----------------------------
def record_failed(ip):
    entry = FAILED.get(ip, {"count": 0, "blocked_until": None})
    entry["count"] += 1
    if entry["count"] >= MAX_FAIL:
        entry["blocked_until"] = datetime.now(timezone.utc) + timedelta(minutes=BLOCK_MINUTES)
    FAILED[ip] = entry

def reset_failed(ip):
    if ip in FAILED:
        del FAILED[ip]

def is_blocked(ip):
    entry = FAILED.get(ip)
    if not entry:
        return False
    blocked_until = entry.get("blocked_until")
    if blocked_until and datetime.now(timezone.utc) < blocked_until:
        return True
    if blocked_until and datetime.now(timezone.utc) >= blocked_until:
        del FAILED[ip]
    return False

def generate_jwt(username):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": now.isoformat(),
        "exp": (now + timedelta(minutes=JWT_EXP_MINUTES)).isoformat()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def send_email(to_email, subject, body):
    """Send OTP via SMTP. If SMTP not configured, optionally print OTP when DEBUG_PRINT_OTP is True."""
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS):
        app.logger.warning("SMTP not configured (SMTP_HOST/SMTP_USER/SMTP_PASS missing).")
        if DEBUG_PRINT_OTP:
            print(f"\n[DEBUG OTP to {to_email}]\n{body}\n")
        return False
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email
    msg.set_content(body)
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        return True
    except Exception as e:
        app.logger.exception("Email send failed")
        if DEBUG_PRINT_OTP:
            print(f"\n[DEBUG OTP to {to_email}] {body}\n")
        return False

def get_client_ip():
    if request.environ.get("HTTP_X_FORWARDED_FOR"):
        return request.environ["HTTP_X_FORWARDED_FOR"].split(",")[0].strip()
    return request.remote_addr or "unknown"

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session or not session.get("verified"):
            flash("Please login and verify OTP first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def index():
    # If already verified, go to dashboard; otherwise go to login
    if session.get("user") and session.get("verified"):
        return redirect(url_for("dashboard_redirect"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("All fields required", "danger")
            return redirect(url_for("register"))

        db = get_db()
        cur = db.cursor()
        try:
            cur.execute("INSERT INTO users (username,email,password_hash) VALUES (?,?,?)",
                        (username, email, generate_password_hash(password)))
            db.commit()
            flash("Registered successfully. Login now.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "danger")
            return redirect(url_for("register"))
        except Exception as e:
            app.logger.exception("DB error on register")
            flash("Server error. Try again.", "danger")
            return redirect(url_for("register"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ident = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip = get_client_ip()

        if is_blocked(ip):
            flash("Too many failed attempts. Try again later.", "danger")
            return redirect(url_for("login"))

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id, username, email, password_hash FROM users WHERE username=? OR email=?",
                    (ident, ident.lower()))
        row = cur.fetchone()

        if row and check_password_hash(row["password_hash"], password):
            reset_failed(ip)
            # Generate OTP and store hashed version
            otp = secrets.token_hex(4)  # 8 hex chars
            otp_hash = generate_password_hash(otp)
            jwt_token = generate_jwt(row["username"])
            expires = (datetime.now(timezone.utc) + timedelta(minutes=JWT_EXP_MINUTES)).isoformat()

            cur.execute("INSERT INTO tokens (otp_hash, jwt_token, user_id, expires_at) VALUES (?,?,?,?)",
                        (otp_hash, jwt_token, row["id"], expires))
            db.commit()

            body = f"Your OTP for login (valid {JWT_EXP_MINUTES} minutes): {otp}"
            if DEBUG_PRINT_OTP:
                print(f"\n=== OTP for {row['email']} ===\n{otp}\n========================\n")

            send_email(row["email"], "Your OTP Code", body)

            session["temp_user"] = row["username"]
            flash("OTP sent to your email. Verify it.", "info")
            return redirect(url_for("verify"))
        else:
            record_failed(ip)
            flash("Invalid credentials.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/verify", methods=["GET", "POST"])
def verify():
    temp_user = session.get("temp_user")
    if not temp_user:
        flash("Please log in again to get a new OTP.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        if not otp:
            flash("OTP required.", "danger")
            return redirect(url_for("verify"))

        db = get_db()
        cur = db.cursor()

        # Fetch latest unused token row for this user
        cur.execute("""
            SELECT t.id, t.otp_hash, t.jwt_token, t.expires_at, t.used
            FROM tokens t
            JOIN users u ON u.id = t.user_id
            WHERE u.username = ? AND t.used = 0
            ORDER BY t.id DESC
            LIMIT 1
        """, (temp_user,))
        row = cur.fetchone()

        if not row:
            flash("No OTP record found. Please login again.", "danger")
            return redirect(url_for("login"))

        try:
            # Validate JWT belongs to temp_user and is not expired (server-side check)
            payload = jwt.decode(row["jwt_token"], SECRET_KEY, algorithms=["HS256"])
            if payload.get("sub") != temp_user:
                flash("Token-user mismatch. Please login again.", "danger")
                return redirect(url_for("login"))
        except jwt.ExpiredSignatureError:
            flash("Internal token expired. Please login again.", "danger")
            return redirect(url_for("login"))
        except Exception as e:
            app.logger.debug("JWT decode error: %s", e)
            # continue to OTP check (we rely on DB expires_at too)

        # check expires_at stored in tokens (timezone-aware)
        try:
            exp_time = datetime.fromisoformat(row["expires_at"])
            if datetime.now(timezone.utc) > exp_time:
                flash("OTP expired. Please login again.", "danger")
                return redirect(url_for("login"))
        except Exception:
            # if parsing fails, be conservative and reject
            flash("Server error validating OTP expiry. Please login again.", "danger")
            return redirect(url_for("login"))

        # compare hashed OTP
        if check_password_hash(row["otp_hash"], otp):
            # Mark token used
            try:
                cur.execute("UPDATE tokens SET used = 1 WHERE id = ?", (row["id"],))
                db.commit()
            except Exception:
                app.logger.exception("Failed to mark token used")

            # Establish verified session
            session.pop("temp_user", None)
            session["user"] = temp_user
            session["verified"] = True

            flash("OTP verified successfully! Redirecting to dashboard...", "success")
            app.logger.info("%s verified - redirecting to dashboard", temp_user)
            return redirect("http://127.0.0.1:5000/")
        else:
            flash("Incorrect OTP. Try again.", "danger")
            return redirect(url_for("verify"))

    # GET -> show verification page
    return render_template("verify_token.html")

@app.route("/dashboard")
@login_required
def dashboard_redirect():
    # after successful verification, redirect to main dashboard on port 5000
    return redirect("http://127.0.0.1:5000/")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))

# -----------------------------
# Run app
# -----------------------------
if __name__ == "__main__":
    os.makedirs(BASE_DIR, exist_ok=True)
    with app.app_context():
        init_db()
    # debug=True for development; set False in production
    app.run(host="127.0.0.1", port=int(os.environ.get("AUTH_PORT", "5001")), debug=True)
