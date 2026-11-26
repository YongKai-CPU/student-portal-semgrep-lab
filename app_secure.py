"""
Student Portal - secured reference version (Flask + MySQL/MariaDB)

Security controls implemented:
  - Passwords stored as salted hashes (werkzeug / scrypt or pbkdf2)
  - Generic login error message + simple account lockout after repeated failures
  - Session fixation protection (session cleared on login), secure cookie flags
  - CSRF token on every state-changing form
  - Parameterised SQL queries only (no string concatenation)
  - File upload allow-list, size limit, secure_filename + random prefix,
    files stored outside the web root
  - Output encoding via Jinja2 auto-escaping (messaging XSS protection)
  - Profile update restricted to the logged-in user (no IDOR)
  - Basic role-based access (student / lecturer)
  - Security headers on every response, debug mode off
  - Secrets and DB credentials read from environment variables
"""
import os
import re
import secrets
import time
import uuid
from functools import wraps

import pymysql
from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_from_directory, session, url_for)
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=1800,           # 30 minutes
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,        # 5 MB upload limit
    UPLOAD_FOLDER=os.path.join(BASE_DIR, "uploads_secure"),
)
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "docx", "txt", "zip"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^\+?[0-9 \-]{7,20}$")
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 300
_failed_logins = {}   # username -> (count, first_failure_time)


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = pymysql.connect(
            host=os.environ.get("DB_HOST", "localhost"),
            user=os.environ.get("DB_USER", "portal_user"),
            password=os.environ.get("DB_PASSWORD", ""),
            database=os.environ.get("DB_NAME", "student_portal"),
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True,
        )
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql, params=(), one=False):
    with get_db().cursor() as cur:
        cur.execute(sql, params)          # always parameterised
        rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows


def execute(sql, params=()):
    with get_db().cursor() as cur:
        cur.execute(sql, params)


# --------------------------------------------------------------------------
# Security helpers
# --------------------------------------------------------------------------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("_csrf", "")):
            abort(400, "Invalid CSRF token")


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def role_required(role):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if session.get("role") != role:
                abort(403)
            return view(*args, **kwargs)
        return login_required(wrapped)
    return decorator


def is_locked(username):
    count, first = _failed_logins.get(username, (0, 0))
    if count >= MAX_FAILED_LOGINS and time.time() - first < LOCKOUT_SECONDS:
        return True
    if time.time() - first >= LOCKOUT_SECONDS:
        _failed_logins.pop(username, None)
    return False


def record_failure(username):
    count, first = _failed_logins.get(username, (0, time.time()))
    _failed_logins[username] = (count + 1, first)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:50]
        password = request.form.get("password", "")
        generic_error = "Invalid username or password."

        if is_locked(username):
            flash(generic_error, "error")
            return render_template("login.html"), 429

        user = query("SELECT id, username, password_hash, role FROM users WHERE username = %s",
                     (username,), one=True)
        if user and check_password_hash(user["password_hash"], password):
            _failed_logins.pop(username, None)
            session.clear()                       # prevent session fixation
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

        record_failure(username)
        flash(generic_error, "error")             # same message for every failure
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    grades = query("SELECT course, grade FROM grades WHERE student_id = %s", (session["user_id"],))
    attendance = query("SELECT course, percentage FROM attendance WHERE student_id = %s",
                       (session["user_id"],))
    return render_template("dashboard.html", grades=grades, attendance=attendance)


@app.route("/assignments", methods=["GET", "POST"])
@login_required
def assignments():
    if request.method == "POST":
        if session.get("role") != "student":
            abort(403)
        title = request.form.get("title", "").strip()[:100]
        file = request.files.get("file")
        if not title or not file or file.filename == "":
            flash("Title and file are required.", "error")
        elif not allowed_file(file.filename):
            flash("File type not allowed. Allowed: " + ", ".join(sorted(ALLOWED_EXTENSIONS)), "error")
        else:
            original = secure_filename(file.filename)
            stored = f"{uuid.uuid4().hex}_{original}"
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], stored))
            execute("INSERT INTO assignments (student_id, title, original_name, stored_name) "
                    "VALUES (%s, %s, %s, %s)", (session["user_id"], title, original, stored))
            flash("Assignment submitted.", "success")
        return redirect(url_for("assignments"))

    if session.get("role") == "lecturer":
        rows = query("SELECT a.id, a.title, a.original_name, a.submitted_at, u.username "
                     "FROM assignments a JOIN users u ON u.id = a.student_id "
                     "ORDER BY a.submitted_at DESC")
    else:
        rows = query("SELECT id, title, original_name, submitted_at FROM assignments "
                     "WHERE student_id = %s ORDER BY submitted_at DESC", (session["user_id"],))
    return render_template("assignments.html", assignments=rows)


@app.route("/assignments/<int:assignment_id>/download")
@login_required
def download_assignment(assignment_id):
    row = query("SELECT student_id, original_name, stored_name FROM assignments WHERE id = %s",
                (assignment_id,), one=True)
    if not row:
        abort(404)
    # owner or lecturer only
    if row["student_id"] != session["user_id"] and session.get("role") != "lecturer":
        abort(403)
    return send_from_directory(app.config["UPLOAD_FOLDER"], row["stored_name"],
                               as_attachment=True, download_name=row["original_name"])


@app.route("/messages", methods=["GET", "POST"])
@login_required
def messages():
    if request.method == "POST":
        recipient_name = request.form.get("recipient", "").strip()[:50]
        body = request.form.get("body", "").strip()
        recipient = query("SELECT id FROM users WHERE username = %s", (recipient_name,), one=True)
        if not recipient:
            flash("Recipient not found.", "error")
        elif not body or len(body) > 1000:
            flash("Message must be 1-1000 characters.", "error")
        else:
            execute("INSERT INTO messages (sender_id, recipient_id, body) VALUES (%s, %s, %s)",
                    (session["user_id"], recipient["id"], body))
            flash("Message sent.", "success")
        return redirect(url_for("messages"))

    inbox = query("SELECT m.body, m.sent_at, u.username AS sender FROM messages m "
                  "JOIN users u ON u.id = m.sender_id WHERE m.recipient_id = %s "
                  "ORDER BY m.sent_at DESC", (session["user_id"],))
    sent = query("SELECT m.body, m.sent_at, u.username AS recipient FROM messages m "
                 "JOIN users u ON u.id = m.recipient_id WHERE m.sender_id = %s "
                 "ORDER BY m.sent_at DESC", (session["user_id"],))
    users = query("SELECT username FROM users WHERE id <> %s ORDER BY username",
                  (session["user_id"],))
    return render_template("messages.html", inbox=inbox, sent=sent, users=users)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()[:100]
        email = request.form.get("email", "").strip()[:120]
        phone = request.form.get("phone", "").strip()[:20]
        if not full_name or not EMAIL_RE.match(email) or (phone and not PHONE_RE.match(phone)):
            flash("Please enter a valid name, email and phone number.", "error")
        else:
            # user id comes from the session, never from the form -> no IDOR
            execute("UPDATE users SET full_name = %s, email = %s, phone = %s WHERE id = %s",
                    (full_name, email, phone, session["user_id"]))
            flash("Profile updated.", "success")
        return redirect(url_for("profile"))

    user = query("SELECT username, full_name, email, phone, role FROM users WHERE id = %s",
                 (session["user_id"],), one=True)
    return render_template("profile.html", user=user)


@app.errorhandler(413)
def too_large(_e):
    flash("File too large (max 5 MB).", "error")
    return redirect(url_for("assignments"))


if __name__ == "__main__":
    # debug stays off; bind to localhost only
    app.run(host="127.0.0.1", port=5000, debug=False)
