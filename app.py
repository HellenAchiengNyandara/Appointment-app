"""
Personal Appointment Management System
Flask + SQLite/PostgreSQL + bcrypt + Jinja2 + Bootstrap 5
"""
import os
import re
import sqlite3
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
from flask import (
    Flask, g, render_template, request, redirect, url_for,
    session, flash, abort
)
from flask import jsonify
from flask_wtf import FlaskForm, CSRFProtect
from flask_mail import Mail, Message
from wtforms import StringField, PasswordField, TextAreaField, SelectField, DateTimeLocalField, HiddenField, BooleanField, EmailField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, Optional as OptionalValidator, Email as EmailValidator

# Try to import PostgreSQL
try:
    import psycopg2
    import psycopg2.extras
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False
    print("PostgreSQL not available, using SQLite")

# ----------------------------------------------------------------------------
# App configuration
# ----------------------------------------------------------------------------
app = Flask(__name__)

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    print(f"WARNING: Using generated SECRET_KEY")

app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    WTF_CSRF_TIME_LIMIT=None,
)
csrf = CSRFProtect(app)

# ----------------------------------------------------------------------------
# Flask-Mail configuration
# ----------------------------------------------------------------------------
app.config.update(
    MAIL_SERVER=os.environ.get("MAIL_SERVER", "localhost"),
    MAIL_PORT=int(os.environ.get("MAIL_PORT", 25)),
    MAIL_USE_TLS=os.environ.get("MAIL_USE_TLS", "0") == "1",
    MAIL_USERNAME=os.environ.get("MAIL_USERNAME"),
    MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD"),
    MAIL_DEFAULT_SENDER=os.environ.get("MAIL_DEFAULT_SENDER", "no-reply@example.com"),
    MAIL_SUPPRESS_SEND=os.environ.get("MAIL_SUPPRESS_SEND", "1") == "1",
)
mail = Mail(app)

DATABASE = os.path.join(os.path.dirname(__file__), "appointments.db")
SESSION_TIMEOUT_MINUTES = 30
BCRYPT_COST = 12

LOGIN_ATTEMPTS: dict = {}
LOGIN_WINDOW_SECONDS = 5 * 60
LOGIN_MAX_ATTEMPTS = 5

def is_postgres():
    """Check if we should use PostgreSQL"""
    return os.environ.get('DATABASE_URL') is not None and POSTGRES_AVAILABLE

# ----------------------------------------------------------------------------
# Database helpers
# ----------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        if is_postgres():
            # Production - PostgreSQL
            print("✅ Using PostgreSQL database")
            g.db = psycopg2.connect(os.environ['DATABASE_URL'])
            def dict_factory(cursor, row):
                return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}
            g.db.row_factory = dict_factory
        else:
            # Development - SQLite
            print("✅ Using SQLite database")
            g.db = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def get_placeholder():
    """Return the correct placeholder for the current database"""
    return "%s" if is_postgres() else "?"

def init_db():
    """Initialize database with tables and default admin user"""
    print("🚀 Initializing database...")
    print(f"📊 Using {'PostgreSQL' if is_postgres() else 'SQLite'}")
    
    db = get_db()
    cursor = db.cursor()
    placeholder = get_placeholder()
    
    # Create users table
    if is_postgres():
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role VARCHAR(20) DEFAULT 'user',
                email VARCHAR(200),
                receive_email_reminders BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    else:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                receive_email_reminders INTEGER NOT NULL DEFAULT 1,
                email TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
    
    # Create appointments table
    if is_postgres():
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS appointments (
                id SERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                start_datetime TIMESTAMP NOT NULL,
                end_datetime TIMESTAMP NOT NULL,
                owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                reminder_sent_24h BOOLEAN DEFAULT FALSE,
                reminder_sent_1h BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    else:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                start_datetime DATETIME NOT NULL,
                end_datetime DATETIME NOT NULL,
                owner_id INTEGER NOT NULL,
                reminder_sent_24h INTEGER NOT NULL DEFAULT 0,
                reminder_sent_1h INTEGER NOT NULL DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
    
    # Create appointment_shares table
    if is_postgres():
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS appointment_shares (
                id SERIAL PRIMARY KEY,
                appointment_id INTEGER NOT NULL REFERENCES appointments(id) ON DELETE CASCADE,
                shared_with_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                permission VARCHAR(20) NOT NULL DEFAULT 'view',
                shared_by_user_id INTEGER NOT NULL REFERENCES users(id),
                shared_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(appointment_id, shared_with_user_id)
            )
        """)
    else:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS appointment_shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                appointment_id INTEGER NOT NULL,
                shared_with_user_id INTEGER NOT NULL,
                permission TEXT NOT NULL CHECK(permission IN ('view','edit')),
                shared_by_user_id INTEGER NOT NULL,
                shared_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (appointment_id) REFERENCES appointments(id) ON DELETE CASCADE,
                FOREIGN KEY (shared_with_user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (shared_by_user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
    
    # Create audit_logs table
    if is_postgres():
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    else:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
    
    db.commit()
    print("✅ Tables created successfully!")
    
    # Create default admin user if not exists
    admin_username = "admin"
    admin_password = "Admin@1234"
    
    cursor.execute(f"SELECT id FROM users WHERE username = {placeholder}", (admin_username,))
    if not cursor.fetchone():
        pw_hash = bcrypt.hashpw(admin_password.encode(), bcrypt.gensalt(12)).decode()
        if is_postgres():
            cursor.execute(
                f"INSERT INTO users (username, password_hash, role, email, receive_email_reminders) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder})",
                (admin_username, pw_hash, "admin", "admin@example.com", True)
            )
        else:
            cursor.execute(
                f"INSERT INTO users (username, password_hash, role, email, receive_email_reminders) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder})",
                (admin_username, pw_hash, "admin", "admin@example.com", 1)
            )
        db.commit()
        print("✅ Default admin user created: admin / Admin@1234")
    else:
        print("ℹ️ Admin user already exists")
    
    print("✅ Database initialized successfully!")

# ----------------------------------------------------------------------------
# Audit logging
# ----------------------------------------------------------------------------
def log_action(action: str, details: str = "", user_id=None) -> None:
    if user_id is None:
        user_id = session.get("user_id")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    db = get_db()
    cursor = db.cursor()
    placeholder = get_placeholder()
    cursor.execute(
        f"INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES ({placeholder},{placeholder},{placeholder},{placeholder})",
        (user_id, action, details, ip),
    )
    db.commit()

# ----------------------------------------------------------------------------
# Password / validation helpers
# ----------------------------------------------------------------------------
PASSWORD_RE = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_\-+=\[\]{};:'\",.<>/?\\|`~]).{8,}$"
)

def validate_password_policy(pw: str) -> bool:
    return bool(PASSWORD_RE.match(pw or ""))

# ----------------------------------------------------------------------------
# Auth / RBAC decorators
# ----------------------------------------------------------------------------
def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login"))
        last = session.get("last_active")
        now = time.time()
        if last and now - last > SESSION_TIMEOUT_MINUTES * 60:
            session.clear()
            flash("Session expired. Please log in again.", "warning")
            return redirect(url_for("login"))
        session["last_active"] = now
        return fn(*a, **kw)
    return wrapper

def role_required(*roles):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapper(*a, **kw):
            if session.get("role") not in roles:
                log_action("ACCESS_DENIED", f"path={request.path} required={roles}")
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco

# ----------------------------------------------------------------------------
# Forms (CSRF via Flask-WTF)
# ----------------------------------------------------------------------------
class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(3, 50)])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm = PasswordField("Confirm Password",
                            validators=[DataRequired(), EqualTo("password", "Passwords must match")])

    def validate_password(self, field):
        if not validate_password_policy(field.data):
            raise ValidationError(
                "Password must be 8+ chars and include upper, lower, digit, and special character."
            )

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(1, 50)])
    password = PasswordField("Password", validators=[DataRequired()])

class AppointmentForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(1, 200)])
    description = TextAreaField("Description", validators=[Length(0, 2000)])
    start_datetime = DateTimeLocalField("Start", format="%Y-%m-%dT%H:%M",
                                        validators=[DataRequired()])
    end_datetime = DateTimeLocalField("End", format="%Y-%m-%dT%H:%M",
                                      validators=[DataRequired()])

    def validate_end_datetime(self, field):
        if self.start_datetime.data and field.data and field.data <= self.start_datetime.data:
            raise ValidationError("End must be after start.")

class ShareForm(FlaskForm):
    username = StringField("Share with (username)", validators=[DataRequired(), Length(1, 50)])
    permission = SelectField("Permission",
                             choices=[("view", "View only"), ("edit", "Can edit")],
                             validators=[DataRequired()])

class RoleForm(FlaskForm):
    user_id = HiddenField(validators=[DataRequired()])
    role = SelectField("Role", choices=[("user", "user"), ("admin", "admin")],
                       validators=[DataRequired()])

class CSRFOnlyForm(FlaskForm):
    pass

# ----------------------------------------------------------------------------
# Rate limiting helper
# ----------------------------------------------------------------------------
def check_login_rate_limit(ip: str) -> bool:
    now = time.time()
    bucket = [t for t in LOGIN_ATTEMPTS.get(ip, []) if now - t < LOGIN_WINDOW_SECONDS]
    LOGIN_ATTEMPTS[ip] = bucket
    return len(bucket) < LOGIN_MAX_ATTEMPTS

def record_login_attempt(ip: str) -> None:
    LOGIN_ATTEMPTS.setdefault(ip, []).append(time.time())

# ----------------------------------------------------------------------------
# Context processor
# ----------------------------------------------------------------------------
@app.context_processor
def inject_user():
    return {
        "current_user": {
            "id": session.get("user_id"),
            "username": session.get("username"),
            "role": session.get("role"),
        } if "user_id" in session else None
    }

# ----------------------------------------------------------------------------
# Routes — auth
# ----------------------------------------------------------------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        db = get_db()
        cursor = db.cursor()
        placeholder = get_placeholder()
        existing = cursor.execute(f"SELECT id FROM users WHERE username = {placeholder}", (username,)).fetchone()
        if existing:
            flash("Username already taken.", "danger")
        else:
            pw_hash = bcrypt.hashpw(form.password.data.encode(),
                                    bcrypt.gensalt(BCRYPT_COST)).decode()
            cursor.execute(
                f"INSERT INTO users (username, password_hash, role) VALUES ({placeholder},{placeholder},{placeholder})",
                (username, pw_hash, "user"),
            )
            db.commit()
            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"

    if form.validate_on_submit():
        if not check_login_rate_limit(ip):
            flash("Too many login attempts. Try again later.", "danger")
            log_action("LOGIN", f"rate_limited username={form.username.data}", user_id=None)
            return render_template("login.html", form=form), 429

        record_login_attempt(ip)
        username = form.username.data.strip()
        db = get_db()
        cursor = db.cursor()
        placeholder = get_placeholder()
        user = cursor.execute(
            f"SELECT id, username, password_hash, role FROM users WHERE username = {placeholder}",
            (username,),
        ).fetchone()

        if user and bcrypt.checkpw(form.password.data.encode(), user["password_hash"].encode()):
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["last_active"] = time.time()
            log_action("LOGIN", f"success username={username}", user_id=user["id"])
            flash(f"Welcome, {user['username']}!", "success")
            return redirect(url_for("dashboard"))
        else:
            log_action("LOGIN", f"failed username={username}", user_id=None)
            flash("Invalid username or password.", "danger")

    return render_template("login.html", form=form)

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    log_action("LOGOUT", f"username={session.get('username')}")
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))

# [Rest of your routes - appointments, admin, profile, reminders, etc.]
# Keep all your existing route functions here...

# ----------------------------------------------------------------------------
# Bootstrap DB on startup
# ----------------------------------------------------------------------------
with app.app_context():
    init_db()

# ----------------------------------------------------------------------------
# Production entry point
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)