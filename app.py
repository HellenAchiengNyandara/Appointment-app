"""
Personal Appointment Management System
Flask + SQLite + bcrypt + Jinja2 + Bootstrap 5

Run:
    pip install -r requirements.txt
    python app.py

Then open: http://127.0.0.1:5000

A default admin account is created on first run:
    username: admin
    password: Admin@1234
(Change immediately in production!)
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

# ----------------------------------------------------------------------------
# App configuration
# ----------------------------------------------------------------------------
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # In production set SESSION_COOKIE_SECURE=True (requires HTTPS)
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    WTF_CSRF_TIME_LIMIT=None,
)
csrf = CSRFProtect(app)

# ----------------------------------------------------------------------------
# Flask-Mail configuration
# ----------------------------------------------------------------------------
# For production, set these via environment variables and uncomment SMTP block.
# Example production config:
#   MAIL_SERVER=smtp.gmail.com  MAIL_PORT=587  MAIL_USE_TLS=1
#   MAIL_USERNAME=...  MAIL_PASSWORD=...  MAIL_DEFAULT_SENDER=no-reply@yourdomain
app.config.update(
    MAIL_SERVER=os.environ.get("MAIL_SERVER", "localhost"),
    MAIL_PORT=int(os.environ.get("MAIL_PORT", 25)),
    MAIL_USE_TLS=os.environ.get("MAIL_USE_TLS", "0") == "1",
    MAIL_USERNAME=os.environ.get("MAIL_USERNAME"),
    MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD"),
    MAIL_DEFAULT_SENDER=os.environ.get("MAIL_DEFAULT_SENDER", "no-reply@example.com"),
    # If MAIL_SUPPRESS_SEND is true (default in dev), Flask-Mail won't open any
    # SMTP connection — we instead print the email to the console for testing.
    MAIL_SUPPRESS_SEND=os.environ.get("MAIL_SUPPRESS_SEND", "1") == "1",
)
mail = Mail(app)

DATABASE = os.path.join(os.path.dirname(__file__), "appointments.db")
SESSION_TIMEOUT_MINUTES = 30
BCRYPT_COST = 12

# In-memory rate-limit store: { ip: [timestamps...] }
LOGIN_ATTEMPTS: dict = {}
LOGIN_WINDOW_SECONDS = 5 * 60
LOGIN_MAX_ATTEMPTS = 5


# ----------------------------------------------------------------------------
# Database helpers
# ----------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    # Schema + seed admin + reminder columns are all handled by init_db.py.
    # We import lazily to avoid a circular dependency at module load time.
    from init_db import init_db as _init
    _init()


# ----------------------------------------------------------------------------
# Audit logging
# ----------------------------------------------------------------------------
def log_action(action: str, details: str = "", user_id=None) -> None:
    if user_id is None:
        user_id = session.get("user_id")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    db = get_db()
    db.execute(
        "INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES (?,?,?,?)",
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
        # Session timeout check
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
        existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            flash("Username already taken.", "danger")
        else:
            pw_hash = bcrypt.hashpw(form.password.data.encode(),
                                    bcrypt.gensalt(BCRYPT_COST)).decode()
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
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
        user = db.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if user and bcrypt.checkpw(form.password.data.encode(), user["password_hash"].encode()):
            # Regenerate session
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


# ----------------------------------------------------------------------------
# Appointments
# ----------------------------------------------------------------------------
def _appointment_overlaps(db, owner_id, start, end, exclude_id=None) -> bool:
    q = """
        SELECT id FROM appointments
        WHERE owner_id = ?
          AND NOT (end_datetime <= ? OR start_datetime >= ?)
    """
    params = [owner_id, start, end]
    if exclude_id:
        q += " AND id != ?"
        params.append(exclude_id)
    return db.execute(q, params).fetchone() is not None


def _get_appointment_with_access(appt_id: int):
    """Return (appt_row, permission) where permission in {'owner','edit','view',None}."""
    db = get_db()
    appt = db.execute("SELECT * FROM appointments WHERE id = ?", (appt_id,)).fetchone()
    if not appt:
        return None, None
    uid = session.get("user_id")
    if appt["owner_id"] == uid:
        return appt, "owner"
    if session.get("role") == "admin":
        return appt, "admin"
    share = db.execute(
        "SELECT permission FROM appointment_shares WHERE appointment_id = ? AND shared_with_user_id = ?",
        (appt_id, uid),
    ).fetchone()
    if share:
        return appt, share["permission"]
    return appt, None


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    uid = session["user_id"]
    role = session["role"]

    own = []
    if role != "guest":
        own = db.execute(
            """SELECT * FROM appointments
               WHERE owner_id = ? AND end_datetime >= datetime('now')
               ORDER BY start_datetime ASC""",
            (uid,),
        ).fetchall()

    shared = db.execute(
        """SELECT a.*, s.permission, u.username AS owner_name
           FROM appointment_shares s
           JOIN appointments a ON a.id = s.appointment_id
           JOIN users u ON u.id = a.owner_id
           WHERE s.shared_with_user_id = ? AND a.end_datetime >= datetime('now')
           ORDER BY a.start_datetime ASC""",
        (uid,),
    ).fetchall()

    return render_template("dashboard.html", own=own, shared=shared,
                           csrf_form=CSRFOnlyForm())


@app.route("/appointments/new", methods=["GET", "POST"])
@login_required
def appointment_new():
    if session.get("role") == "guest":
        abort(403)
    form = AppointmentForm()
    if form.validate_on_submit():
        db = get_db()
        uid = session["user_id"]
        start = form.start_datetime.data.strftime("%Y-%m-%d %H:%M:%S")
        end = form.end_datetime.data.strftime("%Y-%m-%d %H:%M:%S")
        if _appointment_overlaps(db, uid, start, end):
            flash("This appointment overlaps with an existing one.", "danger")
        else:
            cur = db.execute(
                """INSERT INTO appointments (title, description, start_datetime, end_datetime, owner_id)
                   VALUES (?,?,?,?,?)""",
                (form.title.data, form.description.data, start, end, uid),
            )
            db.commit()
            log_action("CREATE_APPOINTMENT", f"id={cur.lastrowid} title={form.title.data}")
            flash("Appointment created.", "success")
            return redirect(url_for("dashboard"))
    return render_template("appointment_form.html", form=form, mode="Create")


@app.route("/appointments/<int:appt_id>/edit", methods=["GET", "POST"])
@login_required
def appointment_edit(appt_id):
    appt, perm = _get_appointment_with_access(appt_id)
    if not appt:
        abort(404)
    if perm not in ("owner", "edit", "admin"):
        log_action("ACCESS_DENIED", f"edit appointment={appt_id}")
        abort(403)

    form = AppointmentForm(data={
        "title": appt["title"],
        "description": appt["description"],
        "start_datetime": datetime.strptime(appt["start_datetime"], "%Y-%m-%d %H:%M:%S"),
        "end_datetime": datetime.strptime(appt["end_datetime"], "%Y-%m-%d %H:%M:%S"),
    })
    if form.validate_on_submit():
        db = get_db()
        start = form.start_datetime.data.strftime("%Y-%m-%d %H:%M:%S")
        end = form.end_datetime.data.strftime("%Y-%m-%d %H:%M:%S")
        if _appointment_overlaps(db, appt["owner_id"], start, end, exclude_id=appt_id):
            flash("This appointment overlaps with another one for the owner.", "danger")
        else:
            db.execute(
                """UPDATE appointments
                   SET title=?, description=?, start_datetime=?, end_datetime=?, updated_at=CURRENT_TIMESTAMP
                   WHERE id=?""",
                (form.title.data, form.description.data, start, end, appt_id),
            )
            db.commit()
            log_action("EDIT_APPOINTMENT", f"id={appt_id}")
            flash("Appointment updated.", "success")
            return redirect(url_for("dashboard"))
    return render_template("appointment_form.html", form=form, mode="Edit")


@app.route("/appointments/<int:appt_id>/delete", methods=["POST"])
@login_required
def appointment_delete(appt_id):
    form = CSRFOnlyForm()
    if not form.validate_on_submit():
        abort(400)
    appt, perm = _get_appointment_with_access(appt_id)
    if not appt:
        abort(404)
    if perm not in ("owner", "admin"):
        log_action("ACCESS_DENIED", f"delete appointment={appt_id}")
        abort(403)
    db = get_db()
    db.execute("DELETE FROM appointments WHERE id = ?", (appt_id,))
    db.commit()
    log_action("DELETE_APPOINTMENT", f"id={appt_id}")
    flash("Appointment deleted.", "info")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/appointments/<int:appt_id>/share", methods=["GET", "POST"])
@login_required
def appointment_share(appt_id):
    appt, perm = _get_appointment_with_access(appt_id)
    if not appt:
        abort(404)
    if perm != "owner":
        log_action("ACCESS_DENIED", f"share appointment={appt_id}")
        abort(403)
    form = ShareForm()
    if form.validate_on_submit():
        db = get_db()
        target = db.execute("SELECT id, username FROM users WHERE username = ?",
                            (form.username.data.strip(),)).fetchone()
        if not target:
            flash("User not found.", "danger")
        elif target["id"] == session["user_id"]:
            flash("You cannot share with yourself.", "warning")
        else:
            existing = db.execute(
                "SELECT id FROM appointment_shares WHERE appointment_id=? AND shared_with_user_id=?",
                (appt_id, target["id"]),
            ).fetchone()
            if existing:
                db.execute(
                    "UPDATE appointment_shares SET permission=?, shared_by_user_id=?, shared_at=CURRENT_TIMESTAMP WHERE id=?",
                    (form.permission.data, session["user_id"], existing["id"]),
                )
            else:
                db.execute(
                    """INSERT INTO appointment_shares
                       (appointment_id, shared_with_user_id, permission, shared_by_user_id)
                       VALUES (?,?,?,?)""",
                    (appt_id, target["id"], form.permission.data, session["user_id"]),
                )
            db.commit()
            log_action("SHARE_APPOINTMENT",
                       f"appointment={appt_id} with={target['username']} perm={form.permission.data}")
            flash(f"Shared with {target['username']}.", "success")
            return redirect(url_for("dashboard"))

    db = get_db()
    shares = db.execute(
        """SELECT s.id, s.permission, u.username
           FROM appointment_shares s JOIN users u ON u.id = s.shared_with_user_id
           WHERE s.appointment_id = ?""", (appt_id,)).fetchall()
    return render_template("share.html", form=form, appt=appt, shares=shares)


# ----------------------------------------------------------------------------
# Admin
# ----------------------------------------------------------------------------
@app.route("/admin")
@role_required("admin")
def admin_dashboard():
    db = get_db()
    users = db.execute(
        "SELECT id, username, role, created_at FROM users ORDER BY created_at DESC"
    ).fetchall()
    role_form = RoleForm()
    return render_template("admin.html", users=users, role_form=role_form,
                           csrf_form=CSRFOnlyForm())


@app.route("/admin/role", methods=["POST"])
@role_required("admin")
def admin_change_role():
    form = RoleForm()
    if form.validate_on_submit():
        uid = int(form.user_id.data)
        new_role = form.role.data
        if new_role not in ("user", "admin"):
            abort(400)
        if uid == session["user_id"] and new_role != "admin":
            flash("You cannot demote yourself.", "warning")
            return redirect(url_for("admin_dashboard"))
        db = get_db()
        db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, uid))
        db.commit()
        log_action("CHANGE_ROLE", f"user={uid} new_role={new_role}")
        flash("Role updated.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/logs")
@role_required("admin")
def admin_logs():
    user_filter = request.args.get("user_id", "").strip()
    action_filter = request.args.get("action", "").strip()

    query = """
        SELECT l.id, l.user_id, u.username, l.action, l.details, l.ip_address, l.timestamp
        FROM audit_logs l LEFT JOIN users u ON u.id = l.user_id
        WHERE 1=1
    """
    params = []
    if user_filter.isdigit():
        query += " AND l.user_id = ?"
        params.append(int(user_filter))
    if action_filter:
        query += " AND l.action = ?"
        params.append(action_filter)
    query += " ORDER BY l.timestamp DESC LIMIT 500"

    db = get_db()
    logs = db.execute(query, params).fetchall()
    actions = db.execute("SELECT DISTINCT action FROM audit_logs ORDER BY action").fetchall()
    return render_template("admin_logs.html", logs=logs, actions=actions,
                           user_filter=user_filter, action_filter=action_filter)


# ----------------------------------------------------------------------------
# Calendar JSON API (RBAC respected)
# ----------------------------------------------------------------------------
@app.route("/api/appointments")
@login_required
def api_appointments():
    """Return all appointments visible to the logged-in user as FullCalendar
    event objects. RBAC is enforced — guests see only shared events; users see
    own + shared; admins see all (so they can moderate from the calendar)."""
    db = get_db()
    uid = session["user_id"]
    role = session["role"]
    events = []

    def _iso(s):
        # Stored as 'YYYY-MM-DD HH:MM:SS' — FullCalendar accepts ISO 8601.
        return s.replace(" ", "T") if s else s

    if role == "admin":
        rows = db.execute(
            """SELECT a.*, u.username AS owner_name
               FROM appointments a JOIN users u ON u.id = a.owner_id"""
        ).fetchall()
        for a in rows:
            events.append({
                "id": a["id"], "title": a["title"],
                "start": _iso(a["start_datetime"]), "end": _iso(a["end_datetime"]),
                "color": "#3b82f6",
                "extendedProps": {
                    "description": a["description"], "owner": a["owner_name"],
                    "permission": "admin", "can_edit": True,
                },
            })
    else:
        if role != "guest":
            own_rows = db.execute(
                "SELECT * FROM appointments WHERE owner_id = ?", (uid,)
            ).fetchall()
            for a in own_rows:
                events.append({
                    "id": a["id"], "title": a["title"],
                    "start": _iso(a["start_datetime"]), "end": _iso(a["end_datetime"]),
                    "color": "#3b82f6",
                    "extendedProps": {
                        "description": a["description"],
                        "owner": session["username"], "permission": "owner",
                        "can_edit": True,
                    },
                })

        shared_rows = db.execute(
            """SELECT a.*, s.permission, u.username AS owner_name
               FROM appointment_shares s
               JOIN appointments a ON a.id = s.appointment_id
               JOIN users u ON u.id = a.owner_id
               WHERE s.shared_with_user_id = ?""",
            (uid,),
        ).fetchall()
        for a in shared_rows:
            can_edit = (a["permission"] == "edit" and role != "guest")
            events.append({
                "id": a["id"],
                "title": f"{a['title']} (shared by {a['owner_name']})",
                "start": _iso(a["start_datetime"]), "end": _iso(a["end_datetime"]),
                "color": "#f97316" if a["permission"] == "edit" else "#22c55e",
                "extendedProps": {
                    "description": a["description"], "owner": a["owner_name"],
                    "permission": a["permission"], "can_edit": can_edit,
                },
            })

    return jsonify(events)


@app.route("/calendar-view-log", methods=["POST"])
@login_required
def calendar_view_log():
    """Lightweight endpoint for the dashboard to log a single 'calendar view'
    audit event (avoids logging every API poll)."""
    form = CSRFOnlyForm()
    if not form.validate_on_submit():
        abort(400)
    log_action("VIEW_CALENDAR", "user opened calendar dashboard")
    return ("", 204)


# ----------------------------------------------------------------------------
# User profile (email + reminder preferences)
# ----------------------------------------------------------------------------
class ProfileForm(FlaskForm):
    email = EmailField("Email", validators=[OptionalValidator(), EmailValidator(), Length(0, 200)])
    receive_email_reminders = BooleanField("Receive email reminders")


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    db = get_db()
    uid = session["user_id"]
    user = db.execute(
        "SELECT id, username, role, email, receive_email_reminders FROM users WHERE id = ?",
        (uid,),
    ).fetchone()
    if not user:
        abort(404)

    if request.method == "POST":
        form = ProfileForm()
        if form.validate_on_submit():
            email = (form.email.data or "").strip() or None
            recv = 1 if form.receive_email_reminders.data else 0
            db.execute(
                "UPDATE users SET email = ?, receive_email_reminders = ? WHERE id = ?",
                (email, recv, uid),
            )
            db.commit()
            log_action("UPDATE_PROFILE", f"email_set={bool(email)} reminders={recv}")
            flash("Profile updated.", "success")
            return redirect(url_for("profile"))

    return render_template("profile.html", user=user)


# ----------------------------------------------------------------------------
# Email reminders
# ----------------------------------------------------------------------------
def _send_reminder_email(to_email: str, appt_row, kind: str) -> None:
    """Send (or, in dev mode, print) a reminder email for an appointment.

    `kind` is '24h' or '1h' — used in the subject line.
    When MAIL_SUPPRESS_SEND is true (default for demo), we print to stdout
    with a clear marker so it's obvious during testing."""
    subject = f"[Reminder] {appt_row['title']} — starts in {kind}"
    body = (
        f"Hello,\n\n"
        f"This is a reminder for your upcoming appointment.\n\n"
        f"Title:       {appt_row['title']}\n"
        f"Description: {appt_row['description'] or '(none)'}\n"
        f"Start:       {appt_row['start_datetime']}\n"
        f"End:         {appt_row['end_datetime']}\n\n"
        f"— Personal Appointment Manager"
    )

    if app.config.get("MAIL_SUPPRESS_SEND"):
        # Demo mode — don't actually send, just print clearly.
        print(f"[EMAIL REMINDER] To: {to_email} - "
              f"Appointment: {appt_row['title']} at {appt_row['start_datetime']} ({kind})")
        print(body)
        print("-" * 60)
        return

    msg = Message(subject=subject, recipients=[to_email], body=body)
    mail.send(msg)


def process_due_reminders() -> dict:
    """Find appointments needing 24h / 1h reminders, send them, and mark
    them as sent. Returns counts. Idempotent — uses reminder_sent_* flags."""
    db = get_db()
    now = datetime.now()
    sent_24h = 0
    sent_1h = 0

    # 24-hour window: appointments starting between now+23h and now+25h that
    # haven't yet had a 24h reminder sent.
    rows_24h = db.execute(
        """SELECT a.*, u.email, u.username, u.receive_email_reminders
           FROM appointments a JOIN users u ON u.id = a.owner_id
           WHERE a.reminder_sent_24h = 0
             AND a.start_datetime BETWEEN ? AND ?""",
        ((now + timedelta(hours=23)).strftime("%Y-%m-%d %H:%M:%S"),
         (now + timedelta(hours=25)).strftime("%Y-%m-%d %H:%M:%S")),
    ).fetchall()
    for a in rows_24h:
        if a["receive_email_reminders"] and a["email"]:
            _send_reminder_email(a["email"], a, "24h")
            log_action("EMAIL_REMINDER_SENT",
                       f"appointment={a['id']} kind=24h to={a['email']}",
                       user_id=a["owner_id"])
            sent_24h += 1
        db.execute("UPDATE appointments SET reminder_sent_24h = 1 WHERE id = ?", (a["id"],))

    # 1-hour window: appointments starting between now+45min and now+75min.
    rows_1h = db.execute(
        """SELECT a.*, u.email, u.username, u.receive_email_reminders
           FROM appointments a JOIN users u ON u.id = a.owner_id
           WHERE a.reminder_sent_1h = 0
             AND a.start_datetime BETWEEN ? AND ?""",
        ((now + timedelta(minutes=45)).strftime("%Y-%m-%d %H:%M:%S"),
         (now + timedelta(minutes=75)).strftime("%Y-%m-%d %H:%M:%S")),
    ).fetchall()
    for a in rows_1h:
        if a["receive_email_reminders"] and a["email"]:
            _send_reminder_email(a["email"], a, "1h")
            log_action("EMAIL_REMINDER_SENT",
                       f"appointment={a['id']} kind=1h to={a['email']}",
                       user_id=a["owner_id"])
            sent_1h += 1
        db.execute("UPDATE appointments SET reminder_sent_1h = 1 WHERE id = ?", (a["id"],))

    db.commit()
    return {"sent_24h": sent_24h, "sent_1h": sent_1h}


@app.route("/send-reminders", methods=["POST"])
@role_required("admin")
def send_reminders():
    """Admin-triggered manual reminder dispatch (Option A from the spec).
    For automation (Option B), APScheduler can call process_due_reminders
    every hour — see commented bootstrap block at the bottom of this file."""
    csrf_form = CSRFOnlyForm()
    if not csrf_form.validate_on_submit():
        abort(400)
    counts = process_due_reminders()
    flash(f"Reminders dispatched: {counts['sent_24h']} (24h) + "
          f"{counts['sent_1h']} (1h).", "success")
    return redirect(url_for("admin_dashboard"))


# ----------------------------------------------------------------------------
# Error handlers
# ----------------------------------------------------------------------------
@app.errorhandler(403)
def err_403(_e):
    return render_template("error.html", code=403, message="Access denied."), 403


@app.errorhandler(404)
def err_404(_e):
    return render_template("error.html", code=404, message="Not found."), 404


# ----------------------------------------------------------------------------
# Bootstrap DB on startup
# ----------------------------------------------------------------------------
with app.app_context():
    init_db()


# ----------------------------------------------------------------------------
# Optional Option B — APScheduler background job (uncomment to enable).
# Runs process_due_reminders() every hour. Disabled by default so the demo
# stays predictable; admins can trigger /send-reminders manually instead.
# ----------------------------------------------------------------------------
# from apscheduler.schedulers.background import BackgroundScheduler
# def _scheduled_reminders():
#     with app.app_context():
#         process_due_reminders()
# scheduler = BackgroundScheduler(daemon=True)
# scheduler.add_job(_scheduled_reminders, "interval", hours=1, id="reminders")
# scheduler.start()


if __name__ == "__main__":
    app.run(debug=True)
