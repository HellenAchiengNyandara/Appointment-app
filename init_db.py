"""
Standalone DB initialiser for the Personal Appointment Management System.

Creates schema (with email-reminder columns) and seeds a default admin
account. Safe to run multiple times — uses CREATE TABLE IF NOT EXISTS and
adds new columns only when missing.

Run:  python init_db.py
"""
import os
import sqlite3
import bcrypt

DATABASE = os.path.join(os.path.dirname(__file__), "appointments.db")
BCRYPT_COST = 12

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    receive_email_reminders INTEGER NOT NULL DEFAULT 1,
    email TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

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
);

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
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    details TEXT,
    ip_address TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
"""


def _add_column_if_missing(conn, table, column, ddl):
    cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def init_db():
    conn = sqlite3.connect(DATABASE)
    conn.executescript(SCHEMA)

    # Backwards-compatible migrations for existing DBs
    _add_column_if_missing(conn, "appointments", "reminder_sent_24h",
                           "reminder_sent_24h INTEGER NOT NULL DEFAULT 0")
    _add_column_if_missing(conn, "appointments", "reminder_sent_1h",
                           "reminder_sent_1h INTEGER NOT NULL DEFAULT 0")
    _add_column_if_missing(conn, "users", "receive_email_reminders",
                           "receive_email_reminders INTEGER NOT NULL DEFAULT 1")
    _add_column_if_missing(conn, "users", "email", "email TEXT")

    # Seed default admin
    cur = conn.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    if cur.fetchone() is None:
        pw = bcrypt.hashpw(b"Admin@1234", bcrypt.gensalt(BCRYPT_COST)).decode()
        conn.execute(
            "INSERT INTO users (username, password_hash, role, email) VALUES (?,?,?,?)",
            ("admin", pw, "admin", "admin@example.com"),
        )
    conn.commit()
    conn.close()
    print(f"Database initialised at {DATABASE}")


if __name__ == "__main__":
    init_db()
