"""
Standalone DB initialiser for the Personal Appointment Management System.

Creates schema (with email-reminder columns) and seeds a default admin
account. Safe to run multiple times — uses CREATE TABLE IF NOT EXISTS and
adds new columns only when missing.

Run:  python init_db.py
"""
import os
import sys
import sqlite3
import bcrypt

# Try to import PostgreSQL, fallback to SQLite
try:
    import psycopg2
    import psycopg2.extras
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False
    print("PostgreSQL not available, using SQLite")

DATABASE = os.path.join(os.path.dirname(__file__), "appointments.db")
BCRYPT_COST = 12

def is_postgres():
    """Check if we're using PostgreSQL (production) or SQLite (development)"""
    return os.environ.get('DATABASE_URL') is not None and POSTGRES_AVAILABLE

def get_db_connection():
    """Get database connection for either SQLite or PostgreSQL"""
    if is_postgres():
        # Production - PostgreSQL
        conn = psycopg2.connect(os.environ['DATABASE_URL'])
        return conn
    else:
        # Development - SQLite
        conn = sqlite3.connect(DATABASE)
        return conn

def create_tables(conn):
    """Create all tables with appropriate SQL for SQLite or PostgreSQL"""
    cursor = conn.cursor()
    is_pg = is_postgres()
    
    # Users table
    if is_pg:
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
    
    # Appointments table
    if is_pg:
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
    
    # Appointment shares table
    if is_pg:
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
    
    # Audit logs table
    if is_pg:
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
    
    conn.commit()
    print("✅ Tables created successfully!")

def add_column_if_missing(conn, table, column, ddl):
    """Add column to SQLite table if missing"""
    if is_postgres():
        # PostgreSQL - check if column exists
        cursor = conn.cursor()
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name=%s AND column_name=%s
        """, (table, column))
        if not cursor.fetchone():
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
            conn.commit()
            print(f"✅ Added column {column} to {table}")
    else:
        # SQLite
        cursor = conn.cursor()
        cursor.execute(f"PRAGMA table_info({table})")
        cols = [row[1] for row in cursor.fetchall()]
        if column not in cols:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
            conn.commit()
            print(f"✅ Added column {column} to {table}")

def seed_admin_user(conn):
    """Create default admin user if not exists"""
    cursor = conn.cursor()
    is_pg = is_postgres()
    
    # Check if admin exists
    if is_pg:
        cursor.execute("SELECT id FROM users WHERE username = %s", ("admin",))
    else:
        cursor.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    
    if cursor.fetchone() is None:
        pw = bcrypt.hashpw(b"Admin@1234", bcrypt.gensalt(BCRYPT_COST)).decode()
        if is_pg:
            cursor.execute(
                "INSERT INTO users (username, password_hash, role, email, receive_email_reminders) VALUES (%s, %s, %s, %s, %s)",
                ("admin", pw, "admin", "admin@example.com", True)
            )
        else:
            cursor.execute(
                "INSERT INTO users (username, password_hash, role, email, receive_email_reminders) VALUES (?,?,?,?,?)",
                ("admin", pw, "admin", "admin@example.com", 1)
            )
        conn.commit()
        print("✅ Default admin user created: admin / Admin@1234")
    else:
        print("ℹ️ Admin user already exists")

def init_db():
    """Initialize database with tables and default admin user"""
    print(f"🚀 Initializing database...")
    print(f"📊 Using {'PostgreSQL' if is_postgres() else 'SQLite'}")
    
    conn = get_db_connection()
    
    try:
        # Create tables
        create_tables(conn)
        
        # Add missing columns for backward compatibility
        if not is_postgres():
            # Only for SQLite - PostgreSQL handles columns in CREATE TABLE
            add_column_if_missing(conn, "appointments", "reminder_sent_24h",
                                "reminder_sent_24h INTEGER NOT NULL DEFAULT 0")
            add_column_if_missing(conn, "appointments", "reminder_sent_1h",
                                "reminder_sent_1h INTEGER NOT NULL DEFAULT 0")
            add_column_if_missing(conn, "users", "receive_email_reminders",
                                "receive_email_reminders INTEGER NOT NULL DEFAULT 1")
            add_column_if_missing(conn, "users", "email", "email TEXT")
        
        # Seed admin user
        seed_admin_user(conn)
        
        print(f"✅ Database initialized successfully!")
        
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()

if __name__ == "__main__":
    init_db()