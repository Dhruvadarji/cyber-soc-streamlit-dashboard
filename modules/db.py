import sqlite3
from datetime import datetime

DB_NAME = "sessions.db"


# -----------------------
# Create Table (runs once)
# -----------------------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        device TEXT,
        ip TEXT,
        login_time TEXT,
        session_hash TEXT
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        reason TEXT,
        risk INTEGER,
        time TEXT
   )
   """)

    conn.commit()
    conn.close()


# -----------------------
# Insert Login Session
# -----------------------
def insert_session(username, device, ip, session_hash):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO sessions (username, device, ip, login_time, session_hash)
        VALUES (?, ?, ?, ?, ?)
    """, (username, device, ip, str(datetime.now()), session_hash))

    conn.commit()
    conn.close()


# -----------------------
# Fetch All Sessions
# -----------------------
def get_sessions():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT username, device, ip, login_time FROM sessions")

    rows = cursor.fetchall()
    conn.close()

    return rows

def insert_alert(username, reason, risk):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts (username, reason, risk, time)
        VALUES (?, ?, ?, ?)
    """, (username, reason, risk, str(datetime.now())))

    conn.commit()
    conn.close()
