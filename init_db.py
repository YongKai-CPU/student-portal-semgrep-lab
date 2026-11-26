"""Create the tables and two demo accounts (passwords are typed in, never hard-coded)."""
import getpass
import os

import pymysql
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

conn = pymysql.connect(
    host=os.environ.get("DB_HOST", "localhost"),
    user=os.environ.get("DB_USER", "portal_user"),
    password=os.environ.get("DB_PASSWORD", ""),
    database=os.environ.get("DB_NAME", "student_portal"),
    autocommit=True,
)

with open(os.path.join(BASE_DIR, "schema.sql"), encoding="utf-8") as f:
    statements = [s.strip() for s in f.read().split(";") if s.strip()]

with conn.cursor() as cur:
    for stmt in statements:
        cur.execute(stmt)

    demo_users = [
        ("student1", "student", "Ali Student", "student1@uni.edu.my"),
        ("lecturer1", "lecturer", "Dr Lee Lecturer", "lecturer1@uni.edu.my"),
    ]
    for username, role, name, email in demo_users:
        cur.execute("SELECT id FROM users WHERE username = %s", (username,))
        if cur.fetchone():
            print(f"{username} already exists, skipping")
            continue
        pw = os.environ.get(f"{username.upper()}_PASSWORD") or getpass.getpass(f"Set password for {username}: ")
        cur.execute("INSERT INTO users (username, password_hash, role, full_name, email) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (username, generate_password_hash(pw), role, name, email))
        if role == "student":
            sid = cur.lastrowid
            cur.executemany("INSERT INTO grades (student_id, course, grade) VALUES (%s, %s, %s)",
                            [(sid, "Secure Software Development", "A-"),
                             (sid, "Database Systems", "B+")])
            cur.executemany("INSERT INTO attendance (student_id, course, percentage) VALUES (%s, %s, %s)",
                            [(sid, "Secure Software Development", 92.5),
                             (sid, "Database Systems", 88.0)])

conn.close()
print("Database initialised.")
