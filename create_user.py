"""
User Management & Provisioning CLI for YemenScan.

Allows administrators and developers to:
- Create or reset users with proper Argon2id password hashing.
- Assign roles (admin, analyst, viewer).
- Synchronize users across PostgreSQL (Docker) and SQLite.
- List all existing registered users.

Usage:
    python create_user.py                                               # List users or create default admin
    python create_user.py --username analyst1 --password Password123!   # Create analyst
    python create_user.py --username boss --password BossPass123! --role admin
"""

import argparse
import sys
import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Add current directory to path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from models.user import User, UserRole
from core.security import get_password_hash


def get_sqlite_engine():
    return create_engine(
        "sqlite:///yemenscan.db",
        echo=False,
        connect_args={"check_same_thread": False}
    )


def get_postgres_engine():
    db_url = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg2://yemenscan_user:yemenscan_secure_password123@localhost:5432/yemenscan_db"
    )
    if db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "postgresql+psycopg2://", 1)
    return create_engine(db_url, connect_args={"connect_timeout": 5})


def add_or_update_user(engine_target, username, email, password, role="analyst", is_active=True):
    Session = sessionmaker(bind=engine_target)
    session = Session()
    try:
        # Check if users table exists
        User.__table__.create(bind=engine_target, checkfirst=True)

        user = session.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()

        hashed = get_password_hash(password)
        if user:
            user.username = username
            user.email = email
            user.hashed_password = hashed
            user.role = role
            user.is_active = is_active
            action = "Updated existing"
        else:
            user = User(
                username=username,
                email=email,
                hashed_password=hashed,
                role=role,
                is_active=is_active
            )
            session.add(user)
            action = "Created new"

        session.commit()
        session.refresh(user)
        return True, f"{action} user '{username}' (id={user.id}, role={user.role})"
    except Exception as e:
        session.rollback()
        return False, str(e)
    finally:
        session.close()


def list_users(engine_target, label):
    print(f"\n--- Registered Users in {label} ---")
    Session = sessionmaker(bind=engine_target)
    session = Session()
    try:
        User.__table__.create(bind=engine_target, checkfirst=True)
        users = session.query(User).all()
        if not users:
            print("  (No users found)")
            return []
        for u in users:
            print(f"  [ID: {u.id}] Username: {u.username:<16} Email: {u.email:<25} Role: {u.role:<10} Active: {u.is_active}")
        return users
    except Exception as e:
        print(f"  Could not read {label}: {e}")
        return []
    finally:
        session.close()


def main():
    parser = argparse.ArgumentParser(description="YemenScan User Provisioning Tool")
    parser.add_argument("--username", "-u", type=str, help="Username to create or update")
    parser.add_argument("--email", "-e", type=str, help="Email address (default: <username>@yemenscan.ye)")
    parser.add_argument("--password", "-p", type=str, help="Account password")
    parser.add_argument("--role", "-r", choices=["admin", "analyst", "viewer"], default="analyst", help="User role (default: analyst)")
    parser.add_argument("--list", "-l", action="store_true", help="List all users")
    args = parser.parse_args()

    sqlite_eng = get_sqlite_engine()

    # If no arguments provided, or --list
    if args.list or (not args.username and not args.password):
        # List users in SQLite
        users_sqlite = list_users(sqlite_eng, "SQLite (yemenscan.db)")

        # Also list in PostgreSQL if accessible
        try:
            pg_eng = get_postgres_engine()
            with pg_eng.connect():
                pass
            list_users(pg_eng, "PostgreSQL (Docker)")
        except Exception as e:
            print(f"\n--- PostgreSQL (Docker) ---: Connection unavailable ({e})")

        if not args.list and not users_sqlite:
            print("\n[*] Initializing default administrator account...")
            args.username = "admin"
            args.email = "admin@yemenscan.ye"
            args.password = "Admin@123456"
            args.role = "admin"

    if args.username and args.password:
        username = args.username.strip().lower()
        email = (args.email or f"{username}@yemenscan.ye").strip().lower()
        password = args.password
        role = args.role

        print(f"\n[*] Provisioning user: {username} ({role})...")

        # 1. Provision in SQLite
        ok_sq, msg_sq = add_or_update_user(sqlite_eng, username, email, password, role)
        print(f"  [SQLite]     : {'SUCCESS' if ok_sq else 'FAILED'} - {msg_sq}")

        # 2. Provision in PostgreSQL (if reachable)
        try:
            pg_eng = get_postgres_engine()
            ok_pg, msg_pg = add_or_update_user(pg_eng, username, email, password, role)
            print(f"  [PostgreSQL] : {'SUCCESS' if ok_pg else 'FAILED'} - {msg_pg}")
        except Exception as e:
            print(f"  [PostgreSQL] : Skipped ({e})")

        print("\n[✔] Provisioning complete! You can now log in with:")
        print(f"    - Username / Email : {username}  (or {email})")
        print(f"    - Password         : {password}")
        print(f"    - Role             : {role}")


if __name__ == "__main__":
    main()
