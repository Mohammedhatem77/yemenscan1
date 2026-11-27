"""
Database Configuration Module for YemenScan.

Configures SQLAlchemy engine, session factory, declarative base,
and provides a FastAPI dependency for database session management.

Design rules:
- PostgreSQL is the PRIMARY and ONLY catalog database.
- Silent fallback to SQLite for PostgreSQL connections is PROHIBITED.
  Any PostgreSQL connection failure raises immediately with a clear error.
- SQLite is ONLY used in automated tests that explicitly pass a SQLite URL.
- The 'fuzzing:' key in Nuclei DAST templates is a Nuclei DSL section, not a protocol.
"""

import os
from typing import Generator
from dotenv import load_dotenv
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# Load environment variables from .env file
load_dotenv()

# Retrieve database connection string from environment
RAW_DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

def _resolve_database_engine():
    global DATABASE_URL
    raw_url = os.getenv("DATABASE_URL", RAW_DATABASE_URL).strip()
    if raw_url:
        db_url = raw_url
    else:
        db_url = "sqlite:///yemenscan.db"

    # Automatically adapt generic postgresql:// to postgresql+psycopg2:// or postgresql+psycopg:// for SQLAlchemy 2.0+
    if db_url.startswith("postgresql://"):
        try:
            import psycopg2
            db_url = db_url.replace("postgresql://", "postgresql+psycopg2://", 1)
        except ImportError:
            try:
                import psycopg
                db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)
            except ImportError:
                db_url = db_url.replace("postgresql://", "postgresql+psycopg2://", 1)
    elif "postgresql+psycopg2://" in db_url:
        try:
            import psycopg2
        except ImportError:
            try:
                import psycopg
                db_url = db_url.replace("postgresql+psycopg2://", "postgresql+psycopg://", 1)
            except ImportError:
                pass

    # Auto-adapt localhost -> db when running inside Docker container network
    if "localhost:5432" in db_url or "127.0.0.1:5432" in db_url:
        try:
            import socket
            socket.gethostbyname("db")
            db_url = db_url.replace("localhost:5432", "db:5432").replace("127.0.0.1:5432", "db:5432")
        except Exception:
            pass

    DATABASE_URL = db_url

    c_args = {}
    engine_kwargs = {
        "echo": False,
        "pool_pre_ping": True,
    }

    if db_url.startswith("sqlite"):
        c_args["check_same_thread"] = False
        engine_kwargs["connect_args"] = c_args
    else:
        # PostgreSQL Connection Pool and Timeout configuration
        c_args["connect_timeout"] = 10
        engine_kwargs["pool_size"] = 10
        engine_kwargs["max_overflow"] = 20
        engine_kwargs["pool_recycle"] = 1800
        engine_kwargs["connect_args"] = c_args

    # NOTE: No silent SQLite fallback for PostgreSQL connections.
    # If PostgreSQL is configured and fails, we raise immediately so the
    # operator knows the catalog is unavailable — silent fallback would
    # corrupt the catalog integrity guarantees.
    try:
        eng = create_engine(db_url, **engine_kwargs)
        # Test connection if PostgreSQL
        if not db_url.startswith("sqlite"):
            with eng.connect() as conn:
                pass
        return eng
    except Exception as err:
        if db_url.startswith("sqlite"):
            raise RuntimeError(f"[!] Database Error: Failed to connect to SQLite: {err}") from err
        # PostgreSQL failure — HARD FAIL, no silent SQLite fallback
        raise RuntimeError(
            f"[!] Database Error: Cannot connect to PostgreSQL at '{db_url}': {err}. "
            "PostgreSQL is required for the YemScan template catalog. "
            "Check Docker container status and DATABASE_URL configuration."
        ) from err

@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable SQLite foreign key constraints for cascade deletions."""
    if dbapi_connection.__class__.__module__.startswith("sqlite"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

DATABASE_URL = ""
engine = _resolve_database_engine()

# SessionLocal class factory for generating scoped sessions
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Base class for all ORM models
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency yielding a SQLAlchemy database session.
    Ensures that the session is properly closed after each request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
