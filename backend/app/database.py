"""
app/database.py

SQLAlchemy database setup.

Design decisions:
- Uses synchronous sessions for MVP simplicity.
- check_same_thread=False is required for SQLite only; PostgreSQL ignores it.
- get_db() is a FastAPI dependency that opens a session per request and
  always closes it in the finally block — prevents connection leaks.
- When switching to PostgreSQL, change only DATABASE_URL in .env.
  No code changes required.
"""

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from app.config import settings
import sys


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
raw_db_url = settings.database_url
# Render & Heroku provide postgres:// URLs; SQLAlchemy 2.0+ requires postgresql://
if raw_db_url.startswith("postgres://"):
    raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)

connect_args = {}
if raw_db_url.startswith("sqlite"):
    # Required for SQLite to work with FastAPI's thread model
    connect_args["check_same_thread"] = False

engine = create_engine(
    raw_db_url,
    connect_args=connect_args,
    # Emit SQL to stderr only in development AND not during pytest runs
    echo=(settings.app_env == "development" and "pytest" not in sys.modules),
)

# ---------------------------------------------------------------------------
# SQLite: enforce foreign-key constraints (disabled by default in SQLite)
# ---------------------------------------------------------------------------
if raw_db_url.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


# ---------------------------------------------------------------------------
# Base class for all ORM models
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# FastAPI dependency — yields one DB session per request
# ---------------------------------------------------------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
