"""
alembic/env.py

Alembic migration environment supporting both SQLite (local/dev) and PostgreSQL (production).
Normalizes Render/Heroku 'postgres://' URLs to 'postgresql://' and enables batch mode for SQLite.
"""

from logging.config import fileConfig
import os
import sys

from sqlalchemy import engine_from_config, pool
from alembic import context

# Ensure backend root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import settings
from app.database import Base
# Import all ORM models so Base.metadata is fully populated
import app.models  # noqa: F401

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _get_database_url() -> str:
    # Allow explicit override via -x db_url=... for offline/CI verification
    x_args = context.get_x_argument(as_dictionary=True)
    raw_url = x_args.get("db_url") or os.environ.get("ALEMBIC_DATABASE_URL") or settings.database_url
    if raw_url.startswith("postgres://"):
        raw_url = raw_url.replace("postgres://", "postgresql://", 1)
    return raw_url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emits dialect-specific SQL without live DB connection)."""
    url = _get_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=url.startswith("sqlite"),
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode against a live SQLite or PostgreSQL database."""
    url = _get_database_url()
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = url

    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=url.startswith("sqlite"),
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
