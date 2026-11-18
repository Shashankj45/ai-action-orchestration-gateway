"""Add demo_session_id columns for per-visitor demo session isolation

Revision ID: 0003_add_demo_session_id
Revises: 0002_add_is_demo_columns
Create Date: 2026-11-18
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0003_add_demo_session_id"
down_revision: Union[str, None] = "0002_add_is_demo_columns"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TARGET_TABLES = ("users", "api_registry", "approval_requests", "execution_logs")


def upgrade() -> None:
    """Adds nullable VARCHAR(36) 'demo_session_id' column and index to isolate concurrent demo visitors."""
    if op.get_context().as_sql:
        for table in TARGET_TABLES:
            op.add_column(table, sa.Column("demo_session_id", sa.String(length=36), nullable=True))
            op.create_index(f"ix_{table}_demo_session_id", table, ["demo_session_id"])
        return

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    for table in TARGET_TABLES:
        if table not in existing_tables:
            continue
        cols = {col["name"] for col in inspector.get_columns(table)}
        if "demo_session_id" not in cols:
            with op.batch_alter_table(table) as batch_op:
                batch_op.add_column(sa.Column("demo_session_id", sa.String(length=36), nullable=True))
                batch_op.create_index(f"ix_{table}_demo_session_id", ["demo_session_id"])


def downgrade() -> None:
    """Removes 'demo_session_id' column and index from target tables."""
    if op.get_context().as_sql:
        for table in reversed(TARGET_TABLES):
            op.drop_index(f"ix_{table}_demo_session_id", table_name=table)
            op.drop_column(table, "demo_session_id")
        return

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    for table in reversed(TARGET_TABLES):
        if table not in existing_tables:
            continue
        cols = {col["name"] for col in inspector.get_columns(table)}
        if "demo_session_id" in cols:
            existing_indexes = {idx["name"] for idx in inspector.get_indexes(table)}
            with op.batch_alter_table(table) as batch_op:
                if f"ix_{table}_demo_session_id" in existing_indexes:
                    batch_op.drop_index(f"ix_{table}_demo_session_id")
                batch_op.drop_column("demo_session_id")
