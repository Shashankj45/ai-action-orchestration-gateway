"""Add rejection_reason column to approval_requests

Revision ID: 0001_add_rejection_reason
Revises:
Create Date: 2026-11-18
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001_add_rejection_reason"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Adds nullable TEXT column 'rejection_reason' to 'approval_requests'.
    Works in both online mode (checks existing columns for idempotency on legacy DBs)
    and offline SQL-generation mode (emits standard ALTER TABLE DDL for SQLite and PostgreSQL).
    """
    if op.get_context().as_sql:
        op.add_column(
            "approval_requests",
            sa.Column("rejection_reason", sa.Text(), nullable=True),
        )
        return

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "approval_requests" not in inspector.get_table_names():
        return

    existing_cols = {col["name"] for col in inspector.get_columns("approval_requests")}
    if "rejection_reason" not in existing_cols:
        with op.batch_alter_table("approval_requests") as batch_op:
            batch_op.add_column(sa.Column("rejection_reason", sa.Text(), nullable=True))


def downgrade() -> None:
    """Removes 'rejection_reason' column from 'approval_requests' using batch mode for SQLite safety."""
    if op.get_context().as_sql:
        op.drop_column("approval_requests", "rejection_reason")
        return

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "approval_requests" not in inspector.get_table_names():
        return

    existing_cols = {col["name"] for col in inspector.get_columns("approval_requests")}
    if "rejection_reason" in existing_cols:
        with op.batch_alter_table("approval_requests") as batch_op:
            batch_op.drop_column("rejection_reason")
