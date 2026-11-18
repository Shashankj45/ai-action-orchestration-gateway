"""Add is_demo isolation columns for Recruiter Demo Mode

Revision ID: 0002_add_is_demo_columns
Revises: 0001_add_rejection_reason
Create Date: 2026-11-18
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002_add_is_demo_columns"
down_revision: Union[str, None] = "0001_add_rejection_reason"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TARGET_TABLES = ("users", "api_registry", "approval_requests", "execution_logs")


def upgrade() -> None:
    """Adds non-null boolean 'is_demo' (default false) to isolate demo and production data."""
    if op.get_context().as_sql:
        for table in TARGET_TABLES:
            op.add_column(
                table,
                sa.Column("is_demo", sa.Boolean(), nullable=False, server_default=sa.false()),
            )
        return

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    for table in TARGET_TABLES:
        if table not in existing_tables:
            continue
        cols = {col["name"] for col in inspector.get_columns(table)}
        if "is_demo" not in cols:
            with op.batch_alter_table(table) as batch_op:
                batch_op.add_column(
                    sa.Column("is_demo", sa.Boolean(), nullable=False, server_default=sa.false())
                )


def downgrade() -> None:
    """Removes 'is_demo' isolation columns from target tables."""
    if op.get_context().as_sql:
        for table in reversed(TARGET_TABLES):
            op.drop_column(table, "is_demo")
        return

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    for table in reversed(TARGET_TABLES):
        if table not in existing_tables:
            continue
        cols = {col["name"] for col in inspector.get_columns(table)}
        if "is_demo" in cols:
            with op.batch_alter_table(table) as batch_op:
                batch_op.drop_column("is_demo")
