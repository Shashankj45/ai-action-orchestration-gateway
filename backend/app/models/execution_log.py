"""
app/models/execution_log.py

SQLAlchemy ORM model for the Execution Log table.

Every API call attempt — whether SAFE (auto-executed) or SENSITIVE
(executed after approval) — is recorded here. Logs are immutable
after creation; replay creates a NEW log entry, never modifies old ones.

Security decisions:
- approval_request_id is nullable: NULL means it was a SAFE auto-execution.
- executed_by_user_id records who triggered/approved this execution.
- response_body is stored as JSON: truncated if > 50 KB to prevent
  log bloat from large API responses.
- request_payload is stored for replay purposes: replaying re-submits
  the original payload exactly (no parameter drift).
- UUID PK: prevents log entry enumeration.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Text, DateTime, JSON, Float,
    Integer, ForeignKey, Enum as SAEnum
)
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.enums import ExecutionStatus


def _now():
    return datetime.now(timezone.utc)

# Max bytes to store for a response body (50 KB)
MAX_RESPONSE_BYTES = 50_000


class ExecutionLog(Base):
    __tablename__ = "execution_logs"

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )

    # Which registered API was called
    api_registry_id = Column(
        String(36),
        ForeignKey("api_registry.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # NULL for SAFE (auto-executed); set for SENSITIVE (after approval)
    approval_request_id = Column(
        String(36),
        ForeignKey("approval_requests.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # User who triggered or approved this execution
    executed_by_user_id = Column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    endpoint_path = Column(String(500), nullable=False)
    http_method = Column(String(10), nullable=False)

    # Payload sent to external API (stored for replay)
    request_payload = Column(JSON, nullable=False, default=dict)

    # Response from external API (truncated at 50 KB)
    response_body = Column(JSON, nullable=True)
    response_status_code = Column(Integer, nullable=True)

    # Outcome
    status = Column(
        SAEnum(ExecutionStatus, name="execution_status_enum"),
        nullable=False,
        index=True,
    )

    # Non-sensitive error message (if FAILED)
    error_message = Column(Text, nullable=True)

    # Performance monitoring
    duration_ms = Column(Float, nullable=True)

    executed_at = Column(DateTime(timezone=True), default=_now, nullable=False, index=True)

    # Relationships
    api = relationship("APIRegistry", back_populates="execution_logs")
    approval_request = relationship(
        "ApprovalRequest",
        back_populates="execution_log",
    )
    executed_by_user = relationship("User", foreign_keys=[executed_by_user_id], lazy="joined")

    @property
    def executed_by_username(self):
        return self.executed_by_user.username if self.executed_by_user else None

    def __repr__(self):
        return (
            f"<ExecutionLog id={self.id!r} "
            f"status={self.status!r} "
            f"code={self.response_status_code} "
            f"method={self.http_method} {self.endpoint_path}>"
        )
