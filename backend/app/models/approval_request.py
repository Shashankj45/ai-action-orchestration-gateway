"""
app/models/approval_request.py

SQLAlchemy ORM model for the Approval Requests table.

An approval request is created when the classifier marks an AI-generated
API call as SENSITIVE. It stays PENDING until a human approves or rejects it.

Security decisions:
- Status transitions are enforced at the service layer (not DB-level).
  PENDING → APPROVED or PENDING → REJECTED are the only valid moves.
- request_payload stores exactly what will be sent to the external API
  if approved — no post-approval parameter modification is allowed
  (prevents approval bypass via payload mutation).
- UUID PK: prevents enumeration of pending approvals.
- Identity Attribution: Tracks requested_by_user_id and decided_by_user_id
  to enforce Four-Eyes principle (preventing self-approval).
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Text, DateTime, JSON, ForeignKey, Enum as SAEnum
)
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.enums import ApprovalStatus


def _now():
    return datetime.now(timezone.utc)


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )

    # Which registered API this request targets
    api_registry_id = Column(
        String(36),
        ForeignKey("api_registry.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # The specific endpoint the LLM wants to call
    endpoint_path = Column(String(500), nullable=False)
    http_method = Column(String(10), nullable=False)

    # Exact payload the LLM generated — frozen at creation time.
    # Cannot be modified after creation (approval bypass prevention).
    request_payload = Column(JSON, nullable=False, default=dict)

    # State machine: PENDING → APPROVED | REJECTED
    status = Column(
        SAEnum(ApprovalStatus, name="approval_status_enum"),
        default=ApprovalStatus.PENDING,
        nullable=False,
        index=True,
    )

    # Human-readable reason the classifier flagged this as SENSITIVE
    classification_reason = Column(Text, nullable=False)

    # Identity tracking for audit and Four-Eyes Principle
    requested_by_user_id = Column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    decided_by_user_id = Column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Set when human makes a decision
    decided_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)

    # Relationships
    api = relationship("APIRegistry", back_populates="approval_requests")
    execution_log = relationship(
        "ExecutionLog",
        back_populates="approval_request",
        uselist=False,
    )
    requested_by_user = relationship("User", foreign_keys=[requested_by_user_id], lazy="joined")
    decided_by_user = relationship("User", foreign_keys=[decided_by_user_id], lazy="joined")

    @property
    def requested_by_username(self):
        return self.requested_by_user.username if self.requested_by_user else None

    @property
    def decided_by_username(self):
        return self.decided_by_user.username if self.decided_by_user else None

    def __repr__(self):
        return (
            f"<ApprovalRequest id={self.id!r} "
            f"status={self.status!r} "
            f"method={self.http_method} {self.endpoint_path}>"
        )
