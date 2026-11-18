"""
app/models/api_registry.py

SQLAlchemy ORM model for the API Registry table.

Security decisions:
- UUID primary key: prevents sequential ID enumeration attacks.
- auth_header_value stored as plaintext for MVP.
  KNOWN RISK: should be encrypted at rest in production (Phase 5 task).
- endpoints stored as JSON: validated by Pydantic at input time.
- SQLite stores JSON as text; PostgreSQL uses JSONB (faster querying).
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Boolean, Text, DateTime, JSON
)
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.types import EncryptedString


def _now():
    return datetime.now(timezone.utc)


class APIRegistry(Base):
    __tablename__ = "api_registry"

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )
    name = Column(String(100), unique=True, nullable=False, index=True)
    base_url = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)

    # Auth — stored as a header name + value pair.
    # e.g. name="Authorization", value="Bearer sk-..."
    # Security: auth_header_value is encrypted at rest via Fernet AES+HMAC.
    auth_header_name = Column(String(100), nullable=True)
    auth_header_value = Column(EncryptedString, nullable=True)

    # If True: ALL operations on this API require human approval,
    # regardless of HTTP method. Overrides classifier rules.
    is_sensitive = Column(Boolean, default=False, nullable=False)

    # Hard tenant isolation flags for Recruiter Demo Mode
    is_demo = Column(Boolean, default=False, nullable=False, index=True)
    demo_session_id = Column(String(36), nullable=True, index=True)

    # JSON list of endpoint definitions the LLM will use as tool definitions.
    # Schema per item:
    # {
    #   "path": "/v1/charges",
    #   "method": "POST",
    #   "description": "Create a charge",
    #   "parameters": {
    #       "amount": {"type": "integer", "required": true, "description": "..."},
    #       "currency": {"type": "string", "required": true}
    #   }
    # }
    endpoints = Column(JSON, nullable=False, default=list)

    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at = Column(
        DateTime(timezone=True), default=_now, onupdate=_now, nullable=False
    )

    # Relationships
    execution_logs = relationship(
        "ExecutionLog", back_populates="api", cascade="all, delete-orphan"
    )
    approval_requests = relationship(
        "ApprovalRequest", back_populates="api", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<APIRegistry name={self.name!r} base_url={self.base_url!r}>"
