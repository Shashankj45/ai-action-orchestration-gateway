"""
backend/app/models/user.py

Database models for Inbound Authentication, RBAC, and Distributed Rate Limiting.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, Enum as SAEnum, ForeignKey
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.enums import UserRole


def _now():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(SAEnum(UserRole), nullable=False, default=UserRole.OPERATOR, index=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_now, onupdate=_now, nullable=False)

    def __repr__(self):
        return f"<User(id='{self.id}', username='{self.username}', role='{self.role}')>"


class LoginAttempt(Base):
    """
    Tracks authentication attempts to enforce rate limiting across multiple
    distributed application workers sharing the database.
    """
    __tablename__ = "login_attempts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    ip_address = Column(String(100), nullable=False, index=True)
    username = Column(String(100), nullable=False, index=True)
    attempted_at = Column(DateTime(timezone=True), default=_now, nullable=False, index=True)
    success = Column(Boolean, nullable=False, default=False)

    def __repr__(self):
        return f"<LoginAttempt(ip='{self.ip_address}', user='{self.username}', success={self.success})>"


class RevokedToken(Base):
    """
    Stores revoked JWT IDs (jti) to enable immediate server-side token revocation
    (e.g., on explicit user logout, password reset, or admin deactivation)
    prior to natural cryptographic token expiry.
    """
    __tablename__ = "revoked_tokens"

    jti = Column(String(36), primary_key=True, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    reason = Column(String(64), default="user_logout", nullable=False)

    def __repr__(self):
        return f"<RevokedToken(jti='{self.jti}', user_id='{self.user_id}', reason='{self.reason}')>"
