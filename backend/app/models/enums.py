"""
app/models/enums.py

Shared enumerations used across models and schemas.

Using Python str+Enum means:
- Values serialize to JSON as plain strings ("PENDING", not 0).
- Pydantic validates incoming strings against the enum automatically.
- SQLAlchemy stores them as VARCHAR in the DB (portable across DBs).
"""

from enum import Enum


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class ExecutionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    PENDING = "PENDING"   # queued, awaiting human approval


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    OPERATOR = "OPERATOR"
    APPROVER = "APPROVER"
