"""
app/schemas/auth.py

Pydantic schemas for authentication and user management.
"""

from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field
from app.models.enums import UserRole


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=6, max_length=128)


class DemoLoginRequest(BaseModel):
    role: Literal["user", "approver", "admin"] = Field(
        ...,
        description="Demo role to authenticate into: 'user', 'approver', or 'admin'",
    )


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: UserRole
    username: str
    user_id: str
    expires_in_minutes: int
    is_demo: bool = False
    demo_session_id: Optional[str] = None


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=8, max_length=128)
    role: UserRole = UserRole.OPERATOR


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    role: UserRole
    is_active: bool
    is_demo: bool = False
    demo_session_id: Optional[str] = None
    created_at: datetime
