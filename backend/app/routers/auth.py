"""
app/routers/auth.py

Authentication and User Administration Router.

Endpoints:
- POST /auth/login: Authenticate credentials with rate limiting and issue JWT.
- GET /auth/me: Retrieve current authenticated user profile.
- POST /auth/users: Admin-only user provisioning (public registration disabled).
- GET /auth/users: Admin-only user list.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import settings
from app.models.user import User
from app.models.enums import UserRole
from app.schemas.auth import (
    LoginRequest,
    DemoLoginRequest,
    TokenResponse,
    UserCreate,
    UserResponse,
)
from app.services import auth_service, demo_service
from app.dependencies.auth import get_current_user, require_roles, get_current_token_payload
from app.utils.auth import create_access_token
from pydantic import BaseModel

router = APIRouter()


class UserUpdate(BaseModel):
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None


def _get_client_ip(request: Request) -> str:
    """Extracts client IP from proxy headers or direct socket connection."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and receive JWT token",
)
def login(
    login_data: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Exchanges credentials for a JWT access token.
    Protected by distributed database-backed rate limiting (5 attempts/5 min).
    Returns generic 401 on any credential mismatch.
    """
    client_ip = _get_client_ip(request)
    try:
        user = auth_service.authenticate_user(
            db=db,
            username=login_data.username,
            password=login_data.password,
            ip_address=client_ip,
        )
    except (auth_service.RateLimitExceededError, auth_service.BurstRateLimitExceededError) as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            headers={"Retry-After": "60"},
        )
    except auth_service.InvalidCredentialsError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(
        user_id=user.id,
        username=user.username,
        role=user.role.value,
        is_demo=bool(user.is_demo),
        demo_session_id=user.demo_session_id,
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        role=user.role,
        username=user.username,
        user_id=user.id,
        expires_in_minutes=settings.jwt_access_token_expire_minutes,
        is_demo=bool(user.is_demo),
        demo_session_id=user.demo_session_id,
    )


@router.post(
    "/demo-login",
    response_model=TokenResponse,
    summary="Start a new per-visitor isolated Recruiter Demo session",
)
def demo_login(
    demo_in: DemoLoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Creates a brand-new, per-visitor isolated demo session (fresh UUIDv4 demo_session_id)
    and issues a signed JWT for the chosen demo role (user, approver, or admin).
    - Controlled strictly on the backend; never exposes real credentials.
    - Protected by burst AND sliding-window per-IP rate limiting.
    - Automatically prunes expired/excess demo sessions to bound database growth.
    """
    if not settings.demo_mode_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Recruiter Demo Mode is disabled on this server.",
        )

    client_ip = _get_client_ip(request)
    try:
        auth_service.check_burst_rate_limit(client_ip)
        demo_service.check_demo_login_rate_limit(client_ip)
    except (auth_service.BurstRateLimitExceededError, demo_service.DemoRateLimitExceededError) as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            headers={"Retry-After": "60"},
        )

    user = demo_service.create_isolated_demo_session(db, demo_in.role)
    token = create_access_token(
        user_id=user.id,
        username=user.username,
        role=user.role.value,
        is_demo=True,
        demo_session_id=user.demo_session_id,
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        role=user.role,
        username=user.username,
        user_id=user.id,
        expires_in_minutes=settings.jwt_access_token_expire_minutes,
        is_demo=True,
        demo_session_id=user.demo_session_id,
    )


@router.post(
    "/demo-switch",
    response_model=TokenResponse,
    summary="Switch role within the current isolated Recruiter Demo session",
)
def demo_switch_role(
    demo_in: DemoLoginRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    payload: dict = Depends(get_current_token_payload),
    db: Session = Depends(get_db),
):
    """
    Switches the authenticated demo visitor to another role strictly inside their OWN
    demo_session_id (read from server-verified identity, never from client input).
    Atomically revokes the previous role's JWT jti so prior permissions cannot be reused.
    """
    if not settings.demo_mode_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Recruiter Demo Mode is disabled on this server.",
        )
    if not current_user.is_demo or not current_user.demo_session_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Demo role switching is only permitted for active demo sessions.",
        )

    client_ip = _get_client_ip(request)
    try:
        auth_service.check_burst_rate_limit(client_ip)
    except auth_service.BurstRateLimitExceededError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            headers={"Retry-After": "60"},
        )

    target_user = demo_service.get_demo_role_user_in_session(
        db, current_user.demo_session_id, demo_in.role
    )
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Demo session has expired. Please start a new demo session.",
        )

    # Immediately revoke the previous role's JWT server-side
    jti = payload.get("jti")
    exp_ts = payload.get("exp")
    if jti and exp_ts:
        auth_service.revoke_token(
            db=db,
            jti=jti,
            user_id=current_user.id,
            expires_at=datetime.fromtimestamp(exp_ts, tz=timezone.utc),
            reason="demo_role_switch",
        )

    token = create_access_token(
        user_id=target_user.id,
        username=target_user.username,
        role=target_user.role.value,
        is_demo=True,
        demo_session_id=target_user.demo_session_id,
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        role=target_user.role,
        username=target_user.username,
        user_id=target_user.id,
        expires_in_minutes=settings.jwt_access_token_expire_minutes,
        is_demo=True,
        demo_session_id=target_user.demo_session_id,
    )


@router.post(
    "/demo-reset",
    status_code=status.HTTP_200_OK,
    summary="Reset sample data strictly inside the caller's own demo session",
)
def demo_reset_session(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Resets approvals and execution logs strictly within the caller's own demo_session_id."""
    if not settings.demo_mode_enabled or not current_user.is_demo or not current_user.demo_session_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Demo reset is only permitted for active demo sessions.",
        )
    try:
        demo_service.reset_demo_session_data(db, current_user.demo_session_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    return {"message": "Demo session data reset to baseline sample records."}


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
)
def get_me(current_user: User = Depends(get_current_user)):
    """Returns profile and assigned role of currently authenticated user."""
    return current_user


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Revoke active token and log out",
)
def logout(
    current_user: User = Depends(get_current_user),
    payload: dict = Depends(get_current_token_payload),
    db: Session = Depends(get_db),
):
    """
    Revokes the current JWT token server-side by adding its JTI to the revocation list.
    Any subsequent request with this token is rejected immediately.
    """
    jti = payload.get("jti")
    exp_ts = payload.get("exp")
    if not jti or not exp_ts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot revoke token without valid jti and exp claims.",
        )

    expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc)
    auth_service.revoke_token(
        db=db,
        jti=jti,
        user_id=current_user.id,
        expires_at=expires_at,
        reason="user_logout",
    )
    return {"message": "Logged out successfully. Token has been revoked."}


@router.post(
    "/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Provision a new user (Admin only)",
)
def create_new_user(
    user_in: UserCreate,
    current_user: User = Depends(require_roles([UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """
    Provisions a new user account with a specified role.
    Strictly restricted to real Admin role; disabled for Demo Admin.
    """
    if current_user.is_demo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User provisioning is disabled in Recruiter Demo Mode.",
        )
    try:
        return auth_service.create_user(db=db, user_in=user_in)
    except auth_service.DuplicateUsernameError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )


@router.get(
    "/users",
    response_model=List[UserResponse],
    summary="List all users (Admin only)",
)
def list_all_users(
    current_user: User = Depends(require_roles([UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """Retrieves user accounts scoped strictly to the caller's tenant and demo session."""
    return auth_service.list_users(
        db,
        is_demo=bool(current_user.is_demo),
        demo_session_id=current_user.demo_session_id,
    )


@router.patch(
    "/users/{id}",
    response_model=UserResponse,
    summary="Update user role or active status (Admin only)",
)
def update_user(
    id: str,
    update_data: UserUpdate,
    current_user: User = Depends(require_roles([UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """
    Updates a user's role or active status.
    - Restricted to real ADMIN role only; disabled for Demo Admin.
    - Validates UUID format and requires at least one field to update.
    - Enforces last-admin protection: refuses to demote or deactivate the last active administrator.
    """
    if current_user.is_demo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Role and account modifications are disabled in Recruiter Demo Mode.",
        )
    try:
        uuid.UUID(id)
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid UUID identifier: '{id}'",
        )

    if update_data.role is None and update_data.is_active is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one field ('role' or 'is_active') must be provided.",
        )

    target_user = db.query(User).filter(User.id == id).first()
    if target_user and bool(target_user.is_demo):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot modify isolated demo user accounts via production user management.",
        )

    try:
        updated = auth_service.update_user(
            db=db,
            user_id=id,
            role=update_data.role,
            is_active=update_data.is_active,
        )
    except auth_service.LastAdminProtectionError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return updated
