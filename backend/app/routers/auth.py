"""
app/routers/auth.py

Authentication and User Administration Router.

Endpoints:
- POST /auth/login: Authenticate credentials with rate limiting and issue JWT.
- GET /auth/me: Retrieve current authenticated user profile.
- POST /auth/users: Admin-only user provisioning (public registration disabled).
- GET /auth/users: Admin-only user list.
"""

from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import settings
from app.models.user import User
from app.models.enums import UserRole
from app.schemas.auth import LoginRequest, TokenResponse, UserCreate, UserResponse
from app.services import auth_service
from app.dependencies.auth import get_current_user, require_roles, get_current_token_payload
from app.utils.auth import create_access_token

router = APIRouter()


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
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        role=user.role,
        username=user.username,
        user_id=user.id,
        expires_in_minutes=settings.jwt_access_token_expire_minutes,
    )


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
    Strictly restricted to Admin role; public registration is disabled.
    """
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
    """Retrieves all registered user accounts."""
    return auth_service.list_users(db)
