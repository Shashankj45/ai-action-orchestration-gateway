"""
app/dependencies/auth.py

FastAPI Authentication and Authorization Dependencies.

Security decisions:
1. Dynamic DB Role Validation: User's role and active status are fetched
   fresh from the database on every request, ensuring instant role revocation
   without trusting potentially stale JWT claims.
2. HTTPBearer with standardized WWW-Authenticate header.
3. Factory function require_roles() for fine-grained, declarative RBAC.
"""

from typing import List, Optional, Tuple, Dict, Any
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.models.enums import UserRole
from app.utils.auth import decode_access_token, InvalidTokenException
from app.services.auth_service import is_token_revoked

security = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    """
    Extracts, verifies, and decodes the JWT bearer token.
    Loads the user's current active record from the database to check role dynamically.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a valid Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        payload = decode_access_token(token)
    except InvalidTokenException as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload is missing subject identifier.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Server-side Token Revocation Check (Phase 10A.2)
    jti = payload.get("jti")
    if jti and is_token_revoked(db, jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Dynamic DB lookup: guarantees immediate enforcement of role changes and deactivations
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account no longer exists.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account has been deactivated.",
        )

    # Demo isolation claim verification: token is_demo and demo_session_id must match DB user strictly
    token_is_demo = bool(payload.get("is_demo", False))
    token_demo_session = payload.get("demo_session_id")
    if token_is_demo != bool(user.is_demo):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token isolation scope mismatch.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.is_demo and (not user.demo_session_id or token_demo_session != user.demo_session_id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Demo session isolation mismatch.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_demo and token_demo_session is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid demo session claim on non-demo account.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def get_current_token_payload(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Dict[str, Any]:
    """Extracts and verifies raw claims from the caller's JWT token."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return decode_access_token(credentials.credentials)
    except InvalidTokenException as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_roles(allowed_roles: List[UserRole]):
    """
    Role-Based Access Control (RBAC) dependency factory.
    Verifies that the authenticated user's current database role is authorized.
    """
    def _role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            role_names = [r.value for r in allowed_roles]
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Access Denied: Role '{current_user.role.value}' is not authorized. "
                    f"Required roles: {', '.join(role_names)}."
                ),
            )
        return current_user

    return _role_checker
