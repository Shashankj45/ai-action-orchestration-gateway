"""
app/utils/auth.py

Cryptographic utilities for Inbound Authentication and JWT RBAC:
1. Salted password hashing with bcrypt (12 rounds).
2. Strict JWT signing & verification with pinned HS256, issuer, audience, and expiration.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
import bcrypt
import jwt

from app.config import settings


class AuthenticationError(Exception):
    """Raised when authentication credentials or token validation fails."""
    pass


class InvalidTokenException(AuthenticationError):
    """Raised when JWT signature, claims, or expiration are invalid."""
    pass


def hash_password(password: str) -> str:
    """
    Hashes a plaintext password using bcrypt with a random salt and work factor of 12.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plaintext password against a bcrypt hash in constant time.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except Exception:
        return False


def create_access_token(
    user_id: str,
    username: str,
    role: str,
    expires_delta: Optional[timedelta] = None,
    is_demo: bool = False,
    demo_session_id: Optional[str] = None,
) -> str:
    """
    Issues a signed JWT access token with pinned issuer, audience, expiration, and demo session isolation claims.
    """
    now = datetime.now(timezone.utc)
    expire_minutes = expires_delta or timedelta(minutes=settings.jwt_access_token_expire_minutes)
    expires_at = now + expire_minutes

    payload: Dict[str, Any] = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": str(user_id),
        "username": username,
        "role": role,
        "is_demo": bool(is_demo),
        "demo_session_id": demo_session_id,
        "exp": expires_at,
        "iat": now,
        "nbf": now,
        "jti": str(uuid.uuid4()),
    }

    token = jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm="HS256",
    )
    return token


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Strictly verifies and decodes a JWT access token.
    Validates algorithm (HS256 only), signature, issuer, audience, and expiration.
    Raises InvalidTokenException on any tampering or expiration.
    """
    try:
        decoded = jwt.decode(
            token,
            key=settings.jwt_secret_key,
            algorithms=["HS256"],  # Strict algorithm pinning; rejects alg: none
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={
                "require": ["exp", "iss", "aud", "sub", "role", "iat", "nbf"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
        return decoded
    except jwt.ExpiredSignatureError as exc:
        raise InvalidTokenException("Token has expired.") from exc
    except (
        jwt.InvalidTokenError,
        jwt.InvalidIssuerError,
        jwt.InvalidAudienceError,
        jwt.InvalidAlgorithmError,
    ) as exc:
        raise InvalidTokenException(f"Invalid authentication token: {exc}") from exc
