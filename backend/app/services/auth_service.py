"""
app/services/auth_service.py

Authentication and Authorization Service.

Security guarantees:
1. Multi-worker distributed rate limiting backed by the login_attempts table.
2. Generic authentication errors: never reveals whether a username exists.
3. Secure admin bootstrap: no credentials printed into application logs.
4. Constant-time password verification via bcrypt.
"""

import os
import sys
import subprocess
import secrets
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.config import settings
from app.models.user import User, LoginAttempt, RevokedToken
from app.models.enums import UserRole
from app.schemas.auth import UserCreate
from app.utils.auth import hash_password, verify_password


class AuthError(Exception):
    """Base exception for authentication errors."""
    pass


class InvalidCredentialsError(AuthError):
    """Raised on invalid username or password (generic message)."""
    pass


class RateLimitExceededError(AuthError):
    """Raised when consecutive failed logins exceed threshold."""
    pass


class DuplicateUsernameError(AuthError):
    """Raised when attempting to create a user with an existing username."""
    pass


class BurstRateLimitExceededError(AuthError):
    """Raised when an IP sends an excessive burst of requests in a sub-second timeframe."""
    pass


class LastAdminProtectionError(AuthError):
    """Raised when an operation would remove or deactivate the last active administrator."""
    pass


# Burst rate limiting parameters: protects compute-heavy bcrypt from CPU starvation attacks
BURST_WINDOW_SECONDS = 1.0
BURST_MAX_REQUESTS = 10
_burst_tracker: dict = defaultdict(list)


def check_burst_rate_limit(ip_address: str) -> None:
    """
    In-memory sliding window rate limiter shielding the CPU from rapid burst attacks.
    Limits to 10 requests per 1 second per client IP.
    """
    now = time.time()
    cutoff = now - BURST_WINDOW_SECONDS
    timestamps = [ts for ts in _burst_tracker[ip_address] if ts > cutoff]
    if len(timestamps) >= BURST_MAX_REQUESTS:
        _burst_tracker[ip_address] = timestamps
        raise BurstRateLimitExceededError(
            "Too many login attempts in a short timeframe. Please wait a moment."
        )
    timestamps.append(now)
    _burst_tracker[ip_address] = timestamps


def reset_burst_rate_limit() -> None:
    """Clears in-memory burst tracking (useful for test isolation)."""
    _burst_tracker.clear()


MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_WINDOW_MINUTES = 5


def check_login_rate_limit(db: Session, ip_address: str, username: str) -> None:
    """
    Checks login failures across all application workers within the lockout window.
    Raises RateLimitExceededError if threshold is reached.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=LOCKOUT_WINDOW_MINUTES)
    
    # Check failed attempts for this IP or username
    failed_attempts = (
        db.query(func.count(LoginAttempt.id))
        .filter(
            (LoginAttempt.ip_address == ip_address) | (LoginAttempt.username == username),
            LoginAttempt.attempted_at >= cutoff,
            LoginAttempt.success == False,
        )
        .scalar()
    ) or 0

    if failed_attempts >= MAX_LOGIN_ATTEMPTS:
        raise RateLimitExceededError(
            f"Too many failed login attempts. Please wait {LOCKOUT_WINDOW_MINUTES} minutes before retrying."
        )


def record_login_attempt(
    db: Session,
    ip_address: str,
    username: str,
    success: bool,
) -> None:
    """Persists a login attempt to the shared database for distributed rate limiting."""
    attempt = LoginAttempt(
        ip_address=ip_address or "unknown",
        username=username or "unknown",
        success=success,
    )
    db.add(attempt)
    db.commit()


def authenticate_user(
    db: Session,
    username: str,
    password: str,
    ip_address: str,
) -> User:
    """
    Authenticates a user with distributed rate limiting and generic error messages.
    """
    # 1. Burst rate limit check (in-memory sliding window against CPU exhaustion)
    check_burst_rate_limit(ip_address)

    # 2. Distributed rate limit check
    check_login_rate_limit(db, ip_address, username)

    # 2. Retrieve user
    user = db.query(User).filter(User.username == username.strip()).first()

    # 3. Validate password using constant-time comparison (block demo accounts from password login)
    if (
        not user
        or not user.is_active
        or bool(user.is_demo)
        or not verify_password(password, user.hashed_password)
    ):
        record_login_attempt(db, ip_address, username, success=False)
        raise InvalidCredentialsError("Invalid username or password.")

    # 4. Success: record success and return user
    record_login_attempt(db, ip_address, username, success=True)
    return user


def create_user(db: Session, user_in: UserCreate) -> User:
    """Creates a new user. Role assignment is controlled by the caller (Admin-only)."""
    existing = db.query(User).filter(User.username == user_in.username.strip()).first()
    if existing:
        raise DuplicateUsernameError(f"Username '{user_in.username}' already exists.")

    hashed = hash_password(user_in.password)
    user = User(
        username=user_in.username.strip(),
        hashed_password=hashed,
        role=user_in.role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def list_users(
    db: Session,
    is_demo: bool = False,
    demo_session_id: Optional[str] = None,
) -> List[User]:
    """Retrieves registered users scoped strictly by demo session vs production tenant."""
    query = db.query(User).filter(User.is_demo == bool(is_demo))
    if is_demo:
        query = query.filter(User.demo_session_id == demo_session_id)
    return query.order_by(User.created_at.desc()).all()


def update_user(
    db: Session,
    user_id: str,
    role: Optional["UserRole"] = None,
    is_active: Optional[bool] = None,
) -> User:
    """
    Updates a user's role and/or active status.
    Enforces last-admin protection: refuses to demote or deactivate the last active administrator.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return None

    # Determine what the state would look like after the update
    new_role = role if role is not None else user.role
    new_is_active = is_active if is_active is not None else user.is_active

    # Count active non-demo admins BEFORE this change (excluding this user)
    active_admins_excluding_target = (
        db.query(func.count(User.id))
        .filter(
            User.role == UserRole.ADMIN,
            User.is_active == True,
            User.is_demo == False,
            User.id != user_id,
        )
        .scalar()
    ) or 0

    # This user is currently an active admin
    currently_active_admin = (user.role == UserRole.ADMIN and user.is_active)
    # After the change, would this user still be an active admin?
    will_still_be_active_admin = (new_role == UserRole.ADMIN and new_is_active)

    # If this was the only active admin and the change removes that status, block it
    if currently_active_admin and not will_still_be_active_admin and active_admins_excluding_target == 0:
        raise LastAdminProtectionError(
            "Cannot remove or deactivate the last active administrator account. "
            "Promote another user to Admin first."
        )

    if role is not None:
        user.role = role
    if is_active is not None:
        user.is_active = is_active

    db.commit()
    db.refresh(user)
    return user


def revoke_token(
    db: Session,
    jti: str,
    user_id: str,
    expires_at: datetime,
    reason: str = "user_logout",
) -> RevokedToken:
    """
    Registers a token's unique ID (jti) in the revocation table to immediately
    invalidate it across all cluster workers before natural expiration.
    """
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    existing = db.query(RevokedToken).filter(RevokedToken.jti == jti).first()
    if existing:
        return existing

    revoked = RevokedToken(
        jti=jti,
        user_id=user_id,
        expires_at=expires_at,
        revoked_at=datetime.now(timezone.utc),
        reason=reason,
    )
    db.add(revoked)
    db.commit()
    db.refresh(revoked)
    return revoked


def is_token_revoked(db: Session, jti: str) -> bool:
    """Verifies whether a token's JTI is on the server-side revocation list."""
    if not jti:
        return False
    return db.query(RevokedToken.jti).filter(RevokedToken.jti == jti).first() is not None


def prune_expired_revoked_tokens(db: Session) -> int:
    """
    Cleans up revoked tokens whose expiration timestamp has passed,
    keeping the revocation registry bounded and fast.
    """
    now = datetime.now(timezone.utc)
    deleted = db.query(RevokedToken).filter(RevokedToken.expires_at < now).delete(synchronize_session=False)
    db.commit()
    return deleted


def _restrict_file_permissions(path: str) -> None:
    """
    Restrict a file so that only the current OS user can access it.

    Security contract:
    1. On Windows:
       - Checks the exit status of all icacls commands and raises RuntimeError if any fails.
       - Strips all inherited permissions (/inheritance:r).
       - Grants exclusive Full-Control to the current user (/grant:r <user>:(F)).
       - Verifies that the current user has access and no broad/unauthorized access
         (e.g., Everyone, Users, Authenticated Users) is present.
       - Never silently ignores errors: failures immediately abort secret generation.
    2. On POSIX:
       - Sets mode 0o600 (owner read/write only).
       - Verifies the mode bits via os.stat, raising RuntimeError if unverified.
    """
    if sys.platform == "win32":
        current_win_user = os.environ.get("USERNAME")
        if not current_win_user or not current_win_user.strip():
            raise RuntimeError(
                "Cannot determine Windows username from environment (%USERNAME%). "
                "ACL protection cannot be applied. Aborting bootstrap secret generation."
            )

        # Step A: Strip inherited permissions
        res_strip = subprocess.run(
            ["icacls", path, "/inheritance:r"],
            capture_output=True,
            timeout=10,
        )
        if res_strip.returncode != 0:
            err = res_strip.stderr.decode(errors="replace").strip()
            raise RuntimeError(
                f"Failed to strip inherited permissions via icacls /inheritance:r "
                f"(exit code {res_strip.returncode}): {err}"
            )

        # Step B: Grant exclusive Full Control to the current Windows user
        res_grant = subprocess.run(
            ["icacls", path, "/grant:r", f"{current_win_user}:(F)"],
            capture_output=True,
            timeout=10,
        )
        if res_grant.returncode != 0:
            err = res_grant.stderr.decode(errors="replace").strip()
            raise RuntimeError(
                f"Failed to grant ACL permissions via icacls /grant:r "
                f"(exit code {res_grant.returncode}): {err}"
            )

        grant_out = res_grant.stdout.decode(errors="replace")
        if "Failed processing" in grant_out and "Failed processing 0 files" not in grant_out:
            raise RuntimeError(f"icacls /grant:r reported processing failures: {grant_out.strip()}")

        # Step C: Verify ACL restrictions
        res_verify = subprocess.run(
            ["icacls", path],
            capture_output=True,
            timeout=10,
        )
        if res_verify.returncode != 0:
            err = res_verify.stderr.decode(errors="replace").strip()
            raise RuntimeError(
                f"Failed to inspect ACL via icacls (exit code {res_verify.returncode}): {err}"
            )

        acl_out = res_verify.stdout.decode(errors="replace").lower()
        if current_win_user.lower() not in acl_out:
            raise RuntimeError(
                f"Windows ACL verification failed: user '{current_win_user}' not granted in ACL output."
            )

        if "(f)" not in acl_out and "(m)" not in acl_out and "(r,w)" not in acl_out:
            raise RuntimeError(
                "Windows ACL verification failed: full/write access rights not detected in ACL output."
            )

        disallowed_principals = ["everyone:", "builtin\\users:", "authenticated users:"]
        for principal in disallowed_principals:
            if principal in acl_out:
                raise RuntimeError(
                    f"Windows ACL verification failed: unauthorized group '{principal}' detected in file ACL."
                )

    else:
        # POSIX: owner read/write only (0o600)
        os.chmod(path, 0o600)
        actual_mode = os.stat(path).st_mode & 0o777
        if actual_mode != 0o600:
            raise RuntimeError(
                f"POSIX permission verification failed: expected 0o600, got {oct(actual_mode)}"
            )


def bootstrap_admin_user(db: Session) -> Optional[User]:
    """
    Initializes the initial Admin account on first startup if no users exist.

    Security guarantees:
    1. An empty file is created first; credentials are NEVER placed in an unverified file.
    2. File permissions are restricted and verified BEFORE writing the bootstrap password.
    3. Fails immediately if permission restriction cannot be applied or verified.
    4. Generated credentials are NEVER printed to console or application logs.
    """
    existing_user_count = (
        db.query(func.count(User.id)).filter(User.is_demo == False).scalar()
    ) or 0
    if existing_user_count > 0:
        return None

    username = (settings.initial_admin_username or "admin").strip()
    password = settings.initial_admin_password

    if not password or not password.strip():
        # Generate secure random 24-character password
        password = secrets.token_urlsafe(24)
        secret_file = os.path.join(os.getcwd(), ".admin_bootstrap_secret")

        # ---- Step 1: Create an EMPTY file first (no secrets on disk yet) ----
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write("")

        # ---- Step 2: Lock down and verify permissions BEFORE writing the secret ----
        _restrict_file_permissions(secret_file)

        # ---- Step 3: Write credentials only AFTER ACL is verified ----
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write(f"USERNAME={username}\nPASSWORD={password}\n")

    hashed = hash_password(password)
    admin_user = User(
        username=username,
        hashed_password=hashed,
        role=UserRole.ADMIN,
        is_active=True,
    )
    db.add(admin_user)
    db.commit()
    db.refresh(admin_user)
    return admin_user
