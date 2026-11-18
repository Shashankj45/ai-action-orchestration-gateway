"""
app/services/demo_service.py

Recruiter Demo Mode Service — Per-Session Isolated Sandbox, Abuse Protection & Simulator.

Security guarantees:
1. Per-visitor isolation: every POST /auth/demo-login generates a fresh UUIDv4 demo_session_id
   with dedicated demo users, APIs, approval requests, and execution logs tagged
   (is_demo=True, demo_session_id=<uuid>). Concurrent visitors NEVER see or interfere with
   each other's demo activity.
2. Same-session role switching: POST /auth/demo-switch reads demo_session_id exclusively from
   the caller's verified JWT/DB user, revokes the previous JWT jti, and issues a new token
   for the target role within the same isolated session.
3. Zero external network calls: simulate_demo_api_call() executes purely in-process.
4. Bounded database growth & abuse protection:
   - Per-IP sliding-window rate limit on /auth/demo-login.
   - Per-user sliding-window rate limit on POST /tasks (stricter for demo sessions).
   - Hard per-session cap on total demo actions (approvals + executions).
   - Automatic TTL + FIFO cleanup deleting ONLY is_demo=True rows (never real records).
"""

import secrets
import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import settings
from app.models.user import User, RevokedToken
from app.models.api_registry import APIRegistry
from app.models.approval_request import ApprovalRequest
from app.models.execution_log import ExecutionLog
from app.models.enums import UserRole, ApprovalStatus, ExecutionStatus
from app.utils.auth import hash_password

DEMO_ROLE_MAP = {
    "user": ("demo_user", UserRole.OPERATOR),
    "approver": ("demo_approver", UserRole.APPROVER),
    "admin": ("demo_admin", UserRole.ADMIN),
}


class DemoRateLimitExceededError(Exception):
    """Raised when demo login, task submission, or per-session demo action limits are exceeded."""
    pass


# ---------------------------------------------------------------------------
# Sliding-window rate limiters (demo login + task submission)
# ---------------------------------------------------------------------------
_demo_login_window: Dict[str, List[float]] = defaultdict(list)
_task_rate_window: Dict[str, List[float]] = defaultdict(list)


def reset_demo_rate_limits() -> None:
    """Clears in-memory rate-limit windows (used by test fixtures for isolation)."""
    _demo_login_window.clear()
    _task_rate_window.clear()


def check_demo_login_rate_limit(ip_address: str) -> None:
    """Enforces per-IP limit on POST /auth/demo-login (default 15 per 5 minutes)."""
    now = time.time()
    window_sec = 300.0
    cutoff = now - window_sec
    timestamps = [ts for ts in _demo_login_window[ip_address] if ts > cutoff]
    if len(timestamps) >= settings.demo_login_limit_per_5min:
        _demo_login_window[ip_address] = timestamps
        raise DemoRateLimitExceededError(
            "Too many demo session requests from this IP. Please wait a few minutes before retrying."
        )
    timestamps.append(now)
    _demo_login_window[ip_address] = timestamps


def check_task_rate_limit(user_id: str, is_demo: bool = False) -> None:
    """
    Enforces per-user per-minute rate limiting on POST /tasks.
    Demo sessions use a stricter limit (demo_task_limit_per_minute) than standard users (rate_limit_per_minute).
    """
    now = time.time()
    cutoff = now - 60.0
    limit = settings.demo_task_limit_per_minute if is_demo else settings.rate_limit_per_minute
    timestamps = [ts for ts in _task_rate_window[user_id] if ts > cutoff]
    if len(timestamps) >= limit:
        _task_rate_window[user_id] = timestamps
        raise DemoRateLimitExceededError(
            f"Rate limit exceeded ({limit} requests per minute). Please wait before submitting more tasks."
        )
    timestamps.append(now)
    _task_rate_window[user_id] = timestamps


def enforce_demo_session_action_limit(db: Session, demo_session_id: str) -> None:
    """Caps total approvals + execution logs created inside a single demo session."""
    appr_count = (
        db.query(func.count(ApprovalRequest.id))
        .filter(
            ApprovalRequest.is_demo == True,
            ApprovalRequest.demo_session_id == demo_session_id,
        )
        .scalar()
        or 0
    )
    log_count = (
        db.query(func.count(ExecutionLog.id))
        .filter(
            ExecutionLog.is_demo == True,
            ExecutionLog.demo_session_id == demo_session_id,
        )
        .scalar()
        or 0
    )
    if (appr_count + log_count) >= settings.demo_max_actions_per_session:
        raise DemoRateLimitExceededError(
            "Demo session activity limit reached. Reset the demo or start a fresh demo session."
        )


# ---------------------------------------------------------------------------
# Bounded Demo Cleanup (Strictly is_demo == True — NEVER touches real data)
# ---------------------------------------------------------------------------
def _delete_demo_sessions(db: Session, session_ids: List[str]) -> int:
    """Deletes all demo records belonging to the specified demo_session_ids. Double-guarded with is_demo==True."""
    if not session_ids:
        return 0

    demo_user_ids = [
        row[0]
        for row in db.query(User.id)
        .filter(User.is_demo == True, User.demo_session_id.in_(session_ids))
        .all()
    ]

    db.query(ExecutionLog).filter(
        ExecutionLog.is_demo == True,
        ExecutionLog.demo_session_id.in_(session_ids),
    ).delete(synchronize_session=False)

    db.query(ApprovalRequest).filter(
        ApprovalRequest.is_demo == True,
        ApprovalRequest.demo_session_id.in_(session_ids),
    ).delete(synchronize_session=False)

    db.query(APIRegistry).filter(
        APIRegistry.is_demo == True,
        APIRegistry.demo_session_id.in_(session_ids),
    ).delete(synchronize_session=False)

    if demo_user_ids:
        db.query(RevokedToken).filter(
            RevokedToken.user_id.in_(demo_user_ids)
        ).delete(synchronize_session=False)

    db.query(User).filter(
        User.is_demo == True,
        User.demo_session_id.in_(session_ids),
    ).delete(synchronize_session=False)

    db.commit()
    return len(session_ids)


def cleanup_expired_demo_sessions(
    db: Session,
    max_age_hours: Optional[int] = None,
    max_active_sessions: Optional[int] = None,
) -> int:
    """
    Prunes expired demo sessions (older than max_age_hours) and enforces an upper bound
    (max_active_sessions) via FIFO eviction to prevent unbounded demo database growth.
    Safety guarantee: NEVER deletes or modifies any record where is_demo == False.
    """
    ttl_hours = max_age_hours if max_age_hours is not None else settings.demo_session_ttl_hours
    cap = max_active_sessions if max_active_sessions is not None else settings.demo_max_active_sessions
    cutoff = datetime.now(timezone.utc) - timedelta(hours=ttl_hours)

    # Group existing demo sessions by earliest creation timestamp
    sessions = (
        db.query(User.demo_session_id, func.min(User.created_at).label("created"))
        .filter(User.is_demo == True, User.demo_session_id.isnot(None))
        .group_by(User.demo_session_id)
        .order_by(func.min(User.created_at).asc())
        .all()
    )

    to_delete: List[str] = []
    remaining: List[str] = []
    for sess_id, created in sessions:
        if created is not None:
            created_aware = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
            if created_aware < cutoff:
                to_delete.append(sess_id)
                continue
        remaining.append(sess_id)

    # FIFO cap enforcement: keep at most (cap - 1) existing sessions if we are about to add one
    if cap >= 0 and len(remaining) > cap:
        excess = len(remaining) - cap
        to_delete.extend(remaining[:excess])

    # Also prune any legacy orphan demo rows without demo_session_id
    orphan_users = (
        db.query(User.id).filter(User.is_demo == True, User.demo_session_id.is_(None)).all()
    )
    if orphan_users:
        orphan_ids = [r[0] for r in orphan_users]
        db.query(ExecutionLog).filter(ExecutionLog.is_demo == True, ExecutionLog.demo_session_id.is_(None)).delete(synchronize_session=False)
        db.query(ApprovalRequest).filter(ApprovalRequest.is_demo == True, ApprovalRequest.demo_session_id.is_(None)).delete(synchronize_session=False)
        db.query(APIRegistry).filter(APIRegistry.is_demo == True, APIRegistry.demo_session_id.is_(None)).delete(synchronize_session=False)
        db.query(RevokedToken).filter(RevokedToken.user_id.in_(orphan_ids)).delete(synchronize_session=False)
        db.query(User).filter(User.is_demo == True, User.demo_session_id.is_(None)).delete(synchronize_session=False)
        db.commit()

    return _delete_demo_sessions(db, to_delete)


# ---------------------------------------------------------------------------
# Per-Session Demo Seeding & Authentication
# ---------------------------------------------------------------------------
def _seed_demo_records_for_session(
    db: Session,
    demo_session_id: str,
    demo_user: User,
    demo_claire: User,
    demo_approver: User,
    reservations_api: APIRegistry,
    billing_api: APIRegistry,
) -> None:
    """Seeds baseline fictional approval requests and execution logs inside a single demo session."""
    now = datetime.now(timezone.utc)

    pending_cancel = ApprovalRequest(
        api_registry_id=reservations_api.id,
        endpoint_path="/v1/bookings/cancel",
        http_method="POST",
        request_payload={"booking_id": 105},
        status=ApprovalStatus.PENDING,
        classification_reason="Operation is SENSITIVE: Endpoint path contains sensitive keyword 'cancel'.",
        requested_by_user_id=demo_user.id,
        is_demo=True,
        demo_session_id=demo_session_id,
        created_at=now - timedelta(minutes=18),
    )

    pending_refund = ApprovalRequest(
        api_registry_id=billing_api.id,
        endpoint_path="/v1/refunds",
        http_method="POST",
        request_payload={"booking_id": 208, "amount": 180.0},
        status=ApprovalStatus.PENDING,
        classification_reason="Operation is SENSITIVE: Target API 'Meridian Billing Service' is marked as sensitive.",
        requested_by_user_id=demo_claire.id,
        is_demo=True,
        demo_session_id=demo_session_id,
        created_at=now - timedelta(minutes=11),
    )

    approved_checkout = ApprovalRequest(
        api_registry_id=reservations_api.id,
        endpoint_path="/v1/bookings/late-checkout",
        http_method="POST",
        request_payload={"booking_id": 102},
        status=ApprovalStatus.APPROVED,
        classification_reason="Operation is SENSITIVE: State-changing HTTP POST requires human review.",
        requested_by_user_id=demo_user.id,
        decided_by_user_id=demo_approver.id,
        decided_at=now - timedelta(hours=2, minutes=10),
        is_demo=True,
        demo_session_id=demo_session_id,
        created_at=now - timedelta(hours=2, minutes=25),
    )

    rejected_cancel = ApprovalRequest(
        api_registry_id=reservations_api.id,
        endpoint_path="/v1/bookings/cancel",
        http_method="POST",
        request_payload={"booking_id": 99},
        status=ApprovalStatus.REJECTED,
        classification_reason="Operation is SENSITIVE: Endpoint path contains sensitive keyword 'cancel'.",
        requested_by_user_id=demo_user.id,
        decided_by_user_id=demo_approver.id,
        decided_at=now - timedelta(hours=4, minutes=5),
        rejection_reason="Check-in window already passed; cancellation requires front-desk fee waiver.",
        is_demo=True,
        demo_session_id=demo_session_id,
        created_at=now - timedelta(hours=4, minutes=20),
    )

    db.add_all([pending_cancel, pending_refund, approved_checkout, rejected_cancel])
    db.flush()

    log_safe_user = ExecutionLog(
        api_registry_id=reservations_api.id,
        approval_request_id=None,
        executed_by_user_id=demo_user.id,
        endpoint_path="/v1/bookings/status",
        http_method="GET",
        request_payload={"booking_id": 105},
        response_body={
            "booking_id": 105,
            "guest_name": "Alex Rivera (Demo)",
            "room_type": "Deluxe King",
            "status": "CONFIRMED",
            "sandbox": True,
        },
        response_status_code=200,
        status=ExecutionStatus.SUCCESS,
        duration_ms=34.2,
        is_demo=True,
        demo_session_id=demo_session_id,
        executed_at=now - timedelta(minutes=25),
    )

    log_approved_exec = ExecutionLog(
        api_registry_id=reservations_api.id,
        approval_request_id=approved_checkout.id,
        executed_by_user_id=demo_approver.id,
        endpoint_path="/v1/bookings/late-checkout",
        http_method="POST",
        request_payload={"booking_id": 102},
        response_body={
            "booking_id": 102,
            "checkout_time": "14:00",
            "status": "UPDATED",
            "sandbox": True,
        },
        response_status_code=200,
        status=ExecutionStatus.SUCCESS,
        duration_ms=48.6,
        is_demo=True,
        demo_session_id=demo_session_id,
        executed_at=now - timedelta(hours=2, minutes=10),
    )

    log_failed_user = ExecutionLog(
        api_registry_id=reservations_api.id,
        approval_request_id=None,
        executed_by_user_id=demo_user.id,
        endpoint_path="/v1/bookings/status",
        http_method="GET",
        request_payload={"booking_id": 404},
        response_body={"error": "Reservation #404 not found in demo catalog", "sandbox": True},
        response_status_code=404,
        status=ExecutionStatus.FAILED,
        error_message="Demo Sandbox: Reservation #404 was not found.",
        duration_ms=19.4,
        is_demo=True,
        demo_session_id=demo_session_id,
        executed_at=now - timedelta(hours=1, minutes=15),
    )

    log_other_demo_user = ExecutionLog(
        api_registry_id=reservations_api.id,
        approval_request_id=None,
        executed_by_user_id=demo_claire.id,
        endpoint_path="/v1/bookings/status",
        http_method="GET",
        request_payload={"booking_id": 208},
        response_body={
            "booking_id": 208,
            "guest_name": "Claire Bennett (Demo)",
            "status": "CONFIRMED",
            "sandbox": True,
        },
        response_status_code=200,
        status=ExecutionStatus.SUCCESS,
        duration_ms=29.1,
        is_demo=True,
        demo_session_id=demo_session_id,
        executed_at=now - timedelta(minutes=30),
    )

    db.add_all([log_safe_user, log_approved_exec, log_failed_user, log_other_demo_user])


def create_isolated_demo_session(db: Session, role_key: str) -> User:
    """
    Creates a brand-new, per-visitor isolated demo session with its own demo_session_id,
    dedicated demo identities, demo APIs, sample approvals, and execution logs.
    Automatically prunes expired/excess demo sessions first to bound database growth.
    """
    if role_key not in DEMO_ROLE_MAP:
        raise ValueError(f"Unsupported demo role: '{role_key}'")

    # Keep total active demo sessions bounded before adding a new one
    cleanup_expired_demo_sessions(
        db,
        max_active_sessions=max(settings.demo_max_active_sessions - 1, 0),
    )

    demo_session_id = str(uuid.uuid4())
    tag = demo_session_id[:8]

    def _new_demo_user(prefix: str, role: UserRole) -> User:
        u = User(
            username=f"{prefix}_{tag}",
            hashed_password=hash_password(secrets.token_urlsafe(32)),
            role=role,
            is_active=True,
            is_demo=True,
            demo_session_id=demo_session_id,
        )
        db.add(u)
        db.flush()
        return u

    demo_user = _new_demo_user("demo_user", UserRole.OPERATOR)
    demo_claire = _new_demo_user("demo_guest_claire", UserRole.OPERATOR)
    demo_approver = _new_demo_user("demo_approver", UserRole.APPROVER)
    demo_admin = _new_demo_user("demo_admin", UserRole.ADMIN)

    reservations_api = APIRegistry(
        name=f"Meridian Reservations API (Demo {tag})",
        base_url="https://reservations.demo-sandbox.invalid",
        description="Fictional hospitality reservation service for viewing, modifying, and cancelling bookings",
        auth_header_name=None,
        auth_header_value=None,
        is_sensitive=False,
        is_demo=True,
        demo_session_id=demo_session_id,
        endpoints=[
            {
                "path": "/v1/bookings/status",
                "method": "GET",
                "description": "View reservation details and booking status",
                "parameters": {
                    "booking_id": {
                        "type": "integer",
                        "required": True,
                        "description": "Numeric reservation identifier",
                    }
                },
            },
            {
                "path": "/v1/bookings/cancel",
                "method": "POST",
                "description": "Cancel an existing guest booking reservation",
                "parameters": {
                    "booking_id": {
                        "type": "integer",
                        "required": True,
                        "description": "Numeric reservation identifier to cancel",
                    }
                },
            },
            {
                "path": "/v1/bookings/late-checkout",
                "method": "POST",
                "description": "Request late checkout modification for a reservation",
                "parameters": {
                    "booking_id": {
                        "type": "integer",
                        "required": True,
                        "description": "Numeric reservation identifier",
                    }
                },
            },
        ],
    )

    billing_api = APIRegistry(
        name=f"Meridian Billing Service (Demo {tag})",
        base_url="https://billing.demo-sandbox.invalid",
        description="Fictional billing and refund processing service (all operations require approval)",
        auth_header_name=None,
        auth_header_value=None,
        is_sensitive=True,
        is_demo=True,
        demo_session_id=demo_session_id,
        endpoints=[
            {
                "path": "/v1/refunds",
                "method": "POST",
                "description": "Issue a refund for a cancelled reservation",
                "parameters": {
                    "booking_id": {
                        "type": "integer",
                        "required": True,
                        "description": "Numeric reservation identifier",
                    },
                    "amount": {
                        "type": "number",
                        "required": False,
                        "default": 150.0,
                        "description": "Refund amount in USD",
                    },
                },
            },
        ],
    )
    db.add_all([reservations_api, billing_api])
    db.flush()

    _seed_demo_records_for_session(
        db=db,
        demo_session_id=demo_session_id,
        demo_user=demo_user,
        demo_claire=demo_claire,
        demo_approver=demo_approver,
        reservations_api=reservations_api,
        billing_api=billing_api,
    )

    db.commit()
    role_users = {"user": demo_user, "approver": demo_approver, "admin": demo_admin}
    return role_users[role_key]


def get_demo_role_user_in_session(db: Session, demo_session_id: str, role_key: str) -> Optional[User]:
    """Looks up the dedicated demo User for role_key inside the caller's existing isolated demo_session_id."""
    if role_key not in DEMO_ROLE_MAP:
        raise ValueError(f"Unsupported demo role: '{role_key}'")
    prefix, target_role = DEMO_ROLE_MAP[role_key]
    return (
        db.query(User)
        .filter(
            User.is_demo == True,
            User.demo_session_id == demo_session_id,
            User.role == target_role,
            User.username.like(f"{prefix}_%"),
            User.is_active == True,
        )
        .first()
    )


def reset_demo_session_data(db: Session, demo_session_id: str) -> None:
    """
    Resets approvals and execution logs strictly within the caller's own demo_session_id.
    Never touches other demo sessions or non-demo production records.
    """
    users = (
        db.query(User)
        .filter(User.is_demo == True, User.demo_session_id == demo_session_id)
        .all()
    )
    apis = (
        db.query(APIRegistry)
        .filter(APIRegistry.is_demo == True, APIRegistry.demo_session_id == demo_session_id)
        .all()
    )
    demo_user = next((u for u in users if u.username.startswith("demo_user_")), None)
    demo_claire = next((u for u in users if u.username.startswith("demo_guest_claire_")), None)
    demo_approver = next((u for u in users if u.username.startswith("demo_approver_")), None)
    reservations_api = next((a for a in apis if "Reservations" in a.name), None)
    billing_api = next((a for a in apis if "Billing" in a.name), None)

    if not all([demo_user, demo_claire, demo_approver, reservations_api, billing_api]):
        raise ValueError("Demo session is incomplete or expired.")

    db.query(ExecutionLog).filter(
        ExecutionLog.is_demo == True,
        ExecutionLog.demo_session_id == demo_session_id,
    ).delete(synchronize_session=False)
    db.query(ApprovalRequest).filter(
        ApprovalRequest.is_demo == True,
        ApprovalRequest.demo_session_id == demo_session_id,
    ).delete(synchronize_session=False)
    db.flush()

    _seed_demo_records_for_session(
        db=db,
        demo_session_id=demo_session_id,
        demo_user=demo_user,
        demo_claire=demo_claire,
        demo_approver=demo_approver,
        reservations_api=reservations_api,
        billing_api=billing_api,
    )
    db.commit()


# ---------------------------------------------------------------------------
# In-Process Sandbox Simulator (Zero External Network Calls)
# ---------------------------------------------------------------------------
def simulate_demo_api_call(
    db: Session,
    api: APIRegistry,
    endpoint_path: str,
    http_method: str,
    payload: Dict[str, Any],
    approval_request_id: Optional[str] = None,
    executed_by_user_id: Optional[str] = None,
    demo_session_id: Optional[str] = None,
) -> ExecutionLog:
    """
    Executes a simulated API operation entirely in-process for Recruiter Demo Mode.
    Security guarantee: NEVER opens outbound network connections or calls real external APIs.
    """
    method_upper = http_method.strip().upper()
    path_lower = endpoint_path.lower()
    booking_id = payload.get("booking_id", 105)
    effective_session_id = demo_session_id or api.demo_session_id

    if booking_id == 404:
        status_code = 404
        exec_status = ExecutionStatus.FAILED
        error_message = "Demo Sandbox: Reservation #404 was not found."
        response_data = {"error": "Reservation #404 not found", "sandbox": True}
    elif "cancel" in path_lower:
        status_code = 200
        exec_status = ExecutionStatus.SUCCESS
        error_message = None
        response_data = {
            "booking_id": booking_id,
            "status": "CANCELLED",
            "message": f"Demo booking #{booking_id} cancelled in sandbox.",
            "sandbox": True,
        }
    elif "late-checkout" in path_lower:
        status_code = 200
        exec_status = ExecutionStatus.SUCCESS
        error_message = None
        response_data = {
            "booking_id": booking_id,
            "checkout_time": "14:00",
            "status": "UPDATED",
            "sandbox": True,
        }
    elif "refund" in path_lower:
        status_code = 200
        exec_status = ExecutionStatus.SUCCESS
        error_message = None
        response_data = {
            "booking_id": booking_id,
            "amount": payload.get("amount", 150.0),
            "status": "REFUND_ISSUED",
            "sandbox": True,
        }
    else:
        status_code = 200
        exec_status = ExecutionStatus.SUCCESS
        error_message = None
        response_data = {
            "booking_id": booking_id,
            "guest_name": "Alex Rivera (Demo)",
            "property": "Meridian Downtown (Demo)",
            "room_type": "Deluxe King",
            "check_in": "2026-11-20",
            "check_out": "2026-11-23",
            "nightly_rate": "$210 USD",
            "status": "CONFIRMED",
            "sandbox": True,
        }

    log_entry = ExecutionLog(
        api_registry_id=api.id,
        approval_request_id=approval_request_id,
        executed_by_user_id=executed_by_user_id,
        endpoint_path=endpoint_path,
        http_method=method_upper,
        request_payload=payload,
        response_body=response_data,
        response_status_code=status_code,
        status=exec_status,
        error_message=error_message,
        duration_ms=24.5,
        is_demo=True,
        demo_session_id=effective_session_id,
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry
