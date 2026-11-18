"""
backend/tests/test_phase12_cross_role_security.py

Phase 12: Comprehensive cross-role security and ownership isolation tests.

Coverage:
1.  OPERATOR attempts to access ADMIN/APPROVER-only endpoints — must receive 403.
2.  APPROVER attempts to access ADMIN-only endpoints — must receive 403.
3.  APPROVER attempts to submit tasks — must receive 403.
4.  Ownership isolation: OPERATOR-A cannot read OPERATOR-B's approvals or logs.
5.  Payload immutability: approved execution uses DB-stored payload.
6.  Rejection reason persistence: reason stored permanently with approver identity.
7.  Last-admin protection: cannot demote or deactivate the sole active admin.
8.  GET /apis/tools: OPERATOR gets sanitized list (no base_url/endpoints/auth_header_name).
9.  GET /apis: OPERATOR receives 403.
"""

import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.config import settings
settings.initial_admin_password = "test_password_to_bypass_icacls"

from app.main import app
from app.database import Base, engine, SessionLocal
from app.models.user import User
from app.models.enums import UserRole, ApprovalStatus, ExecutionStatus
from app.models.api_registry import APIRegistry
from app.models.approval_request import ApprovalRequest
from app.models.execution_log import ExecutionLog
from app.utils.auth import hash_password, create_access_token


@pytest.fixture(autouse=True)
def clean_db():
    """Drop and recreate all tables before each test for complete isolation."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_user(db, username, role, is_active=True):
    user = User(
        id=str(uuid.uuid4()),
        username=username,
        hashed_password=hash_password("TestPass123!"),
        role=role,
        is_active=is_active,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _token(user):
    return create_access_token(user_id=user.id, username=user.username, role=user.role.value)


def _auth(user):
    return {"Authorization": f"Bearer {_token(user)}"}


def _make_api(db):
    api = APIRegistry(
        id=str(uuid.uuid4()),
        name="Test Hotel API",
        description="A test hotel API",
        base_url="https://hotel.example.com",
        endpoints=[{"path": "/bookings/{id}", "method": "DELETE", "description": "Cancel booking"}],
        is_sensitive=True,
    )
    db.add(api)
    db.commit()
    db.refresh(api)
    return api


def _make_approval(db, api, operator, status=ApprovalStatus.PENDING):
    appr = ApprovalRequest(
        id=str(uuid.uuid4()),
        api_registry_id=api.id,
        endpoint_path="/bookings/105",
        http_method="DELETE",
        request_payload={"booking_id": 105},
        status=status,
        classification_reason="Destructive operation requires human review",
        requested_by_user_id=operator.id,
    )
    db.add(appr)
    db.commit()
    db.refresh(appr)
    return appr


def _make_log(db, api, operator):
    log = ExecutionLog(
        id=str(uuid.uuid4()),
        api_registry_id=api.id,
        endpoint_path="/bookings/105",
        http_method="GET",
        request_payload={},
        status=ExecutionStatus.SUCCESS,
        response_status_code=200,
        response_body={"ok": True},
        duration_ms=42.0,
        executed_by_user_id=operator.id,
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


# ===========================================================================
# 1. OPERATOR cannot access ADMIN/APPROVER-only endpoints
# ===========================================================================

def test_operator_cannot_get_apis(client, db):
    """OPERATOR calling GET /apis must get 403."""
    op = _make_user(db, "op1", UserRole.OPERATOR)
    r = client.get("/apis", headers=_auth(op))
    assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"


def test_operator_cannot_post_apis(client, db):
    """OPERATOR calling POST /apis must get 403."""
    op = _make_user(db, "op1", UserRole.OPERATOR)
    r = client.post("/apis", headers=_auth(op), json={
        "name": "hack", "base_url": "https://evil.example.com", "endpoints": []
    })
    assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"


def test_operator_cannot_list_all_approvals(client, db):
    """OPERATOR calling GET /approvals (all) must get 403."""
    op = _make_user(db, "op1", UserRole.OPERATOR)
    r = client.get("/approvals", headers=_auth(op))
    assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"


def test_operator_cannot_approve(client, db):
    """OPERATOR calling POST /approvals/{id}/approve must get 403."""
    op = _make_user(db, "op1", UserRole.OPERATOR)
    api = _make_api(db)
    appr = _make_approval(db, api, op)
    r = client.post(f"/approvals/{appr.id}/approve", headers=_auth(op))
    assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"


def test_operator_cannot_reject(client, db):
    """OPERATOR calling POST /approvals/{id}/reject must get 403."""
    op = _make_user(db, "op1", UserRole.OPERATOR)
    api = _make_api(db)
    appr = _make_approval(db, api, op)
    r = client.post(f"/approvals/{appr.id}/reject", headers=_auth(op), json={})
    assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"


def test_operator_cannot_replay_log(client, db):
    """OPERATOR calling POST /logs/{id}/replay must get 403."""
    op = _make_user(db, "op1", UserRole.OPERATOR)
    api = _make_api(db)
    log = _make_log(db, api, op)
    r = client.post(f"/logs/{log.id}/replay", headers=_auth(op))
    assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"


def test_operator_cannot_get_system_metrics(client, db):
    """OPERATOR calling GET /system/metrics must get 403."""
    op = _make_user(db, "op1", UserRole.OPERATOR)
    r = client.get("/system/metrics", headers=_auth(op))
    assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"


def test_operator_cannot_list_users(client, db):
    """OPERATOR calling GET /auth/users must get 403."""
    op = _make_user(db, "op1", UserRole.OPERATOR)
    r = client.get("/auth/users", headers=_auth(op))
    assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"


def test_operator_cannot_create_user(client, db):
    """OPERATOR calling POST /auth/users must get 403."""
    op = _make_user(db, "op1", UserRole.OPERATOR)
    r = client.post("/auth/users", headers=_auth(op), json={
        "username": "newuser", "password": "NewPass123!", "role": "OPERATOR"
    })
    assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"


def test_operator_cannot_patch_user(client, db):
    """OPERATOR calling PATCH /auth/users/{id} must get 403."""
    op = _make_user(db, "op1", UserRole.OPERATOR)
    r = client.patch(f"/auth/users/{op.id}", headers=_auth(op), json={"is_active": False})
    assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"


# ===========================================================================
# 2. APPROVER cannot access ADMIN-only endpoints
# ===========================================================================

def test_approver_cannot_post_task(client, db):
    """APPROVER calling POST /tasks must get 403."""
    apr = _make_user(db, "apr1", UserRole.APPROVER)
    r = client.post("/tasks", headers=_auth(apr), json={"task": "Cancel booking 105"})
    assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"


def test_approver_cannot_post_apis(client, db):
    """APPROVER calling POST /apis must get 403."""
    apr = _make_user(db, "apr1", UserRole.APPROVER)
    r = client.post("/apis", headers=_auth(apr), json={
        "name": "hack", "base_url": "https://evil.example.com", "endpoints": []
    })
    assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"


def test_approver_cannot_list_users(client, db):
    """APPROVER calling GET /auth/users must get 403."""
    apr = _make_user(db, "apr1", UserRole.APPROVER)
    r = client.get("/auth/users", headers=_auth(apr))
    assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"


def test_approver_cannot_get_system_metrics(client, db):
    """APPROVER calling GET /system/metrics must get 403."""
    apr = _make_user(db, "apr1", UserRole.APPROVER)
    r = client.get("/system/metrics", headers=_auth(apr))
    assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"


def test_approver_cannot_patch_user(client, db):
    """APPROVER calling PATCH /auth/users/{id} must get 403."""
    apr = _make_user(db, "apr1", UserRole.APPROVER)
    r = client.patch(f"/auth/users/{apr.id}", headers=_auth(apr), json={"is_active": False})
    assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"


# ===========================================================================
# 3. Ownership isolation
# ===========================================================================

def test_operator_a_cannot_read_operator_b_approval(client, db):
    """OPERATOR-A calling GET /approvals/{id} for OPERATOR-B's approval → 403."""
    op_a = _make_user(db, "op_a", UserRole.OPERATOR)
    op_b = _make_user(db, "op_b", UserRole.OPERATOR)
    api = _make_api(db)
    appr_b = _make_approval(db, api, op_b)
    r = client.get(f"/approvals/{appr_b.id}", headers=_auth(op_a))
    assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"


def test_operator_a_cannot_read_operator_b_log(client, db):
    """OPERATOR-A calling GET /logs/{id} for OPERATOR-B's log → 403."""
    op_a = _make_user(db, "op_a", UserRole.OPERATOR)
    op_b = _make_user(db, "op_b", UserRole.OPERATOR)
    api = _make_api(db)
    log_b = _make_log(db, api, op_b)
    r = client.get(f"/logs/{log_b.id}", headers=_auth(op_a))
    assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"


def test_operator_my_requests_scoped_to_own(client, db):
    """OPERATOR-A's GET /approvals/my returns only their own requests."""
    op_a = _make_user(db, "op_a", UserRole.OPERATOR)
    op_b = _make_user(db, "op_b", UserRole.OPERATOR)
    api = _make_api(db)
    _make_approval(db, api, op_b)  # B's request — should not appear for A
    r = client.get("/approvals/my", headers=_auth(op_a))
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    # None of B's approvals should appear for A
    for item in data:
        assert item["requested_by_user_id"] == op_a.id, (
            f"Got approval for different user: {item['requested_by_user_id']}"
        )


def test_operator_logs_scoped_to_own(client, db):
    """OPERATOR-A's GET /logs returns only their own logs."""
    op_a = _make_user(db, "op_a", UserRole.OPERATOR)
    op_b = _make_user(db, "op_b", UserRole.OPERATOR)
    api = _make_api(db)
    _make_log(db, api, op_b)  # B's log
    r = client.get("/logs", headers=_auth(op_a))
    assert r.status_code == 200
    data = r.json()
    for item in data:
        assert item.get("executed_by_user_id") == op_a.id, (
            f"Got log for different user: {item.get('executed_by_user_id')}"
        )


# ===========================================================================
# 4. Rejection reason persistence
# ===========================================================================

def test_rejection_reason_stored_in_db(client, db):
    """Rejecting with a reason → reason persisted in DB and returned in GET /approvals/{id}."""
    admin = _make_user(db, "admin1", UserRole.ADMIN)
    op = _make_user(db, "op1", UserRole.OPERATOR)
    api = _make_api(db)
    appr = _make_approval(db, api, op)

    reason_text = "Booking already expired and cannot be cancelled."
    r = client.post(
        f"/approvals/{appr.id}/reject",
        headers=_auth(admin),
        json={"reason": reason_text},
    )
    assert r.status_code == 200, f"Reject failed: {r.text}"
    body = r.json()
    assert body["approval"]["status"] == "REJECTED"
    assert body["approval"]["rejection_reason"] == reason_text
    assert body["approval"]["decided_by_user_id"] == admin.id
    assert body["approval"]["decided_at"] is not None


def test_rejection_without_reason_rejected_with_422(client, db):
    """Rejecting without a body, empty body, or null reason must return 422 (reason is mandatory)."""
    admin = _make_user(db, "admin1", UserRole.ADMIN)
    op = _make_user(db, "op1", UserRole.OPERATOR)
    api = _make_api(db)
    appr = _make_approval(db, api, op)

    # Missing body
    r_no_body = client.post(f"/approvals/{appr.id}/reject", headers=_auth(admin))
    assert r_no_body.status_code == 422, f"Expected 422, got {r_no_body.status_code}: {r_no_body.text}"

    # Empty JSON object
    r_empty = client.post(f"/approvals/{appr.id}/reject", headers=_auth(admin), json={})
    assert r_empty.status_code == 422

    # Null reason
    r_null = client.post(f"/approvals/{appr.id}/reject", headers=_auth(admin), json={"reason": None})
    assert r_null.status_code == 422

    # Empty string
    r_blank = client.post(f"/approvals/{appr.id}/reject", headers=_auth(admin), json={"reason": ""})
    assert r_blank.status_code == 422

    # Approval must still be PENDING in DB
    db.refresh(appr)
    assert appr.status == ApprovalStatus.PENDING
    assert appr.rejection_reason is None


# ===========================================================================
# 5. Last-admin protection
# ===========================================================================

def test_cannot_demote_last_active_admin(client, db):
    """PATCH /auth/users/{id} to demote the only active admin → 400."""
    admin = _make_user(db, "admin1", UserRole.ADMIN)
    # Only one admin — demotion should be blocked
    r = client.patch(
        f"/auth/users/{admin.id}",
        headers=_auth(admin),
        json={"role": "OPERATOR"},
    )
    assert r.status_code == 400, f"Expected 400, got {r.status_code}: {r.text}"
    assert "last active administrator" in r.json()["detail"].lower()


def test_cannot_deactivate_last_active_admin(client, db):
    """PATCH /auth/users/{id} to deactivate the only active admin → 400."""
    admin = _make_user(db, "admin1", UserRole.ADMIN)
    r = client.patch(
        f"/auth/users/{admin.id}",
        headers=_auth(admin),
        json={"is_active": False},
    )
    assert r.status_code == 400, f"Expected 400, got {r.status_code}: {r.text}"
    assert "last active administrator" in r.json()["detail"].lower()


def test_can_demote_admin_when_another_exists(client, db):
    """PATCH /auth/users/{id} to demote an admin → 200 when another active admin exists."""
    admin1 = _make_user(db, "admin1", UserRole.ADMIN)
    admin2 = _make_user(db, "admin2", UserRole.ADMIN)
    r = client.patch(
        f"/auth/users/{admin1.id}",
        headers=_auth(admin2),
        json={"role": "OPERATOR"},
    )
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    assert r.json()["role"] == "OPERATOR"


def test_role_update_persisted_correctly(client, db):
    """Updated role is returned and verifiable via GET /auth/users."""
    admin = _make_user(db, "admin1", UserRole.ADMIN)
    op = _make_user(db, "op1", UserRole.OPERATOR)
    # Promote op to APPROVER
    r = client.patch(
        f"/auth/users/{op.id}",
        headers=_auth(admin),
        json={"role": "APPROVER"},
    )
    assert r.status_code == 200
    assert r.json()["role"] == "APPROVER"
    # Verify via user list
    users_r = client.get("/auth/users", headers=_auth(admin))
    assert users_r.status_code == 200
    op_data = next((u for u in users_r.json() if u["id"] == op.id), None)
    assert op_data is not None
    assert op_data["role"] == "APPROVER"


# ===========================================================================
# 6. GET /apis/tools — sanitized OPERATOR view
# ===========================================================================

def test_operator_can_get_api_tools(client, db):
    """OPERATOR calling GET /apis/tools → 200 with sanitized data (no base_url/endpoints/auth_header_name)."""
    op = _make_user(db, "op1", UserRole.OPERATOR)
    api = _make_api(db)
    r = client.get("/apis/tools", headers=_auth(op))
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    data = r.json()
    assert isinstance(data, list)
    assert len(data) == 1
    tool = data[0]
    assert "id" in tool
    assert "name" in tool
    # Must NOT expose internal API details
    assert "base_url" not in tool, "base_url must not be exposed to OPERATOR"
    assert "endpoints" not in tool, "endpoints must not be exposed to OPERATOR"
    assert "auth_header_name" not in tool, "auth_header_name must not be exposed to OPERATOR"
    assert "auth_header_value" not in tool, "auth_header_value must not be exposed to OPERATOR"


def test_operator_cannot_access_full_api_registry(client, db):
    """OPERATOR calling GET /apis → 403."""
    op = _make_user(db, "op1", UserRole.OPERATOR)
    _make_api(db)
    r = client.get("/apis", headers=_auth(op))
    assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"


def test_approver_can_access_full_api_registry(client, db):
    """APPROVER calling GET /apis → 200 with full data."""
    apr = _make_user(db, "apr1", UserRole.APPROVER)
    _make_api(db)
    r = client.get("/apis", headers=_auth(apr))
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    data = r.json()
    assert len(data) == 1
    assert "base_url" in data[0]


# ===========================================================================
# 7. Self-approval enforcement
# ===========================================================================

def test_operator_cannot_self_approve_even_as_admin(client, db):
    """An ADMIN who requested a task cannot approve their own request."""
    admin = _make_user(db, "admin1", UserRole.ADMIN)
    api = _make_api(db)
    appr = _make_approval(db, api, admin)  # Admin submitted this
    r = client.post(f"/approvals/{appr.id}/approve", headers=_auth(admin))
    assert r.status_code == 403, f"Expected 403 (self-approval blocked), got {r.status_code}: {r.text}"
    assert "self-approval" in r.json()["detail"].lower()


# ===========================================================================
# 8. Unauthenticated requests always blocked
# ===========================================================================

def test_unauthenticated_access_blocked(client):
    """Unauthenticated requests to protected endpoints must return 401 or 403."""
    endpoints = [
        ("GET", "/apis"),
        ("GET", "/apis/tools"),
        ("GET", "/approvals"),
        ("POST", "/tasks"),
        ("GET", "/auth/users"),
        ("GET", "/system/metrics"),
    ]
    for method, endpoint in endpoints:
        r = client.request(method, endpoint)
        assert r.status_code in (401, 403), (
            f"{method} {endpoint} expected 401/403 without auth, got {r.status_code}"
        )


# ===========================================================================
# 9. Backend Response Sanitization for OPERATOR (Requirement #2)
# ===========================================================================

def test_operator_approvals_my_and_by_id_sanitized(client, db):
    """OPERATOR responses on /approvals/my and /approvals/{id} must not expose internal API details."""
    op = _make_user(db, "op_san", UserRole.OPERATOR)
    api = _make_api(db)
    appr = _make_approval(db, api, op)

    # List endpoint
    r_list = client.get("/approvals/my", headers=_auth(op))
    assert r_list.status_code == 200
    items = r_list.json()
    assert len(items) == 1
    item = items[0]
    assert item["api_name"] == "Test Hotel API"
    assert item["endpoint_path"] is None
    assert item["http_method"] is None
    assert item["request_payload"] is None
    assert item["classification_reason"] is None
    assert item["api_registry_id"] is None

    # Detail endpoint
    r_detail = client.get(f"/approvals/{appr.id}", headers=_auth(op))
    assert r_detail.status_code == 200
    detail = r_detail.json()
    assert detail["endpoint_path"] is None
    assert detail["http_method"] is None
    assert detail["request_payload"] is None
    assert detail["classification_reason"] is None
    assert detail["api_registry_id"] is None


def test_operator_logs_and_log_detail_sanitized(client, db):
    """OPERATOR responses on /logs and /logs/{id} must not expose HTTP internals or raw payloads."""
    op = _make_user(db, "op_log_san", UserRole.OPERATOR)
    api = _make_api(db)
    log = _make_log(db, api, op)

    r_list = client.get("/logs", headers=_auth(op))
    assert r_list.status_code == 200
    items = r_list.json()
    assert len(items) == 1
    item = items[0]
    assert item["api_name"] == "Test Hotel API"
    assert item["endpoint_path"] is None
    assert item["http_method"] is None
    assert item["request_payload"] is None
    assert item["response_body"] is None
    assert item["response_status_code"] is None
    assert item["api_registry_id"] is None

    r_detail = client.get(f"/logs/{log.id}", headers=_auth(op))
    assert r_detail.status_code == 200
    detail = r_detail.json()
    assert detail["endpoint_path"] is None
    assert detail["http_method"] is None
    assert detail["request_payload"] is None
    assert detail["response_body"] is None
    assert detail["api_registry_id"] is None


def test_operator_post_tasks_sanitized_sensitive_and_safe(client, db):
    """POST /tasks for OPERATOR must strip endpoint_path, http_method, request_payload, classification_reason, response_body."""
    from unittest.mock import patch, AsyncMock
    from app.schemas.tasks import TaskExecutionResult

    op = _make_user(db, "op_task_san", UserRole.OPERATOR)
    api = _make_api(db)

    # Case 1: SENSITIVE action -> 202 sanitized
    sensitive_plan = TaskExecutionResult(
        status="PLAN_CREATED",
        api_id=api.id,
        api_name=api.name,
        endpoint_path="/bookings/105",
        http_method="DELETE",
        is_sensitive=True,
        request_payload={"booking_id": 105},
        message="Plan created",
    )
    with patch("app.routers.tasks.orchestrate_task", new=AsyncMock(return_value=sensitive_plan)):
        r = client.post("/tasks", headers=_auth(op), json={"task": "Cancel booking 105"})
        assert r.status_code == 202
        body = r.json()
        assert body["status"] == "AWAITING_APPROVAL"
        assert body["api_name"] == "Test Hotel API"
        assert body["approval_id"] is not None
        assert body["api_id"] is None
        assert body["endpoint_path"] is None
        assert body["http_method"] is None
        assert body["request_payload"] is None
        assert body["classification_reason"] is None

    # Case 2: Unmatched / error plan -> sanitized
    failed_plan = TaskExecutionResult(
        status="VALIDATION_FAILED",
        api_id=api.id,
        api_name=api.name,
        endpoint_path="/bookings/105",
        http_method="DELETE",
        message="Internal schema error on field X",
    )
    with patch("app.routers.tasks.orchestrate_task", new=AsyncMock(return_value=failed_plan)):
        r_err = client.post("/tasks", headers=_auth(op), json={"task": "Do something invalid"})
        assert r_err.status_code == 200
        err_body = r_err.json()
        assert err_body["endpoint_path"] is None
        assert err_body["http_method"] is None
        assert err_body["api_id"] is None
        assert "Internal schema error" not in err_body["message"]


# ===========================================================================
# 10. Approver Log Scoping (No Unrestricted Administrative Logs)
# ===========================================================================

def test_approver_cannot_access_unrestricted_safe_logs(client, db):
    """APPROVER can only see approval-linked or FAILED logs, not arbitrary safe read-only logs."""
    apr = _make_user(db, "apr_scope", UserRole.APPROVER)
    op = _make_user(db, "op_scope", UserRole.OPERATOR)
    api = _make_api(db)
    appr = _make_approval(db, api, op, status=ApprovalStatus.APPROVED)

    safe_log = _make_log(db, api, op)  # approval_request_id=None, status=SUCCESS
    approved_log = ExecutionLog(
        id=str(uuid.uuid4()),
        api_registry_id=api.id,
        approval_request_id=appr.id,
        endpoint_path="/bookings/105",
        http_method="DELETE",
        request_payload={"booking_id": 105},
        status=ExecutionStatus.SUCCESS,
        response_status_code=200,
        executed_by_user_id=apr.id,
    )
    failed_log = ExecutionLog(
        id=str(uuid.uuid4()),
        api_registry_id=api.id,
        approval_request_id=None,
        endpoint_path="/bookings/999",
        http_method="GET",
        request_payload={},
        status=ExecutionStatus.FAILED,
        error_message="Upstream timeout",
        executed_by_user_id=op.id,
    )
    db.add_all([approved_log, failed_log])
    db.commit()

    # GET /logs for APPROVER excludes safe_log, includes approved_log and failed_log
    r = client.get("/logs", headers=_auth(apr))
    assert r.status_code == 200
    returned_ids = {item["id"] for item in r.json()}
    assert safe_log.id not in returned_ids
    assert approved_log.id in returned_ids
    assert failed_log.id in returned_ids

    # Direct GET /logs/{safe_log.id} by APPROVER -> 403 Forbidden
    r_direct = client.get(f"/logs/{safe_log.id}", headers=_auth(apr))
    assert r_direct.status_code == 403

    # Direct GET /logs/{approved_log.id} and /logs/{failed_log.id} by APPROVER -> 200 OK
    assert client.get(f"/logs/{approved_log.id}", headers=_auth(apr)).status_code == 200
    assert client.get(f"/logs/{failed_log.id}", headers=_auth(apr)).status_code == 200


# ===========================================================================
# 11. Rejection Reason Validation & Audit Binding (Requirement #4)
# ===========================================================================

def test_rejection_reason_validation_rejects_blank_or_too_short(client, db):
    """Whitespace-only or overly short rejection reasons are rejected with 422."""
    apr = _make_user(db, "apr_val", UserRole.APPROVER)
    op = _make_user(db, "op_val", UserRole.OPERATOR)
    api = _make_api(db)
    appr = _make_approval(db, api, op)

    r_ws = client.post(
        f"/approvals/{appr.id}/reject",
        headers=_auth(apr),
        json={"reason": "    "},
    )
    assert r_ws.status_code == 422

    r_short = client.post(
        f"/approvals/{appr.id}/reject",
        headers=_auth(apr),
        json={"reason": "no"},
    )
    assert r_short.status_code == 422

    # Valid reason succeeds and permanently records approver username & timestamp
    r_ok = client.post(
        f"/approvals/{appr.id}/reject",
        headers=_auth(apr),
        json={"reason": "Customer verification incomplete."},
    )
    assert r_ok.status_code == 200
    data = r_ok.json()["approval"]
    assert data["rejection_reason"] == "Customer verification incomplete."
    assert data["decided_by_username"] == "apr_val"
    assert data["decided_at"] is not None

    # Cannot re-decide or overwrite rejection reason after decision
    r_replay = client.post(
        f"/approvals/{appr.id}/reject",
        headers=_auth(apr),
        json={"reason": "Attempted overwrite"},
    )
    assert r_replay.status_code == 409


# ===========================================================================
# 12. Approval Frozen Payload Immutability (Requirement #7)
# ===========================================================================

def test_approval_executes_exact_frozen_payload(client, db):
    """Approving a request executes strictly the DB-frozen payload, ignoring any tampered request body."""
    from unittest.mock import patch, AsyncMock

    apr = _make_user(db, "apr_immut", UserRole.APPROVER)
    op = _make_user(db, "op_immut", UserRole.OPERATOR)
    api = _make_api(db)
    appr = _make_approval(db, api, op)  # frozen payload: {"booking_id": 105}

    captured = {}

    async def fake_execute_api_call(db, api, endpoint_path, http_method, payload, approval_request_id, executed_by_user_id, is_demo_execution=False, demo_session_id=None):
        captured["endpoint_path"] = endpoint_path
        captured["http_method"] = http_method
        captured["payload"] = payload
        log = ExecutionLog(
            id=str(uuid.uuid4()),
            api_registry_id=api.id,
            approval_request_id=approval_request_id,
            endpoint_path=endpoint_path,
            http_method=http_method,
            request_payload=payload,
            status=ExecutionStatus.SUCCESS,
            response_status_code=200,
            executed_by_user_id=executed_by_user_id,
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        return log

    with patch("app.services.approval_service.execute_api_call", new=fake_execute_api_call):
        # Attempt to pass a tampered payload in the approve POST body
        r = client.post(
            f"/approvals/{appr.id}/approve",
            headers=_auth(apr),
            json={"request_payload": {"booking_id": 999, "admin_override": True}},
        )
        assert r.status_code == 200
        assert captured["endpoint_path"] == "/bookings/105"
        assert captured["http_method"] == "DELETE"
        assert captured["payload"] == {"booking_id": 105}


# ===========================================================================
# 13. User Deactivation & Patch Validation (Requirement #3)
# ===========================================================================

def test_deactivating_user_immediately_blocks_active_jwt(client, db):
    """Deactivating a user via PATCH /auth/users/{id} immediately blocks their existing JWT."""
    admin = _make_user(db, "admin_deact", UserRole.ADMIN)
    op = _make_user(db, "op_deact", UserRole.OPERATOR)
    op_headers = _auth(op)

    assert client.get("/auth/me", headers=op_headers).status_code == 200

    r_patch = client.patch(
        f"/auth/users/{op.id}",
        headers=_auth(admin),
        json={"is_active": False},
    )
    assert r_patch.status_code == 200
    assert r_patch.json()["is_active"] is False

    # Existing token must immediately be rejected with 403
    r_after = client.get("/auth/me", headers=op_headers)
    assert r_after.status_code == 403


def test_patch_user_validation_errors(client, db):
    """Invalid UUID or empty PATCH payload returns 400."""
    admin = _make_user(db, "admin_p_val", UserRole.ADMIN)
    assert client.patch("/auth/users/not-a-uuid", headers=_auth(admin), json={"role": "OPERATOR"}).status_code == 400
    assert client.patch(f"/auth/users/{admin.id}", headers=_auth(admin), json={}).status_code == 400


def test_last_active_admin_protected_even_when_inactive_admin_exists(client, db):
    """Having an inactive admin account does NOT satisfy active-admin minimum."""
    active_admin = _make_user(db, "active_admin", UserRole.ADMIN, is_active=True)
    _make_user(db, "inactive_admin", UserRole.ADMIN, is_active=False)

    r_demote = client.patch(
        f"/auth/users/{active_admin.id}",
        headers=_auth(active_admin),
        json={"role": "APPROVER"},
    )
    assert r_demote.status_code == 400
    r_deact = client.patch(
        f"/auth/users/{active_admin.id}",
        headers=_auth(active_admin),
        json={"is_active": False},
    )
    assert r_deact.status_code == 400


def test_operator_and_approver_cannot_put_or_delete_apis(client, db):
    """PUT and DELETE /apis/{id} are strictly ADMIN-only (403 for OPERATOR and APPROVER)."""
    op = _make_user(db, "op_mut", UserRole.OPERATOR)
    apr = _make_user(db, "apr_mut", UserRole.APPROVER)
    api = _make_api(db)

    for user in (op, apr):
        r_put = client.put(
            f"/apis/{api.id}",
            headers=_auth(user),
            json={"description": "Tampered"},
        )
        assert r_put.status_code == 403
        r_del = client.delete(f"/apis/{api.id}", headers=_auth(user))
        assert r_del.status_code == 403


def test_approver_cannot_replay_out_of_scope_safe_log(client, db):
    """APPROVER cannot replay an unrelated safe execution log (403 Forbidden)."""
    apr = _make_user(db, "apr_rep", UserRole.APPROVER)
    op = _make_user(db, "op_rep", UserRole.OPERATOR)
    api = _make_api(db)
    safe_log = _make_log(db, api, op)

    r = client.post(f"/logs/{safe_log.id}/replay", headers=_auth(apr))
    assert r.status_code == 403


def test_operator_post_tasks_safe_execution_fully_sanitized(client, db):
    """POST /tasks SAFE execution for OPERATOR strips HTTP status, method, path, payload, response_body, and classification_reason."""
    from unittest.mock import patch, AsyncMock
    from app.schemas.tasks import TaskExecutionResult

    op = _make_user(db, "op_safe_san", UserRole.OPERATOR)
    api = APIRegistry(
        id=str(uuid.uuid4()),
        name="Weather Service",
        description="Safe read-only weather",
        base_url="https://weather.example.com",
        endpoints=[{"path": "/v1/forecast", "method": "GET", "description": "Get forecast"}],
        is_sensitive=False,
    )
    db.add(api)
    db.commit()
    db.refresh(api)

    safe_plan = TaskExecutionResult(
        status="PLAN_CREATED",
        api_id=api.id,
        api_name=api.name,
        endpoint_path="/v1/forecast",
        http_method="GET",
        is_sensitive=False,
        request_payload={"city": "London"},
        message="Plan created",
    )

    async def fake_exec(db, api, endpoint_path, http_method, payload, executed_by_user_id, is_demo_execution=False, demo_session_id=None):
        log = ExecutionLog(
            id=str(uuid.uuid4()),
            api_registry_id=api.id,
            endpoint_path=endpoint_path,
            http_method=http_method,
            request_payload=payload,
            status=ExecutionStatus.SUCCESS,
            response_status_code=200,
            response_body={"temp_c": 18, "internal_node": "eu-west-1a"},
            duration_ms=25.0,
            executed_by_user_id=executed_by_user_id,
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        return log

    with patch("app.routers.tasks.orchestrate_task", new=AsyncMock(return_value=safe_plan)):
        with patch("app.routers.tasks.execute_api_call", new=fake_exec):
            r = client.post("/tasks", headers=_auth(op), json={"task": "Check weather in London"})
            assert r.status_code == 200
            body = r.json()
            assert body["status"] == "EXECUTED_SAFE"
            assert body["api_name"] == "Weather Service"
            assert body["api_id"] is None
            assert body["endpoint_path"] is None
            assert body["http_method"] is None
            assert body["request_payload"] is None
            assert body["classification_reason"] is None
            assert body["response_body"] is None
            assert body["response_status_code"] is None


# ===========================================================================
# 14. Alembic Migration Compatibility (SQLite + PostgreSQL DDL)
# ===========================================================================

def test_alembic_migration_sqlite_upgrade_and_downgrade(tmp_path):
    """Verifies Alembic upgrade adds rejection_reason on legacy SQLite preserving data, and downgrade removes it cleanly."""
    import os
    import sqlite3
    from alembic.config import Config
    from alembic import command

    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    db_file = tmp_path / "legacy_sqlite.db"

    # Seed legacy approval_requests table WITHOUT rejection_reason
    conn = sqlite3.connect(str(db_file))
    conn.execute("CREATE TABLE approval_requests (id VARCHAR(36) PRIMARY KEY, status VARCHAR(20) NOT NULL)")
    conn.execute("INSERT INTO approval_requests (id, status) VALUES ('legacy-row-1', 'PENDING')")
    conn.commit()
    conn.close()

    cfg = Config(os.path.join(backend_dir, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(backend_dir, "alembic"))
    cfg.cmd_opts = type("Opts", (), {"x": [f"db_url=sqlite:///{db_file.as_posix()}"]})()

    # 1. Upgrade to head
    command.upgrade(cfg, "head")
    conn = sqlite3.connect(str(db_file))
    cols_up = [row[1] for row in conn.execute("PRAGMA table_info(approval_requests)").fetchall()]
    rows_up = conn.execute("SELECT id, status, rejection_reason FROM approval_requests").fetchall()
    conn.close()
    assert "rejection_reason" in cols_up
    assert rows_up == [("legacy-row-1", "PENDING", None)]

    # 2. Downgrade to base
    command.downgrade(cfg, "base")
    conn = sqlite3.connect(str(db_file))
    cols_down = [row[1] for row in conn.execute("PRAGMA table_info(approval_requests)").fetchall()]
    rows_down = conn.execute("SELECT id, status FROM approval_requests").fetchall()
    conn.close()
    assert "rejection_reason" not in cols_down
    assert rows_down == [("legacy-row-1", "PENDING")]

    # 3. Re-upgrade to head (idempotency)
    command.upgrade(cfg, "head")
    conn = sqlite3.connect(str(db_file))
    cols_reup = [row[1] for row in conn.execute("PRAGMA table_info(approval_requests)").fetchall()]
    conn.close()
    assert "rejection_reason" in cols_reup


def test_alembic_migration_postgresql_ddl_generation(capsys):
    """Verifies Alembic generates valid transactional PostgreSQL ALTER TABLE DDL for rejection_reason."""
    import os
    from alembic.config import Config
    from alembic import command

    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cfg = Config(os.path.join(backend_dir, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(backend_dir, "alembic"))
    cfg.cmd_opts = type("Opts", (), {"x": ["db_url=postgresql://user:pass@localhost/gateway"]})()

    command.upgrade(cfg, "head", sql=True)
    ddl = capsys.readouterr().out
    assert "ALTER TABLE approval_requests ADD COLUMN rejection_reason TEXT;" in ddl
    assert "BEGIN;" in ddl and "COMMIT;" in ddl



