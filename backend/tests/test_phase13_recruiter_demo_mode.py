"""
backend/tests/test_phase13_recruiter_demo_mode.py

Phase 13: Recruiter Demo Mode — Per-Session Isolation, Security, Abuse Protection & Migration Tests.

Verifies:
1.  Each demo option authenticates into a brand-new per-visitor isolated demo_session_id with real signed JWT.
2.  Concurrent demo visitors (Recruiter A vs Recruiter B) cannot see, inspect, approve, reject, or interfere
    with each other's demo approvals, logs, APIs, or users (403 Forbidden).
3.  POST /auth/demo-switch switches roles within the caller's own server-verified demo_session_id and
    atomically revokes the previous role's JWT (401 on reuse).
4.  Demo User cannot access Approver/Admin endpoints and receives strictly sanitized responses.
5.  Demo Approver cannot access Admin endpoints, enforces mandatory rejection reason & anti-self-approval.
6.  Demo Admin can read all 8 Admin dashboard endpoints (demo-session-scoped) while blocked (403) from
    every write/destructive/production action.
7.  Hard cross-environment isolation: demo accounts cannot read/modify real records, AND real accounts
    cannot see or modify demo records.
8.  Zero external network calls: demo task execution and demo approval execution never call httpx or DNS.
9.  Demo sessions cannot bypass normal authentication (blocked password login, claim mismatch, toggle off).
10. Demo abuse protection: rate limiting on /auth/demo-login, rate limiting on POST /tasks, per-session
    action cap, bounded FIFO/TTL cleanup, and session reset — never affecting real application data.
11. Alembic migrations (0001 -> 0002 -> 0003) verified on SQLite (preserving real data) and PostgreSQL DDL.
"""

from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from app.config import settings
settings.initial_admin_password = "test_password_to_bypass_icacls"

from app.main import app
from app.database import Base, engine, SessionLocal
from app.models.user import User
from app.models.api_registry import APIRegistry
from app.models.approval_request import ApprovalRequest
from app.models.execution_log import ExecutionLog
from app.models.enums import UserRole, ApprovalStatus, ExecutionStatus
from app.services.auth_service import reset_burst_rate_limit
from app.services.demo_service import reset_demo_rate_limits, cleanup_expired_demo_sessions
from app.utils.auth import hash_password, create_access_token


@pytest.fixture(autouse=True)
def clean_db():
    reset_burst_rate_limit()
    reset_demo_rate_limits()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    reset_burst_rate_limit()
    reset_demo_rate_limits()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def _demo_login(client, role: str):
    r = client.post("/auth/demo-login", json={"role": role})
    assert r.status_code == 200, f"Demo login '{role}' failed: {r.status_code} {r.text}"
    data = r.json()
    return data, {"Authorization": f"Bearer {data['access_token']}"}


def _demo_switch(client, headers: dict, role: str):
    r = client.post("/auth/demo-switch", headers=headers, json={"role": role})
    assert r.status_code == 200, f"Demo switch '{role}' failed: {r.status_code} {r.text}"
    data = r.json()
    return data, {"Authorization": f"Bearer {data['access_token']}"}


def _seed_real_production_records():
    """Creates real (non-demo) users, API with secret, approval, and execution log."""
    db = SessionLocal()
    try:
        real_admin = User(
            username="real_prod_admin",
            hashed_password=hash_password("RealAdminPass123!"),
            role=UserRole.ADMIN,
            is_active=True,
            is_demo=False,
        )
        real_user = User(
            username="real_prod_customer",
            hashed_password=hash_password("RealCustomerPass123!"),
            role=UserRole.OPERATOR,
            is_active=True,
            is_demo=False,
        )
        db.add_all([real_admin, real_user])
        db.flush()

        real_api = APIRegistry(
            name="Production Treasury API",
            base_url="https://treasury.internal-prod.example.com",
            description="Real production wire service",
            auth_header_name="Authorization",
            auth_header_value="Bearer REAL_PROD_SUPER_SECRET_999",
            is_sensitive=True,
            is_demo=False,
            endpoints=[{"path": "/v1/wire", "method": "POST", "description": "Wire funds"}],
        )
        db.add(real_api)
        db.flush()

        real_appr = ApprovalRequest(
            api_registry_id=real_api.id,
            endpoint_path="/v1/wire",
            http_method="POST",
            request_payload={"amount": 50000, "account": "PROD-ACCT-77"},
            status=ApprovalStatus.PENDING,
            classification_reason="Real production wire transfer",
            requested_by_user_id=real_user.id,
            is_demo=False,
        )
        real_log = ExecutionLog(
            api_registry_id=real_api.id,
            endpoint_path="/v1/wire",
            http_method="GET",
            request_payload={"account": "PROD-ACCT-77"},
            response_body={"balance": 999999},
            response_status_code=200,
            status=ExecutionStatus.SUCCESS,
            executed_by_user_id=real_user.id,
            is_demo=False,
        )
        db.add_all([real_appr, real_log])
        db.commit()

        return {
            "real_admin_id": real_admin.id,
            "real_user_id": real_user.id,
            "real_admin_token": create_access_token(
                real_admin.id, real_admin.username, real_admin.role.value, is_demo=False
            ),
            "real_api_id": real_api.id,
            "real_appr_id": real_appr.id,
            "real_log_id": real_log.id,
        }
    finally:
        db.close()


# ===========================================================================
# 1. Each Demo Option Authenticates into Its Own Isolated Demo Session
# ===========================================================================

def test_demo_login_authenticates_all_three_roles_with_unique_sessions(client):
    user_data, user_headers = _demo_login(client, "user")
    assert user_data["role"] == "OPERATOR"
    assert user_data["username"].startswith("demo_user_")
    assert user_data["is_demo"] is True
    assert user_data["demo_session_id"] is not None
    me_user = client.get("/auth/me", headers=user_headers)
    assert me_user.status_code == 200
    assert me_user.json()["is_demo"] is True
    assert me_user.json()["demo_session_id"] == user_data["demo_session_id"]

    appr_data, _ = _demo_login(client, "approver")
    assert appr_data["role"] == "APPROVER"
    assert appr_data["username"].startswith("demo_approver_")
    assert appr_data["demo_session_id"] != user_data["demo_session_id"]

    admin_data, _ = _demo_login(client, "admin")
    assert admin_data["role"] == "ADMIN"
    assert admin_data["username"].startswith("demo_admin_")
    assert admin_data["demo_session_id"] not in (user_data["demo_session_id"], appr_data["demo_session_id"])

    # Invalid role rejected with 422
    assert client.post("/auth/demo-login", json={"role": "superadmin"}).status_code == 422


# ===========================================================================
# 2. Concurrent Visitors Strictly Isolated (Recruiter A vs Recruiter B)
# ===========================================================================

def test_concurrent_demo_visitors_strictly_isolated(client):
    # Recruiter A enters as User and submits a new sensitive cancellation
    rec_a_user, rec_a_user_h = _demo_login(client, "user")
    r_cancel = client.post("/tasks", headers=rec_a_user_h, json={"task": "Cancel my booking 555"})
    assert r_cancel.status_code == 202
    rec_a_appr_id = r_cancel.json()["approval_id"]

    # Recruiter A also gets a safe execution log
    r_safe = client.post("/tasks", headers=rec_a_user_h, json={"task": "View reservation status for booking 555"})
    assert r_safe.status_code == 200
    rec_a_log_id = r_safe.json()["execution_log_id"]

    # Recruiter B starts a separate concurrent session as Approver and switches to Admin
    rec_b_appr, rec_b_appr_h = _demo_login(client, "approver")
    assert rec_b_appr["demo_session_id"] != rec_a_user["demo_session_id"]

    # Recruiter B's pending approvals do NOT include Recruiter A's booking 555
    rec_b_pending = client.get("/approvals?status=PENDING", headers=rec_b_appr_h).json()
    assert all(a["id"] != rec_a_appr_id for a in rec_b_pending)

    # Recruiter B attempting direct UUID access/approval/rejection on Recruiter A's records -> 403
    assert client.get(f"/approvals/{rec_a_appr_id}", headers=rec_b_appr_h).status_code == 403
    assert client.post(f"/approvals/{rec_a_appr_id}/approve", headers=rec_b_appr_h).status_code == 403
    assert client.post(
        f"/approvals/{rec_a_appr_id}/reject",
        headers=rec_b_appr_h,
        json={"reason": "Cross-session interference attempt"},
    ).status_code == 403
    assert client.get(f"/logs/{rec_a_log_id}", headers=rec_b_appr_h).status_code == 403

    # Recruiter B switches to Admin -> still cannot see or inspect Recruiter A's APIs/logs/users
    _, rec_b_admin_h = _demo_switch(client, rec_b_appr_h, "admin")
    assert client.get(f"/approvals/{rec_a_appr_id}", headers=rec_b_admin_h).status_code == 403
    assert client.get(f"/logs/{rec_a_log_id}", headers=rec_b_admin_h).status_code == 403

    # Recruiter A switches from User to Approver inside THEIR OWN session -> sees & approves booking 555!
    rec_a_appr, rec_a_appr_h = _demo_switch(client, rec_a_user_h, "approver")
    assert rec_a_appr["demo_session_id"] == rec_a_user["demo_session_id"]
    # Previous User JWT was atomically revoked on switch
    assert client.get("/auth/me", headers=rec_a_user_h).status_code == 401

    r_ok = client.post(f"/approvals/{rec_a_appr_id}/approve", headers=rec_a_appr_h)
    assert r_ok.status_code == 200
    assert r_ok.json()["approval"]["status"] == "APPROVED"


# ===========================================================================
# 3. Demo User RBAC & Response Sanitization
# ===========================================================================

def test_demo_user_cannot_access_approver_or_admin_endpoints(client):
    user_data, user_headers = _demo_login(client, "user")
    # Fetch one of the seeded approvals in this session via DB to test direct approval calls
    db = SessionLocal()
    try:
        appr = (
            db.query(ApprovalRequest)
            .filter_by(is_demo=True, demo_session_id=user_data["demo_session_id"], status=ApprovalStatus.PENDING)
            .first()
        )
        appr_id = appr.id
    finally:
        db.close()

    assert client.get("/apis", headers=user_headers).status_code == 403
    assert client.post("/apis", headers=user_headers, json={"name": "x", "base_url": "https://x.com", "endpoints": []}).status_code == 403
    assert client.get("/approvals", headers=user_headers).status_code == 403
    assert client.post(f"/approvals/{appr_id}/approve", headers=user_headers).status_code == 403
    assert client.post(f"/approvals/{appr_id}/reject", headers=user_headers, json={"reason": "Not allowed"}).status_code == 403
    assert client.get("/auth/users", headers=user_headers).status_code == 403
    assert client.get("/system/metrics", headers=user_headers).status_code == 403

    # Own /approvals/my and /logs are strictly sanitized
    my_reqs = client.get("/approvals/my", headers=user_headers).json()
    assert len(my_reqs) >= 1
    for item in my_reqs:
        assert item["endpoint_path"] is None
        assert item["http_method"] is None
        assert item["request_payload"] is None
        assert item["classification_reason"] is None
        assert item["api_registry_id"] is None

    my_logs = client.get("/logs", headers=user_headers).json()
    assert len(my_logs) >= 1
    for log in my_logs:
        assert log["endpoint_path"] is None
        assert log["http_method"] is None
        assert log["request_payload"] is None
        assert log["response_body"] is None
        assert log["response_status_code"] is None


# ===========================================================================
# 4. Demo Approver Workflow, Mandatory Rejection Reason & Anti-Self-Approval
# ===========================================================================

def test_demo_approver_cannot_access_admin_and_can_decide_demo_requests(client):
    appr_data, appr_headers = _demo_login(client, "approver")

    assert client.post("/tasks", headers=appr_headers, json={"task": "Cancel booking 105"}).status_code == 403
    assert client.post("/apis", headers=appr_headers, json={"name": "x", "base_url": "https://x.com", "endpoints": []}).status_code == 403
    assert client.get("/auth/users", headers=appr_headers).status_code == 403
    assert client.get("/system/metrics", headers=appr_headers).status_code == 403

    pending = client.get("/approvals?status=PENDING", headers=appr_headers).json()
    assert len(pending) == 2

    target_reject = pending[0]["id"]
    assert client.post(f"/approvals/{target_reject}/reject", headers=appr_headers).status_code == 422
    assert client.post(f"/approvals/{target_reject}/reject", headers=appr_headers, json={"reason": "  "}).status_code == 422

    r_rej = client.post(
        f"/approvals/{target_reject}/reject",
        headers=appr_headers,
        json={"reason": "Guest identity verification required before refund."},
    )
    assert r_rej.status_code == 200
    assert r_rej.json()["approval"]["status"] == "REJECTED"
    assert r_rej.json()["approval"]["rejection_reason"] == "Guest identity verification required before refund."

    # Anti-self-approval enforced inside demo session
    db = SessionLocal()
    try:
        demo_appr_user = db.query(User).filter_by(id=appr_data["user_id"]).first()
        demo_api = db.query(APIRegistry).filter_by(demo_session_id=appr_data["demo_session_id"]).first()
        self_req = ApprovalRequest(
            api_registry_id=demo_api.id,
            endpoint_path="/v1/bookings/cancel",
            http_method="POST",
            request_payload={"booking_id": 777},
            status=ApprovalStatus.PENDING,
            classification_reason="Self-requested test",
            requested_by_user_id=demo_appr_user.id,
            is_demo=True,
            demo_session_id=appr_data["demo_session_id"],
        )
        db.add(self_req)
        db.commit()
        self_req_id = self_req.id
    finally:
        db.close()

    r_self = client.post(f"/approvals/{self_req_id}/approve", headers=appr_headers)
    assert r_self.status_code == 403
    assert "self-approval" in r_self.json()["detail"].lower()


# ===========================================================================
# 5. Demo Admin Dashboard Read Endpoints Work & All Mutations Return 403
# ===========================================================================

def test_demo_admin_read_only_dashboard_works_and_mutations_blocked(client):
    prod = _seed_real_production_records()
    admin_data, admin_headers = _demo_login(client, "admin")

    # Every read endpoint powering the 8 Admin Dashboard tabs succeeds (200) and is strictly session-scoped
    apis_r = client.get("/apis", headers=admin_headers)
    assert apis_r.status_code == 200
    apis = apis_r.json()
    assert len(apis) == 2
    assert all(a["id"] != prod["real_api_id"] for a in apis)

    users_r = client.get("/auth/users", headers=admin_headers)
    assert users_r.status_code == 200
    users = users_r.json()
    assert len(users) == 4
    assert all(u["is_demo"] is True and u["demo_session_id"] == admin_data["demo_session_id"] for u in users)

    logs_r = client.get("/logs", headers=admin_headers)
    assert logs_r.status_code == 200
    logs = logs_r.json()
    assert len(logs) == 4

    apprs_r = client.get("/approvals?status=PENDING", headers=admin_headers)
    assert apprs_r.status_code == 200
    apprs = apprs_r.json()
    assert len(apprs) == 2

    metrics_r = client.get("/system/metrics", headers=admin_headers)
    assert metrics_r.status_code == 200
    m = metrics_r.json()
    assert m["is_demo"] is True
    assert m["app_env"] == "demo-sandbox"
    assert m["allowed_hosts"] == "demo-sandbox (restricted)"
    assert m["total_apis"] == 2
    assert m["total_users"] == 4
    assert m["pending_approvals"] == 2
    assert m["total_executions"] == 4

    # All write / destructive / execution actions MUST return 403
    demo_api_id = apis[0]["id"]
    demo_user_id = users[0]["id"]
    demo_log_id = logs[0]["id"]
    demo_appr_id = apprs[0]["id"]

    assert client.post("/apis", headers=admin_headers, json={"name": "Rogue", "base_url": "https://evil.com", "endpoints": []}).status_code == 403
    assert client.put(f"/apis/{demo_api_id}", headers=admin_headers, json={"description": "Changed"}).status_code == 403
    assert client.delete(f"/apis/{demo_api_id}", headers=admin_headers).status_code == 403
    assert client.post("/auth/users", headers=admin_headers, json={"username": "evil_admin", "password": "Password123!", "role": "ADMIN"}).status_code == 403
    assert client.patch(f"/auth/users/{demo_user_id}", headers=admin_headers, json={"is_active": False}).status_code == 403
    assert client.patch(f"/auth/users/{prod['real_admin_id']}", headers=admin_headers, json={"is_active": False}).status_code == 403
    assert client.post(f"/logs/{demo_log_id}/replay", headers=admin_headers).status_code == 403
    assert client.post("/tasks", headers=admin_headers, json={"task": "Cancel booking 105"}).status_code == 403
    assert client.post(f"/approvals/{demo_appr_id}/approve", headers=admin_headers).status_code == 403
    assert client.post(f"/approvals/{demo_appr_id}/reject", headers=admin_headers, json={"reason": "Demo admin blocked"}).status_code == 403


# ===========================================================================
# 6. Hard Bidirectional Cross-Environment & Cross-User Isolation
# ===========================================================================

def test_demo_and_real_data_completely_isolated_both_directions(client):
    prod = _seed_real_production_records()
    demo_user_data, demo_user_headers = _demo_login(client, "user")
    _, demo_appr_headers = _demo_switch(client, demo_user_headers, "approver")
    _, demo_admin_headers = _demo_switch(client, demo_appr_headers, "admin")
    # Re-enter user role in same session for cross-user check
    _, demo_user_headers2 = _demo_switch(client, demo_admin_headers, "user")
    # And get fresh admin/approver sessions for concurrent probes
    _, probe_appr_headers = _demo_login(client, "approver")
    _, probe_admin_headers = _demo_login(client, "admin")
    real_admin_headers = {"Authorization": f"Bearer {prod['real_admin_token']}"}

    # Demo -> Real direct UUID probes all return 403
    assert client.get(f"/apis/{prod['real_api_id']}", headers=probe_admin_headers).status_code == 403
    assert client.get(f"/apis/{prod['real_api_id']}", headers=probe_appr_headers).status_code == 403
    assert client.get(f"/approvals/{prod['real_appr_id']}", headers=demo_user_headers2).status_code == 403
    assert client.get(f"/approvals/{prod['real_appr_id']}", headers=probe_appr_headers).status_code == 403
    assert client.get(f"/approvals/{prod['real_appr_id']}", headers=probe_admin_headers).status_code == 403
    assert client.post(f"/approvals/{prod['real_appr_id']}/approve", headers=probe_appr_headers).status_code == 403
    assert client.post(f"/approvals/{prod['real_appr_id']}/reject", headers=probe_appr_headers, json={"reason": "Cross-tenant"}).status_code == 403
    assert client.get(f"/logs/{prod['real_log_id']}", headers=demo_user_headers2).status_code == 403
    assert client.get(f"/logs/{prod['real_log_id']}", headers=probe_appr_headers).status_code == 403
    assert client.get(f"/logs/{prod['real_log_id']}", headers=probe_admin_headers).status_code == 403

    # Real Admin sees ONLY real records, never demo records
    assert len(client.get("/apis", headers=real_admin_headers).json()) == 1
    assert all(u["is_demo"] is False for u in client.get("/auth/users", headers=real_admin_headers).json())
    assert len(client.get("/approvals?status=PENDING", headers=real_admin_headers).json()) == 1
    assert len(client.get("/logs", headers=real_admin_headers).json()) == 1

    # Real Admin attempting to mutate/replay isolated demo records -> 403
    demo_apis = client.get("/apis", headers=probe_admin_headers).json()
    demo_users = client.get("/auth/users", headers=probe_admin_headers).json()
    demo_logs = client.get("/logs", headers=probe_admin_headers).json()
    assert client.put(f"/apis/{demo_apis[0]['id']}", headers=real_admin_headers, json={"description": "x"}).status_code == 403
    assert client.delete(f"/apis/{demo_apis[0]['id']}", headers=real_admin_headers).status_code == 403
    assert client.patch(f"/auth/users/{demo_users[0]['id']}", headers=real_admin_headers, json={"is_active": False}).status_code == 403
    assert client.post(f"/logs/{demo_logs[0]['id']}/replay", headers=real_admin_headers).status_code == 403

    # Cross-user isolation INSIDE demo session: demo_user cannot access demo_guest_claire's records
    db = SessionLocal()
    try:
        claire = (
            db.query(User)
            .filter(User.demo_session_id == demo_user_data["demo_session_id"], User.username.like("demo_guest_claire_%"))
            .first()
        )
        claire_appr = db.query(ApprovalRequest).filter_by(requested_by_user_id=claire.id).first()
        claire_log = db.query(ExecutionLog).filter_by(executed_by_user_id=claire.id).first()
        claire_appr_id, claire_log_id = claire_appr.id, claire_log.id
    finally:
        db.close()

    assert client.get(f"/approvals/{claire_appr_id}", headers=demo_user_headers2).status_code == 403
    assert client.get(f"/logs/{claire_log_id}", headers=demo_user_headers2).status_code == 403


# ===========================================================================
# 7. Zero External Network Calls During Demo Execution
# ===========================================================================

def test_demo_actions_never_call_real_external_apis(client):
    _, demo_user_headers = _demo_login(client, "user")

    def _forbid_network(*args, **kwargs):
        raise AssertionError("SECURITY VIOLATION: Outbound network call attempted during Recruiter Demo Mode!")

    with patch("app.services.executor.resolve_and_verify_host", side_effect=_forbid_network):
        with patch("httpx.AsyncClient", side_effect=_forbid_network):
            r_safe = client.post(
                "/tasks",
                headers=demo_user_headers,
                json={"task": "View reservation details for booking 105"},
            )
            assert r_safe.status_code == 200
            safe_body = r_safe.json()
            assert safe_body["status"] == "EXECUTED_SAFE"
            assert safe_body["execution_status"] == "SUCCESS"
            assert safe_body["endpoint_path"] is None
            assert safe_body["response_body"] is None
            assert safe_body["is_demo_result"] is True
            assert safe_body["result_data"]["booking_id"] == 105
            assert safe_body["result_data"]["status"] == "CONFIRMED"
            assert "guest_name" in safe_body["result_data"]
            assert "room_type" in safe_body["result_data"]
            assert "check_in" in safe_body["result_data"]
            assert "sandbox" not in safe_body["result_data"]

            # Demo error case (booking 404 -> FAILED cleanly reported without result_data)
            r_404 = client.post(
                "/tasks",
                headers=demo_user_headers,
                json={"task": "View reservation details for booking 404"},
            )
            assert r_404.status_code == 200
            body_404 = r_404.json()
            assert body_404["execution_status"] == "FAILED"
            assert body_404["result_data"] is None
            assert body_404["is_demo_result"] is True
            assert "404" in body_404["message"]

            # Verify GET /logs for Demo User also exposes sanitized result_data while hiding raw response_body
            logs = client.get("/logs", headers=demo_user_headers).json()
            success_log = next((l for l in logs if l["id"] == safe_body["execution_log_id"]), None)
            assert success_log is not None
            assert success_log["response_body"] is None
            assert success_log["result_data"]["booking_id"] == 105
            assert success_log["is_demo_result"] is True

            r_sens = client.post(
                "/tasks",
                headers=demo_user_headers,
                json={"task": "Cancel my booking 105"},
            )
            assert r_sens.status_code == 202
            new_appr_id = r_sens.json()["approval_id"]

            # Switch to Approver in SAME isolated demo session and approve
            _, demo_appr_headers = _demo_switch(client, demo_user_headers, "approver")
            r_approve = client.post(f"/approvals/{new_appr_id}/approve", headers=demo_appr_headers)
            assert r_approve.status_code == 200
            assert r_approve.json()["approval"]["status"] == "APPROVED"
            assert r_approve.json()["execution"]["response_body"]["sandbox"] is True


# ===========================================================================
# 8. Auth Hardening: Password Login Blocked, Claim Tampering Blocked, Toggle Off
# ===========================================================================

def test_demo_auth_hardening_and_kill_switch(client):
    admin_data, admin_headers = _demo_login(client, "admin")
    # 1. Demo accounts cannot authenticate via /auth/login
    assert client.post("/auth/login", json={"username": admin_data["username"], "password": "AnyPassword123!"}).status_code == 401

    # 2. Forged/mismatched is_demo or demo_session_id JWT claims rejected (401)
    prod = _seed_real_production_records()
    forged_real = create_access_token(prod["real_admin_id"], "real_prod_admin", "ADMIN", is_demo=True)
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {forged_real}"}).status_code == 401

    forged_wrong_sess = create_access_token(
        admin_data["user_id"], admin_data["username"], "ADMIN", is_demo=True, demo_session_id="00000000-0000-0000-0000-000000000000"
    )
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {forged_wrong_sess}"}).status_code == 401

    # 3. Real user cannot call /auth/demo-switch or /auth/demo-reset (403)
    real_headers = {"Authorization": f"Bearer {prod['real_admin_token']}"}
    assert client.post("/auth/demo-switch", headers=real_headers, json={"role": "user"}).status_code == 403
    assert client.post("/auth/demo-reset", headers=real_headers).status_code == 403

    # 4. Kill switch DEMO_MODE_ENABLED=false disables /auth/demo-login and /auth/demo-switch
    with patch.object(settings, "demo_mode_enabled", False):
        assert client.post("/auth/demo-login", json={"role": "user"}).status_code == 403
        assert client.post("/auth/demo-switch", headers=admin_headers, json={"role": "user"}).status_code == 403


# ===========================================================================
# 9. Demo Abuse Protection: Rate Limits, Action Caps, Bounded Cleanup & Reset
# ===========================================================================

def test_demo_rate_limits_and_per_session_action_cap(client):
    # 1. /auth/demo-login rate limit enforced (429 + Retry-After)
    with patch.object(settings, "demo_login_limit_per_5min", 3):
        reset_demo_rate_limits()
        reset_burst_rate_limit()
        for _ in range(3):
            assert client.post("/auth/demo-login", json={"role": "user"}).status_code == 200
        r_429 = client.post("/auth/demo-login", json={"role": "user"})
        assert r_429.status_code == 429
        assert "Retry-After" in r_429.headers

    # 2. POST /tasks per-minute rate limit enforced for demo user (429)
    reset_demo_rate_limits()
    reset_burst_rate_limit()
    _, user_headers = _demo_login(client, "user")
    with patch.object(settings, "demo_task_limit_per_minute", 2):
        assert client.post("/tasks", headers=user_headers, json={"task": "View reservation status for booking 105"}).status_code == 200
        assert client.post("/tasks", headers=user_headers, json={"task": "View reservation status for booking 105"}).status_code == 200
        r_task_429 = client.post("/tasks", headers=user_headers, json={"task": "View reservation status for booking 105"})
        assert r_task_429.status_code == 429

    # 3. Per-session total demo action cap enforced (429)
    reset_demo_rate_limits()
    reset_burst_rate_limit()
    _, user_headers2 = _demo_login(client, "user")
    # Seeded session starts with 4 approvals + 4 logs = 8 records; cap at 9 allows 1 more, blocks 2nd
    with patch.object(settings, "demo_max_actions_per_session", 9):
        assert client.post("/tasks", headers=user_headers2, json={"task": "View reservation status for booking 105"}).status_code == 200
        r_cap = client.post("/tasks", headers=user_headers2, json={"task": "View reservation status for booking 105"})
        assert r_cap.status_code == 429
        assert "limit reached" in r_cap.json()["detail"].lower()


def test_demo_bounded_cleanup_and_session_reset_preserve_real_data(client):
    prod = _seed_real_production_records()

    # Create 3 isolated demo sessions
    s1, _ = _demo_login(client, "user")
    s2, _ = _demo_login(client, "user")
    s3, s3_headers = _demo_login(client, "user")

    # FIFO cap to 1 active demo session evicts s1 and s2 ONLY — real data untouched
    db = SessionLocal()
    try:
        evicted = cleanup_expired_demo_sessions(db, max_active_sessions=1)
        assert evicted == 2
        remaining_demo_sessions = {
            r[0] for r in db.query(User.demo_session_id).filter(User.is_demo == True).distinct().all()
        }
        assert remaining_demo_sessions == {s3["demo_session_id"]}
        # Verify real production records are 100% untouched
        assert db.query(User).filter_by(id=prod["real_admin_id"]).first() is not None
        assert db.query(APIRegistry).filter_by(id=prod["real_api_id"]).first() is not None
        assert db.query(ApprovalRequest).filter_by(id=prod["real_appr_id"]).first() is not None
        assert db.query(ExecutionLog).filter_by(id=prod["real_log_id"]).first() is not None
    finally:
        db.close()

    # Submit an extra task in s3, then call POST /auth/demo-reset -> restores baseline without affecting real data
    assert client.post("/tasks", headers=s3_headers, json={"task": "Cancel my booking 999"}).status_code == 202
    assert len(client.get("/approvals/my", headers=s3_headers).json()) == 4

    r_reset = client.post("/auth/demo-reset", headers=s3_headers)
    assert r_reset.status_code == 200
    assert len(client.get("/approvals/my", headers=s3_headers).json()) == 3

    # Real data still untouched
    real_headers = {"Authorization": f"Bearer {prod['real_admin_token']}"}
    assert len(client.get("/approvals?status=PENDING", headers=real_headers).json()) == 1


# ===========================================================================
# 10. Alembic Migrations 0001 -> 0002 -> 0003 (SQLite + PostgreSQL DDL)
# ===========================================================================

def test_alembic_full_migration_chain_sqlite_and_postgresql(tmp_path, capsys):
    import os
    import sqlite3
    from alembic.config import Config
    from alembic import command

    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # 1. PostgreSQL offline transactional DDL verification
    pg_cfg = Config(os.path.join(backend_dir, "alembic.ini"))
    pg_cfg.set_main_option("script_location", os.path.join(backend_dir, "alembic"))
    pg_cfg.cmd_opts = type("Opts", (), {"x": ["db_url=postgresql://user:pass@localhost/gateway"]})()
    command.upgrade(pg_cfg, "head", sql=True)
    ddl = capsys.readouterr().out
    assert "ALTER TABLE approval_requests ADD COLUMN rejection_reason TEXT;" in ddl
    assert "ALTER TABLE users ADD COLUMN is_demo BOOLEAN DEFAULT false NOT NULL;" in ddl
    assert "ALTER TABLE users ADD COLUMN demo_session_id VARCHAR(36);" in ddl
    assert "CREATE INDEX ix_approval_requests_demo_session_id ON approval_requests (demo_session_id);" in ddl

    # 2. Legacy SQLite DB upgrade -> preserves existing non-demo rows with is_demo=0 and demo_session_id=NULL
    db_file = tmp_path / "legacy_full.db"
    conn = sqlite3.connect(str(db_file))
    conn.execute("CREATE TABLE users (id VARCHAR(36) PRIMARY KEY, username VARCHAR(100) NOT NULL)")
    conn.execute("CREATE TABLE api_registry (id VARCHAR(36) PRIMARY KEY, name VARCHAR(100) NOT NULL)")
    conn.execute("CREATE TABLE approval_requests (id VARCHAR(36) PRIMARY KEY, status VARCHAR(20) NOT NULL)")
    conn.execute("CREATE TABLE execution_logs (id VARCHAR(36) PRIMARY KEY, status VARCHAR(20) NOT NULL)")
    conn.execute("INSERT INTO users (id, username) VALUES ('u1', 'real_admin')")
    conn.execute("INSERT INTO approval_requests (id, status) VALUES ('a1', 'PENDING')")
    conn.commit()
    conn.close()

    sq_cfg = Config(os.path.join(backend_dir, "alembic.ini"))
    sq_cfg.set_main_option("script_location", os.path.join(backend_dir, "alembic"))
    sq_cfg.cmd_opts = type("Opts", (), {"x": [f"db_url=sqlite:///{db_file.as_posix()}"]})()
    command.upgrade(sq_cfg, "head")

    conn = sqlite3.connect(str(db_file))
    user_row = conn.execute("SELECT id, username, is_demo, demo_session_id FROM users").fetchall()
    appr_row = conn.execute("SELECT id, status, rejection_reason, is_demo, demo_session_id FROM approval_requests").fetchall()
    conn.close()
    assert user_row == [("u1", "real_admin", 0, None)]
    assert appr_row == [("a1", "PENDING", None, 0, None)]
