"""
backend/tests/test_phase11_hotel_rbac_idor.py

Comprehensive tests for Hotel Management Scenario:
1. Customer / Operator resource isolation (IDOR protection on /approvals and /logs).
2. Four-Eyes Anti-Self-Approval enforcement.
3. Approver Approval History & relevant execution logs.
4. Admin system metrics telemetry and RBAC restrictions.
5. End-to-end hotel booking cancellation workflow.
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
    from app.services.auth_service import reset_burst_rate_limit
    reset_burst_rate_limit()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    reset_burst_rate_limit()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def hotel_setup():
    db = SessionLocal()
    try:
        # Create 2 Operators (Customers), 1 Approver (Hotel Manager), 1 Admin (IT Admin)
        dummy_hash = "$2b$12$e8kZ.4qM5jP9.1wUe1J8..fQo8w1f7y3u4v5w6x7y8z9a0b1c2d3e"
        admin = User(
            username="admin_it",
            hashed_password=dummy_hash,
            role=UserRole.ADMIN,
            is_active=True,
        )
        customer_105 = User(
            username="guest_105",
            hashed_password=dummy_hash,
            role=UserRole.OPERATOR,
            is_active=True,
        )
        customer_204 = User(
            username="guest_204",
            hashed_password=dummy_hash,
            role=UserRole.OPERATOR,
            is_active=True,
        )
        manager = User(
            username="duty_manager",
            hashed_password=dummy_hash,
            role=UserRole.APPROVER,
            is_active=True,
        )
        db.add_all([admin, customer_105, customer_204, manager])
        db.commit()

        # Create Hotel API
        hotel_api = APIRegistry(
            name="Grand Hotel API",
            base_url="https://api.hotel-demo.com",
            description="Hotel reservation system",
            is_sensitive=False,
            endpoints=[
                {"path": "/v1/bookings/105", "method": "GET", "description": "View reservation"},
                {"path": "/v1/bookings/105/cancel", "method": "POST", "description": "Cancel reservation"},
            ],
        )
        db.add(hotel_api)
        db.commit()

        # Customer 105 requested cancellation
        appr_105 = ApprovalRequest(
            api_registry_id=hotel_api.id,
            endpoint_path="/v1/bookings/105/cancel",
            http_method="POST",
            request_payload={"booking_id": "105", "reason": "Guest emergency"},
            status=ApprovalStatus.PENDING,
            classification_reason="Operation is SENSITIVE: Endpoint path contains sensitive keyword 'cancel'.",
            requested_by_user_id=customer_105.id,
        )
        # Customer 204 requested cancellation
        appr_204 = ApprovalRequest(
            api_registry_id=hotel_api.id,
            endpoint_path="/v1/bookings/204/cancel",
            http_method="POST",
            request_payload={"booking_id": "204", "reason": "Change of plans"},
            status=ApprovalStatus.PENDING,
            classification_reason="Operation is SENSITIVE: Endpoint path contains sensitive keyword 'cancel'.",
            requested_by_user_id=customer_204.id,
        )
        db.add_all([appr_105, appr_204])

        # Customer 105 safe execution log
        log_105 = ExecutionLog(
            api_registry_id=hotel_api.id,
            executed_by_user_id=customer_105.id,
            endpoint_path="/v1/bookings/105",
            http_method="GET",
            request_payload={},
            response_body={"booking_id": "105", "guest": "guest_105", "status": "confirmed"},
            response_status_code=200,
            status=ExecutionStatus.SUCCESS,
            duration_ms=45.2,
        )
        # Customer 204 safe execution log
        log_204 = ExecutionLog(
            api_registry_id=hotel_api.id,
            executed_by_user_id=customer_204.id,
            endpoint_path="/v1/bookings/204",
            http_method="GET",
            request_payload={},
            response_body={"booking_id": "204", "guest": "guest_204", "status": "confirmed"},
            response_status_code=200,
            status=ExecutionStatus.SUCCESS,
            duration_ms=40.1,
        )
        db.add_all([log_105, log_204])
        db.commit()

        return {
            "admin_token": create_access_token(admin.id, admin.username, admin.role.value),
            "guest_105_token": create_access_token(customer_105.id, customer_105.username, customer_105.role.value),
            "guest_204_token": create_access_token(customer_204.id, customer_204.username, customer_204.role.value),
            "manager_token": create_access_token(manager.id, manager.username, manager.role.value),
            "guest_105_id": customer_105.id,
            "guest_204_id": customer_204.id,
            "appr_105_id": appr_105.id,
            "appr_204_id": appr_204.id,
            "log_105_id": log_105.id,
            "log_204_id": log_204.id,
        }
    finally:
        db.close()


def test_operator_my_requests_isolation(client, hotel_setup):
    """Verifies that an Operator only sees their own requests on /approvals/my."""
    headers_105 = {"Authorization": f"Bearer {hotel_setup['guest_105_token']}"}
    r = client.get("/approvals/my", headers=headers_105)
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1
    assert data[0]["id"] == hotel_setup["appr_105_id"]
    assert data[0]["endpoint_path"] == "/v1/bookings/105/cancel"


def test_operator_idor_protection_on_approvals(client, hotel_setup):
    """Verifies that an Operator cannot access another customer's approval request."""
    headers_105 = {"Authorization": f"Bearer {hotel_setup['guest_105_token']}"}
    
    # 1. Allowed: Customer 105 can access their own request
    r_own = client.get(f"/approvals/{hotel_setup['appr_105_id']}", headers=headers_105)
    assert r_own.status_code == 200
    assert r_own.json()["id"] == hotel_setup["appr_105_id"]

    # 2. Forbidden (IDOR): Customer 105 cannot access Customer 204's request
    r_other = client.get(f"/approvals/{hotel_setup['appr_204_id']}", headers=headers_105)
    assert r_other.status_code == 403
    assert "You can only view your own approval requests" in r_other.json()["detail"]


def test_operator_idor_protection_on_execution_logs(client, hotel_setup):
    """Verifies that an Operator's execution history is strictly scoped to their own account."""
    headers_105 = {"Authorization": f"Bearer {hotel_setup['guest_105_token']}"}
    
    # 1. GET /logs returns only Customer 105's logs
    r_list = client.get("/logs", headers=headers_105)
    assert r_list.status_code == 200
    logs = r_list.json()
    assert all(log["executed_by_user_id"] == hotel_setup["guest_105_id"] for log in logs)

    # 2. Direct IDOR check: Customer 105 cannot inspect Customer 204's log
    r_idor = client.get(f"/logs/{hotel_setup['log_204_id']}", headers=headers_105)
    assert r_idor.status_code == 403
    assert "You can only view your own execution records" in r_idor.json()["detail"]


def test_admin_system_metrics_rbac(client, hotel_setup):
    """Verifies that /system/metrics is restricted strictly to ADMIN."""
    # 1. Admin succeeds
    admin_headers = {"Authorization": f"Bearer {hotel_setup['admin_token']}"}
    r_admin = client.get("/system/metrics", headers=admin_headers)
    assert r_admin.status_code == 200
    metrics = r_admin.json()
    assert metrics["status"] == "healthy"
    assert "total_apis" in metrics
    assert "total_users" in metrics

    # 2. Operator gets 403 Forbidden
    op_headers = {"Authorization": f"Bearer {hotel_setup['guest_105_token']}"}
    assert client.get("/system/metrics", headers=op_headers).status_code == 403

    # 3. Approver gets 403 Forbidden
    mgr_headers = {"Authorization": f"Bearer {hotel_setup['manager_token']}"}
    assert client.get("/system/metrics", headers=mgr_headers).status_code == 403


def test_approver_and_admin_approval_listing_and_history(client, hotel_setup):
    """Verifies that Approvers and Admins can query pending approvals and approval history."""
    mgr_headers = {"Authorization": f"Bearer {hotel_setup['manager_token']}"}

    # Approver lists pending
    r_pending = client.get("/approvals?status=PENDING", headers=mgr_headers)
    assert r_pending.status_code == 200
    pending_list = r_pending.json()
    assert len(pending_list) == 2  # appr_105 and appr_204

    # Approver approves customer 105 request
    r_decision = client.post(
        f"/approvals/{hotel_setup['appr_105_id']}/approve",
        headers=mgr_headers,
    )
    assert r_decision.status_code == 200
    assert r_decision.json()["approval"]["status"] == "APPROVED"
    assert r_decision.json()["approval"]["decided_by_username"] == "duty_manager"

    # Pending list now only has 1
    r_pending_after = client.get("/approvals?status=PENDING", headers=mgr_headers)
    assert len(r_pending_after.json()) == 1

    # History list (status=APPROVED) has customer 105 request
    r_approved = client.get("/approvals?status=APPROVED", headers=mgr_headers)
    assert len(r_approved.json()) == 1
    assert r_approved.json()[0]["id"] == hotel_setup["appr_105_id"]


def test_anti_self_approval_four_eyes_hotel(client, hotel_setup):
    """Verifies that Four-Eyes enforcement blocks any user from approving their own request."""
    # Duty manager attempts to create or has an approval request requested by themselves
    db = SessionLocal()
    try:
        manager_user = db.query(User).filter_by(username="duty_manager").first()
        hotel_api = db.query(APIRegistry).filter_by(name="Grand Hotel API").first()
        mgr_req = ApprovalRequest(
            api_registry_id=hotel_api.id,
            endpoint_path="/v1/bookings/105/cancel",
            http_method="POST",
            request_payload={"booking_id": "105"},
            status=ApprovalStatus.PENDING,
            classification_reason="Testing Four Eyes",
            requested_by_user_id=manager_user.id,
        )
        db.add(mgr_req)
        db.commit()
        mgr_req_id = mgr_req.id
    finally:
        db.close()

    # Duty manager attempts to approve their own request -> 403 Forbidden
    mgr_headers = {"Authorization": f"Bearer {hotel_setup['manager_token']}"}
    r_self = client.post(
        f"/approvals/{mgr_req_id}/approve",
        headers=mgr_headers,
    )
    assert r_self.status_code == 403
    assert "Self-approval is forbidden" in r_self.json()["detail"]


def test_operator_replay_forbidden(client, hotel_setup):
    """Verifies that Operators cannot trigger replay of execution logs."""
    op_headers = {"Authorization": f"Bearer {hotel_setup['guest_105_token']}"}
    r = client.post(f"/logs/{hotel_setup['log_105_id']}/replay", headers=op_headers)
    assert r.status_code == 403

