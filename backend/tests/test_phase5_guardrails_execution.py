"""
tests/test_phase5_guardrails_execution.py

Comprehensive tests for Phase 5:
1. DNS Rebinding Defense (pre-execution verification of resolved destination IPs).
2. Deterministic Safety Classifier (SAFE vs SENSITIVE rules).
3. Guardrailed Task Dispatch:
   - SENSITIVE actions queued for human approval (202 Accepted).
   - SAFE actions auto-executed (200 OK).
4. Approval Workflow:
   - List pending approvals (GET /approvals).
   - Approve action (POST /approvals/{id}/approve) triggers execution of frozen payload.
   - Reject action (POST /approvals/{id}/reject).
   - Prevention of double-decision / replay tampering (409 Conflict).
"""

import pytest
import uuid
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.database import Base, engine, SessionLocal
from app.models.api_registry import APIRegistry
from app.models.approval_request import ApprovalRequest
from app.models.execution_log import ExecutionLog
from app.models.enums import ApprovalStatus, ExecutionStatus
from app.services.classifier import classify_action
from app.utils.network import resolve_and_verify_host, DNSRebindingError


@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


from tests.conftest import create_test_admin_client

@pytest.fixture
def client():
    yield from create_test_admin_client()


# ---------------------------------------------------------------------------
# 1. DNS Rebinding Defense Tests
# ---------------------------------------------------------------------------
class TestDNSRebindingDefense:
    def test_direct_private_ip_resolution_blocked(self):
        with pytest.raises(DNSRebindingError, match="loopback"):
            resolve_and_verify_host("http://127.0.0.1:8000/api")

        with pytest.raises(DNSRebindingError, match="metadata"):
            resolve_and_verify_host("http://169.254.169.254/latest")

    def test_hostname_resolving_to_private_ip_blocked(self):
        # Simulate a malicious domain that passes initial check but DNS resolves to 127.0.0.1
        fake_addrinfo = [(2, 1, 6, "", ("127.0.0.1", 80))]
        with patch("socket.getaddrinfo", return_value=fake_addrinfo):
            with pytest.raises(DNSRebindingError, match="loopback"):
                resolve_and_verify_host("https://rebound-evil-domain.com/secret")

    def test_public_ip_resolution_succeeds(self):
        fake_addrinfo = [(2, 1, 6, "", ("93.184.216.34", 443))]  # example.com public IP
        with patch("socket.getaddrinfo", return_value=fake_addrinfo):
            ips = resolve_and_verify_host("https://safe-domain.com")
            assert "93.184.216.34" in ips


# ---------------------------------------------------------------------------
# 2. Classifier Unit Tests
# ---------------------------------------------------------------------------
class TestClassifier:
    def test_safe_get_operation(self):
        is_sensitive, reason = classify_action("GET", "/v1/weather/forecast")
        assert is_sensitive is False
        assert "Read-only GET" in reason

    def test_sensitive_post_method(self):
        is_sensitive, reason = classify_action("POST", "/v1/charges")
        assert is_sensitive is True
        assert "SENSITIVE" in reason
        assert "POST" in reason

    def test_sensitive_delete_method(self):
        is_sensitive, reason = classify_action("DELETE", "/v1/records/123")
        assert is_sensitive is True
        assert "SENSITIVE" in reason
        assert "DELETE" in reason

    def test_sensitive_path_keywords_in_get(self):
        # Even a GET is sensitive if path contains sensitive keywords
        is_sensitive, reason = classify_action("GET", "/v1/accounts/transfer_history")
        assert is_sensitive is True
        assert "SENSITIVE" in reason
        assert "transfer" in reason

        is_sensitive, reason = classify_action("GET", "/admin/delete_user")
        assert is_sensitive is True
        assert "SENSITIVE" in reason
        assert "delete" in reason

    def test_admin_api_override_flag(self):
        # Safe GET becomes sensitive if the API itself is tagged sensitive
        is_sensitive, reason = classify_action("GET", "/v1/public_info", api_is_sensitive=True)
        assert is_sensitive is True
        assert "SENSITIVE" in reason
        assert "flagged as sensitive by administrator" in reason


# ---------------------------------------------------------------------------
# 3. Guardrailed Task Execution Tests (SAFE vs SENSITIVE)
# ---------------------------------------------------------------------------
class TestGuardrailedTasks:
    def test_sensitive_task_triggers_approval_flow(self, client):
        # Register an API with a sensitive POST endpoint
        client.post(
            "/apis",
            json={
                "name": "Stripe Payments",
                "base_url": "https://api.stripe.com",
                "endpoints": [
                    {
                        "path": "/v1/charges",
                        "method": "POST",
                        "description": "Create a charge or transfer funds",
                        "parameters": {
                            "amount": {"type": "integer", "required": True},
                        },
                    }
                ],
            },
        )

        # Submit task requiring POST
        resp = client.post("/tasks", json={"task": "Transfer 500 dollars via Stripe"})
        assert resp.status_code == 202  # Accepted, held for review

        data = resp.json()
        assert data["status"] == "AWAITING_APPROVAL"
        assert data["is_sensitive"] is True
        assert data["approval_id"] is not None
        assert data["request_payload"] == {"amount": 500}
        assert "SENSITIVE" in data["classification_reason"]

    def test_safe_task_auto_executes(self, client):
        # Register an API with a SAFE GET endpoint
        client.post(
            "/apis",
            json={
                "name": "Weather Service",
                "base_url": "https://api.weather.com",
                "is_sensitive": False,
                "endpoints": [
                    {
                        "path": "/v1/temperature",
                        "method": "GET",
                        "description": "Read temperature for a city",
                        "parameters": {
                            "city": {"type": "string", "required": True},
                        },
                    }
                ],
            },
        )

        # Mock external HTTP call to return 200 with temperature
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"temperature": 72, "unit": "F"}

        with patch("app.services.executor.resolve_and_verify_host", return_value=["93.184.216.34"]):
            with patch("httpx.AsyncClient.get", return_value=mock_response):
                resp = client.post("/tasks", json={"task": "Get temperature for Paris via Weather Service"})
                assert resp.status_code == 200
                data = resp.json()
                assert data["status"] == "EXECUTED_SAFE"
                assert data["is_sensitive"] is False
                assert data["execution_status"] == "SUCCESS"
                assert data["execution_log_id"] is not None
                assert data["response_body"] == {"temperature": 72, "unit": "F"}


# ---------------------------------------------------------------------------
# 4. Human Approval Workflow Tests
# ---------------------------------------------------------------------------
class TestApprovalWorkflow:
    def test_approve_and_reject_lifecycle(self, client):
        # 1. Register API
        client.post(
            "/apis",
            json={
                "name": "Cloud Infra",
                "base_url": "https://api.cloud.com",
                "endpoints": [
                    {
                        "path": "/v1/servers/terminate",
                        "method": "POST",
                        "description": "Terminate server instance",
                        "parameters": {
                            "server_id": {"type": "string", "required": True},
                        },
                    }
                ],
            },
        )

        # 2. Trigger sensitive task -> creates approval
        task_resp = client.post("/tasks", json={"task": "Terminate server instance srv-999 via Cloud Infra"})
        assert task_resp.status_code == 202
        approval_id = task_resp.json()["approval_id"]

        # 3. List pending approvals (GET /approvals)
        list_resp = client.get("/approvals")
        assert list_resp.status_code == 200
        approvals = list_resp.json()
        assert len(approvals) == 1
        assert approvals[0]["id"] == approval_id
        assert approvals[0]["status"] == "PENDING"
        assert approvals[0]["endpoint_path"] == "/v1/servers/terminate"

        # 4. Approve the action (POST /approvals/{id}/approve)
        # Create independent Approver user to satisfy Four-Eyes Principle (anti-self-approval)
        db = SessionLocal()
        try:
            from app.models.user import User
            from app.models.enums import UserRole
            from app.utils.auth import hash_password, create_access_token
            approver = User(
                username="compliance_officer",
                hashed_password=hash_password("CompliancePass123!"),
                role=UserRole.APPROVER,
                is_active=True,
            )
            db.add(approver)
            db.commit()
            approver_token = create_access_token(approver.id, approver.username, approver.role.value)
        finally:
            db.close()
        appr_headers = {"Authorization": f"Bearer {approver_token}"}

        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 200
        mock_post_resp.json.return_value = {"status": "terminated", "id": "srv-999"}

        with patch("app.services.executor.resolve_and_verify_host", return_value=["93.184.216.34"]):
            with patch("httpx.AsyncClient.post", return_value=mock_post_resp):
                approve_resp = client.post(f"/approvals/{approval_id}/approve", headers=appr_headers)
                assert approve_resp.status_code == 200
                appr_data = approve_resp.json()
                assert appr_data["approval"]["status"] == "APPROVED"
                assert appr_data["execution"] is not None
                assert appr_data["execution"]["status"] == "SUCCESS"
                assert appr_data["execution"]["response_body"] == {"status": "terminated", "id": "srv-999"}

        # 5. Security Check: Double-approval / Replay attempt is rejected (409 Conflict)
        re_approve_resp = client.post(f"/approvals/{approval_id}/approve", headers=appr_headers)
        assert re_approve_resp.status_code == 409
        assert "cannot be modified" in re_approve_resp.json()["detail"]

        # 6. Rejecting an already approved item is also rejected (409 Conflict)
        reject_resp = client.post(
            f"/approvals/{approval_id}/reject",
            headers=appr_headers,
            json={"reason": "Late rejection attempt"},
        )
        assert reject_resp.status_code == 409

    def test_reject_pending_approval(self, client):
        # Create an approval request directly in DB
        db = SessionLocal()
        try:
            api = APIRegistry(
                name="Bank API",
                base_url="https://api.bank.com",
                endpoints=[],
            )
            db.add(api)
            db.commit()

            approval = ApprovalRequest(
                api_registry_id=api.id,
                endpoint_path="/v1/wire",
                http_method="POST",
                request_payload={"amount": 10000},
                classification_reason="Large wire transfer",
                status=ApprovalStatus.PENDING,
            )
            db.add(approval)
            db.commit()
            approval_id = approval.id
        finally:
            db.close()

        # Reject it with a mandatory reason
        resp = client.post(
            f"/approvals/{approval_id}/reject",
            json={"reason": "Wire transfer exceeds daily policy limit"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["approval"]["status"] == "REJECTED"
        assert data["approval"]["rejection_reason"] == "Wire transfer exceeds daily policy limit"
        assert data["execution"] is None

        # Verify DB state
        db = SessionLocal()
        try:
            updated = db.query(ApprovalRequest).filter_by(id=approval_id).first()
            assert updated.status == ApprovalStatus.REJECTED
            assert updated.rejection_reason == "Wire transfer exceeds daily policy limit"
            assert updated.decided_at is not None
        finally:
            db.close()
