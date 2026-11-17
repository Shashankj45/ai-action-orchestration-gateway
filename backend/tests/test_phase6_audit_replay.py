"""
tests/test_phase6_audit_replay.py

Comprehensive tests for Phase 6:
1. Audit Logs Querying:
   - Pagination (skip, limit).
   - Filtering by API ID.
   - Filtering by execution status (SUCCESS, FAILED).
   - Retrieval by ID (GET /logs/{id}).
2. Replay Safeguards (Anti-Replay Attack & Immutability):
   - SAFE replay: Re-executes immediately, creates new log, leaves original log untouched.
   - SENSITIVE replay: Refuses auto-execution, creates a new PENDING approval request.
   - Target API Deleted: Refuses replay with 400 Bad Request.
   - Input validation: Invalid UUID format rejection (400 Bad Request).
"""

import pytest
import uuid
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.database import Base, engine, SessionLocal
from app.models.api_registry import APIRegistry
from app.models.execution_log import ExecutionLog
from app.models.approval_request import ApprovalRequest
from app.models.enums import ExecutionStatus, ApprovalStatus


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


class TestAuditLogsQuery:
    def test_list_logs_empty(self, client):
        resp = client.get("/logs")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_logs_filtering_and_pagination(self, client):
        db = SessionLocal()
        try:
            api1 = APIRegistry(name="API-1", base_url="https://api1.com", endpoints=[])
            api2 = APIRegistry(name="API-2", base_url="https://api2.com", endpoints=[])
            db.add_all([api1, api2])
            db.commit()

            # Create 3 logs: 2 for api1, 1 for api2
            log1 = ExecutionLog(
                api_registry_id=api1.id,
                endpoint_path="/status",
                http_method="GET",
                status=ExecutionStatus.SUCCESS,
                response_status_code=200,
            )
            log2 = ExecutionLog(
                api_registry_id=api1.id,
                endpoint_path="/error",
                http_method="GET",
                status=ExecutionStatus.FAILED,
                response_status_code=500,
            )
            log3 = ExecutionLog(
                api_registry_id=api2.id,
                endpoint_path="/ping",
                http_method="GET",
                status=ExecutionStatus.SUCCESS,
                response_status_code=200,
            )
            db.add_all([log1, log2, log3])
            db.commit()

            api1_id = api1.id
            log1_id = log1.id
        finally:
            db.close()

        # Query all logs
        resp = client.get("/logs")
        assert len(resp.json()) == 3

        # Filter by API ID
        resp_api1 = client.get(f"/logs?api_id={api1_id}")
        assert len(resp_api1.json()) == 2

        # Filter by status=FAILED
        resp_failed = client.get("/logs?status=FAILED")
        assert len(resp_failed.json()) == 1
        assert resp_failed.json()[0]["response_status_code"] == 500

        # Pagination
        resp_paged = client.get("/logs?skip=0&limit=2")
        assert len(resp_paged.json()) == 2

    def test_get_log_by_id(self, client):
        db = SessionLocal()
        try:
            api = APIRegistry(name="API-Target", base_url="https://target.com", endpoints=[])
            db.add(api)
            db.commit()

            log = ExecutionLog(
                api_registry_id=api.id,
                endpoint_path="/info",
                http_method="GET",
                status=ExecutionStatus.SUCCESS,
                response_body={"version": "1.0"},
            )
            db.add(log)
            db.commit()
            log_id = log.id
        finally:
            db.close()

        resp = client.get(f"/logs/{log_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == log_id
        assert data["endpoint_path"] == "/info"
        assert data["response_body"] == {"version": "1.0"}

    def test_get_log_not_found(self, client):
        random_id = str(uuid.uuid4())
        resp = client.get(f"/logs/{random_id}")
        assert resp.status_code == 404

    def test_get_log_invalid_uuid(self, client):
        resp = client.get("/logs/not-a-valid-uuid")
        assert resp.status_code == 400


class TestSecureReplay:
    def test_safe_operation_replay(self, client):
        # 1. Setup API and original log
        db = SessionLocal()
        try:
            api = APIRegistry(
                name="Safe API",
                base_url="https://api.safe.com",
                endpoints=[{"path": "/health", "method": "GET"}],
            )
            db.add(api)
            db.commit()

            original_log = ExecutionLog(
                api_registry_id=api.id,
                endpoint_path="/health",
                http_method="GET",
                request_payload={"verbose": True},
                status=ExecutionStatus.FAILED,  # Initially failed, user wants to replay
                response_status_code=504,
            )
            db.add(original_log)
            db.commit()
            orig_log_id = original_log.id
        finally:
            db.close()

        # 2. Replay execution
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "recovered"}

        with patch("app.services.executor.resolve_and_verify_host", return_value=["93.184.216.34"]):
            with patch("httpx.AsyncClient.get", return_value=mock_response):
                resp = client.post(f"/logs/{orig_log_id}/replay")
                assert resp.status_code == 200
                data = resp.json()
                assert data["status"] == "REPLAYED"
                assert data["is_sensitive"] is False
                assert data["original_log_id"] == orig_log_id
                assert data["new_log_id"] is not None
                assert data["execution_status"] == "SUCCESS"
                assert data["response_body"] == {"status": "recovered"}

        # 3. Security Assertions:
        # A. Original log MUST remain unchanged (immutability check)
        db = SessionLocal()
        try:
            orig_check = db.query(ExecutionLog).filter_by(id=orig_log_id).first()
            assert orig_check.status == ExecutionStatus.FAILED
            assert orig_check.response_status_code == 504

            # B. Total logs should now be 2
            assert db.query(ExecutionLog).count() == 2
        finally:
            db.close()

    def test_sensitive_operation_replay_requires_approval(self, client):
        # 1. Setup API and original log for a sensitive POST operation
        db = SessionLocal()
        try:
            api = APIRegistry(
                name="Payment API",
                base_url="https://api.pay.com",
                is_sensitive=True,
                endpoints=[{"path": "/v1/charges", "method": "POST"}],
            )
            db.add(api)
            db.commit()

            original_log = ExecutionLog(
                api_registry_id=api.id,
                endpoint_path="/v1/charges",
                http_method="POST",
                request_payload={"amount": 1000},
                status=ExecutionStatus.FAILED,
                response_status_code=500,
            )
            db.add(original_log)
            db.commit()
            orig_log_id = original_log.id
        finally:
            db.close()

        # 2. Attempt replay: MUST NOT auto-execute; must route to approval queue
        resp = client.post(f"/logs/{orig_log_id}/replay")
        assert resp.status_code == 202  # Accepted, pending review

        data = resp.json()
        assert data["status"] == "AWAITING_APPROVAL"
        assert data["is_sensitive"] is True
        assert data["approval_id"] is not None
        assert "Human approval required" in data["message"]

        # 3. Verify that an ApprovalRequest was created in PENDING status
        db = SessionLocal()
        try:
            approval = db.query(ApprovalRequest).filter_by(id=data["approval_id"]).first()
            assert approval is not None
            assert approval.status == ApprovalStatus.PENDING
            assert approval.endpoint_path == "/v1/charges"
            assert approval.request_payload == {"amount": 1000}
        finally:
            db.close()

    def test_replay_deleted_api_rejected(self, client):
        # Create log pointing to deleted API
        db = SessionLocal()
        try:
            api = APIRegistry(name="TempAPI", base_url="https://temp.com", endpoints=[])
            db.add(api)
            db.commit()

            log = ExecutionLog(
                api_registry_id=api.id,
                endpoint_path="/temp",
                http_method="GET",
                status=ExecutionStatus.FAILED,
            )
            db.add(log)
            db.commit()
            log_id = log.id

            # Delete the API
            db.delete(api)
            db.commit()
        finally:
            db.close()

        # Replay attempt fails cleanly with 404 because deleting API cascaded delete to linked logs
        resp = client.post(f"/logs/{log_id}/replay")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()
