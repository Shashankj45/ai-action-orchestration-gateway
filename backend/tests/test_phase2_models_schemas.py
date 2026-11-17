"""
tests/test_phase2_models_schemas.py

Comprehensive tests for Phase 2:
1. SSRF prevention on API base URLs.
2. Credential exposure / data leakage prevention.
3. SQLAlchemy ORM models, relations, cascades, and constraints.
4. Approval state machine and decision schema constraints.
5. Payload truncation / protection against resource exhaustion.
"""

import pytest
import uuid
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError
from pydantic import ValidationError

from app.database import Base
from app.models.enums import ApprovalStatus, ExecutionStatus
from app.models.api_registry import APIRegistry
from app.models.approval_request import ApprovalRequest
from app.models.execution_log import ExecutionLog

from app.schemas.api_registry import (
    APIRegistryCreate,
    APIRegistryResponse,
    EndpointDefinition,
    ParameterDefinition,
)
from app.schemas.approval_request import ApprovalDecisionRequest
from app.utils.security import validate_safe_url, truncate_payload


# ---------------------------------------------------------------------------
# Test Database Fixture (In-Memory SQLite)
# ---------------------------------------------------------------------------
@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


# ---------------------------------------------------------------------------
# 1. SSRF Protection Tests
# ---------------------------------------------------------------------------
class TestSSRFProtection:
    @pytest.mark.parametrize(
        "blocked_url",
        [
            "http://localhost",
            "http://localhost:8080/admin",
            "http://127.0.0.1",
            "http://127.0.0.1:3000/internal",
            "http://0.0.0.0:5000",
            "http://169.254.169.254/latest/meta-data/",  # Cloud metadata
            "http://169.254.169.253",
            "http://10.0.0.1/status",                    # Class A Private
            "http://172.16.0.5:8000",                    # Class B Private
            "http://192.168.1.1/router",                 # Class C Private
            "http://metadata.google.internal/compute",   # GCP metadata
            "http://service.local/api",                  # .local mDNS
            "http://database.internal",                  # .internal domain
            "ftp://example.com/api",                     # Non-HTTP scheme
            "file:///etc/passwd",                        # File scheme
            "http://user:pass@example.com/api",          # Embedded credentials
        ],
    )
    def test_ssrf_forbidden_urls(self, blocked_url):
        with pytest.raises(ValueError):
            validate_safe_url(blocked_url)

    @pytest.mark.parametrize(
        "allowed_url",
        [
            "https://api.stripe.com",
            "https://api.github.com/v3",
            "http://api.weatherapi.com",
            "https://slack.com/api",
        ],
    )
    def test_valid_public_urls(self, allowed_url):
        result = validate_safe_url(allowed_url)
        assert result.startswith("http")

    def test_pydantic_schema_rejects_ssrf(self):
        with pytest.raises(ValidationError) as exc_info:
            APIRegistryCreate(
                name="Malicious Internal API",
                base_url="http://169.254.169.254/secret",
                endpoints=[],
            )
        assert "SSRF Protection" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 2. Credential Leakage Prevention Tests
# ---------------------------------------------------------------------------
class TestCredentialLeakagePrevention:
    def test_auth_header_value_not_exposed_in_response_schema(self, db_session):
        secret_token = "sk_live_super_secret_token_12345"
        
        # 1. Create in DB
        api_record = APIRegistry(
            name="Stripe API",
            base_url="https://api.stripe.com",
            auth_header_name="Authorization",
            auth_header_value=secret_token,
            endpoints=[],
        )
        db_session.add(api_record)
        db_session.commit()
        db_session.refresh(api_record)

        # 2. Serialize via Pydantic response schema
        response = APIRegistryResponse.model_validate(api_record)
        serialized_dict = response.model_dump()

        # Security Assertions:
        # auth_header_value MUST NOT be present in serialized dict
        assert "auth_header_value" not in serialized_dict
        # has_auth must be True
        assert serialized_dict["has_auth"] is True
        # Secret token must not appear anywhere in the output
        assert secret_token not in str(serialized_dict)


# ---------------------------------------------------------------------------
# 3. SQLAlchemy ORM Constraints & Cascades
# ---------------------------------------------------------------------------
class TestORMModels:
    def test_create_and_cascade_delete(self, db_session):
        # 1. Create API
        api = APIRegistry(
            name="Test API",
            base_url="https://api.example.com",
            endpoints=[{"path": "/users", "method": "GET"}],
        )
        db_session.add(api)
        db_session.commit()

        # 2. Create linked ApprovalRequest
        approval = ApprovalRequest(
            api_registry_id=api.id,
            endpoint_path="/users/delete",
            http_method="DELETE",
            request_payload={"user_id": 42},
            classification_reason="Destructive DELETE operation",
        )
        db_session.add(approval)
        db_session.commit()

        # 3. Create linked ExecutionLog
        log = ExecutionLog(
            api_registry_id=api.id,
            approval_request_id=approval.id,
            endpoint_path="/users/delete",
            http_method="DELETE",
            request_payload={"user_id": 42},
            status=ExecutionStatus.PENDING,
        )
        db_session.add(log)
        db_session.commit()

        # Check records exist
        assert db_session.query(APIRegistry).count() == 1
        assert db_session.query(ApprovalRequest).count() == 1
        assert db_session.query(ExecutionLog).count() == 1

        # 4. Cascade Delete API
        db_session.delete(api)
        db_session.commit()

        # Approval request and execution log should cascade delete
        assert db_session.query(APIRegistry).count() == 0
        assert db_session.query(ApprovalRequest).count() == 0
        assert db_session.query(ExecutionLog).count() == 0

    def test_unique_api_name_constraint(self, db_session):
        api1 = APIRegistry(name="DuplicateName", base_url="https://api.one.com")
        api2 = APIRegistry(name="DuplicateName", base_url="https://api.two.com")
        db_session.add(api1)
        db_session.commit()

        db_session.add(api2)
        with pytest.raises(IntegrityError):
            db_session.commit()


# ---------------------------------------------------------------------------
# 4. Approval State Machine & Decision Validation
# ---------------------------------------------------------------------------
class TestApprovalSchemas:
    def test_valid_approval_decisions(self):
        req_approved = ApprovalDecisionRequest(decision=ApprovalStatus.APPROVED)
        assert req_approved.decision == ApprovalStatus.APPROVED

        req_rejected = ApprovalDecisionRequest(decision=ApprovalStatus.REJECTED)
        assert req_rejected.decision == ApprovalStatus.REJECTED

    def test_invalid_approval_decision_rejected(self):
        # Setting status back to PENDING must be rejected
        with pytest.raises(ValidationError):
            ApprovalDecisionRequest(decision=ApprovalStatus.PENDING)


# ---------------------------------------------------------------------------
# 5. Payload Truncation / Large Body Protection
# ---------------------------------------------------------------------------
class TestPayloadProtection:
    def test_truncate_oversized_payload(self):
        huge_text = "A" * 60_000
        data = {"response": huge_text}
        truncated = truncate_payload(data, max_bytes=50_000)

        assert truncated["_truncated"] is True
        assert truncated["_original_size_bytes"] > 50_000
        assert "_preview" in truncated

    def test_preserve_normal_payload(self):
        normal_data = {"status": "ok", "items": [1, 2, 3]}
        result = truncate_payload(normal_data, max_bytes=50_000)
        assert result == normal_data
