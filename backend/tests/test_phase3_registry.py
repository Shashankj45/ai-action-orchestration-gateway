"""
tests/test_phase3_registry.py

End-to-end integration tests for the API Registry router and service:
- Dynamic API registration (POST /apis)
- Credential masking in responses
- Duplicate name rejection (409 Conflict)
- SSRF attempt rejection at HTTP boundary (422 Unprocessable Entity)
- API listing with pagination (GET /apis)
- Retrieval by ID (GET /apis/{id})
- Input validation: Invalid UUID format rejection (400 Bad Request)
- Not found handling (404)
- API update (PUT /apis/{id})
- API deletion (DELETE /apis/{id})
"""

import uuid
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.database import Base, engine, SessionLocal
from app.models.api_registry import APIRegistry


@pytest.fixture(autouse=True)
def clean_db():
    """Wipes and recreates tables before each test to ensure test isolation."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


from tests.conftest import create_test_admin_client

@pytest.fixture
def client():
    yield from create_test_admin_client()


class TestAPIRegistration:
    def test_register_api_success(self, client):
        payload = {
            "name": "Stripe Gateway",
            "base_url": "https://api.stripe.com",
            "description": "Stripe Payments API",
            "auth_header_name": "Authorization",
            "auth_header_value": "Bearer sk_test_secret12345",
            "is_sensitive": True,
            "endpoints": [
                {
                    "path": "/v1/charges",
                    "method": "POST",
                    "description": "Create a credit card charge",
                    "parameters": {
                        "amount": {"type": "integer", "required": True},
                        "currency": {"type": "string", "required": True},
                    },
                }
            ],
        }
        resp = client.post("/apis", json=payload)
        assert resp.status_code == 201

        data = resp.json()
        assert "id" in data
        assert uuid.UUID(data["id"])  # Valid UUIDv4
        assert data["name"] == "Stripe Gateway"
        assert data["base_url"] == "https://api.stripe.com"
        assert data["is_sensitive"] is True
        assert data["has_auth"] is True

        # CRITICAL SECURITY CHECK: Secret token MUST NOT be in response
        assert "auth_header_value" not in data
        assert "sk_test_secret12345" not in resp.text

    def test_register_duplicate_name_returns_409(self, client):
        payload = {
            "name": "UniqueService",
            "base_url": "https://api.example.com",
            "endpoints": [],
        }
        # First registration succeeds
        r1 = client.post("/apis", json=payload)
        assert r1.status_code == 201

        # Second registration with duplicate name fails with 409
        r2 = client.post("/apis", json=payload)
        assert r2.status_code == 409
        assert "already exists" in r2.json()["detail"]

    def test_register_ssrf_url_rejected_with_422(self, client):
        malicious_payload = {
            "name": "Internal AWS Metadata",
            "base_url": "http://169.254.169.254/latest/meta-data/",
            "endpoints": [],
        }
        resp = client.post("/apis", json=malicious_payload)
        assert resp.status_code == 422
        assert "SSRF Protection" in str(resp.json())

    def test_register_localhost_url_rejected_with_422(self, client):
        malicious_payload = {
            "name": "Localhost Attack",
            "base_url": "http://localhost:8080",
            "endpoints": [],
        }
        resp = client.post("/apis", json=malicious_payload)
        assert resp.status_code == 422
        assert "SSRF Protection" in str(resp.json())


class TestAPIListingAndRetrieval:
    def test_list_apis_empty(self, client):
        resp = client.get("/apis")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_apis_pagination(self, client):
        # Register 3 APIs
        for i in range(3):
            client.post(
                "/apis",
                json={
                    "name": f"Service-{i}",
                    "base_url": f"https://api{i}.service.com",
                    "endpoints": [],
                },
            )

        # Query with pagination limit=2
        resp = client.get("/apis?skip=0&limit=2")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2

    def test_get_api_by_id_success(self, client):
        # Register API
        create_resp = client.post(
            "/apis",
            json={
                "name": "TargetAPI",
                "base_url": "https://api.target.com",
                "endpoints": [],
            },
        )
        api_id = create_resp.json()["id"]

        # Fetch API
        get_resp = client.get(f"/apis/{api_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["id"] == api_id
        assert get_resp.json()["name"] == "TargetAPI"

    def test_get_api_not_found(self, client):
        random_id = str(uuid.uuid4())
        resp = client.get(f"/apis/{random_id}")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    def test_get_api_invalid_uuid_format(self, client):
        # Path parameter validation prevents malformed input
        resp = client.get("/apis/not-a-valid-uuid")
        assert resp.status_code == 400
        assert "Invalid UUID" in resp.json()["detail"]


class TestAPIUpdateAndDeletion:
    def test_update_api_success(self, client):
        # 1. Register API
        create_resp = client.post(
            "/apis",
            json={
                "name": "OldName",
                "base_url": "https://api.old.com",
                "is_sensitive": False,
                "endpoints": [],
            },
        )
        api_id = create_resp.json()["id"]

        # 2. Update fields
        update_payload = {
            "name": "NewName",
            "is_sensitive": True,
            "description": "Updated Description",
        }
        put_resp = client.put(f"/apis/{api_id}", json=update_payload)
        assert put_resp.status_code == 200
        data = put_resp.json()
        assert data["name"] == "NewName"
        assert data["is_sensitive"] is True
        assert data["description"] == "Updated Description"

    def test_update_api_duplicate_name_conflict(self, client):
        # Register two APIs
        client.post(
            "/apis",
            json={"name": "API-A", "base_url": "https://a.com", "endpoints": []},
        )
        r2 = client.post(
            "/apis",
            json={"name": "API-B", "base_url": "https://b.com", "endpoints": []},
        )
        api_b_id = r2.json()["id"]

        # Attempt to rename API-B to API-A
        update_resp = client.put(f"/apis/{api_b_id}", json={"name": "API-A"})
        assert update_resp.status_code == 409
        assert "already exists" in update_resp.json()["detail"]

    def test_delete_api_success(self, client):
        # 1. Register API
        create_resp = client.post(
            "/apis",
            json={
                "name": "ToDelete",
                "base_url": "https://to-delete.com",
                "endpoints": [],
            },
        )
        api_id = create_resp.json()["id"]

        # 2. Delete API
        del_resp = client.delete(f"/apis/{api_id}")
        assert del_resp.status_code == 204

        # 3. Verify it is gone
        get_resp = client.get(f"/apis/{api_id}")
        assert get_resp.status_code == 404

    def test_delete_api_not_found(self, client):
        random_id = str(uuid.uuid4())
        resp = client.delete(f"/apis/{random_id}")
        assert resp.status_code == 404
