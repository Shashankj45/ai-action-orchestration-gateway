# Phase 1 tests: startup, config validation, security headers, CORS
import os
import pytest

# Override env before any app import to prevent echo/debug output blocking
os.environ.setdefault("APP_ENV", "development")

from fastapi.testclient import TestClient


@pytest.fixture()
def client():
    """
    Per-test client. Import app here (after env is configured).
    Uses function scope to avoid lifespan context issues.
    """
    from app.main import app
    # TestClient handles lifespan startup/shutdown synchronously
    with TestClient(app) as c:
        yield c


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_health_does_not_expose_internals(self, client):
        body = client.get("/health").json()
        # Must NOT contain version, db url, secret key, env details
        forbidden = ["version", "database", "secret", "key", "env", "config"]
        body_str = str(body).lower()
        for f in forbidden:
            assert f not in body_str, f"Health response leaks '{f}'"


class TestSecurityHeaders:
    def test_x_content_type_options(self, client):
        resp = client.get("/health")
        assert resp.headers.get("x-content-type-options") == "nosniff"

    def test_x_frame_options(self, client):
        resp = client.get("/health")
        assert resp.headers.get("x-frame-options") == "DENY"

    def test_x_xss_protection(self, client):
        resp = client.get("/health")
        assert resp.headers.get("x-xss-protection") == "1; mode=block"

    def test_timing_header_present(self, client):
        resp = client.get("/health")
        assert "x-response-time-ms" in resp.headers

    def test_content_security_policy(self, client):
        resp = client.get("/health")
        assert "content-security-policy" in resp.headers
        assert "default-src 'self'" in resp.headers["content-security-policy"]


class TestRequestSizeLimit:
    def test_oversized_body_rejected(self, client):
        # Claim content is 11 MB (over the 10 MB limit)
        oversized_headers = {"content-length": str(11 * 1024 * 1024)}
        resp = client.post("/health", headers=oversized_headers)
        assert resp.status_code == 413

    def test_normal_size_body_accepted(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200


class TestConfigValidation:
    def test_settings_loads_without_error(self):
        from app.config import settings
        assert settings.secret_key is not None
        assert settings.database_url is not None

    def test_cors_origins_parsed_correctly(self):
        from app.config import settings
        origins = settings.cors_origins
        assert isinstance(origins, list)
        assert len(origins) >= 1
        for origin in origins:
            assert origin.startswith("http")

    def test_secret_key_not_empty(self):
        from app.config import settings
        assert len(settings.secret_key) > 10

    def test_database_url_set(self):
        from app.config import settings
        assert settings.database_url
        assert "gateway" in settings.database_url.lower() or "sqlite" in settings.database_url.lower()
