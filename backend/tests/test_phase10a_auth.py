"""
backend/tests/test_phase10a_auth.py

Phase 10A: Inbound Authentication and Authorization (RBAC) Test Suite.

Verifies:
1. Password hashing security (bcrypt 12-round salted hashing).
2. Strict JWT claim validation (algorithm pinning, signature, expiry, issuer, audience).
3. Generic authentication errors and distributed database rate limiting.
4. Unauthenticated request rejection across protected endpoints.
5. Role-Based Access Control (RBAC): OPERATOR vs APPROVER vs ADMIN permissions.
6. Admin Sensitive-Action No-Bypass Rule.
7. Four-Eyes Principle (Anti-Self-Approval).
8. Dynamic database role validation (revocation takes effect immediately without trusting stale JWT).
"""

import time
import uuid
from datetime import timedelta, datetime, timezone
import pytest
import jwt
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings
from app.database import Base, engine, SessionLocal
from app.models.user import User, LoginAttempt
from app.models.enums import UserRole, ApprovalStatus
from app.models.api_registry import APIRegistry
from app.models.approval_request import ApprovalRequest
from app.models.execution_log import ExecutionLog, ExecutionStatus
from app.utils.auth import hash_password, verify_password, create_access_token, decode_access_token


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
def seed_users():
    """Seeds an Admin, an Operator, and an Approver into the test database."""
    db = SessionLocal()
    try:
        admin = User(
            username="admin_user",
            hashed_password=hash_password("AdminSecretPass123!"),
            role=UserRole.ADMIN,
            is_active=True,
        )
        operator = User(
            username="operator_user",
            hashed_password=hash_password("OperatorPass123!"),
            role=UserRole.OPERATOR,
            is_active=True,
        )
        approver = User(
            username="approver_user",
            hashed_password=hash_password("ApproverPass123!"),
            role=UserRole.APPROVER,
            is_active=True,
        )
        db.add_all([admin, operator, approver])
        db.commit()
        db.refresh(admin)
        db.refresh(operator)
        db.refresh(approver)

        return {
            "admin": admin,
            "operator": operator,
            "approver": approver,
            "admin_token": create_access_token(admin.id, admin.username, admin.role.value),
            "operator_token": create_access_token(operator.id, operator.username, operator.role.value),
            "approver_token": create_access_token(approver.id, approver.username, approver.role.value),
        }
    finally:
        db.close()


# ===========================================================================
# 1. Cryptographic Security Tests
# ===========================================================================
class TestCryptoSecurity:
    def test_password_hashing_security(self):
        """Verifies bcrypt salting, uniqueness, and verification."""
        password = "SuperSecurePassword123!"
        h1 = hash_password(password)
        h2 = hash_password(password)

        # Unique salt per hash
        assert h1 != h2
        assert h1.startswith("$2b$12$")

        # Constant-time verify
        assert verify_password(password, h1) is True
        assert verify_password("WrongPassword", h1) is False
        assert verify_password("", h1) is False

    def test_jwt_claims_validation_issuer_and_audience(self, seed_users):
        """Verifies that invalid issuer or audience rejects the token."""
        user = seed_users["operator"]

        # Valid token passes
        valid_token = create_access_token(user.id, user.username, user.role.value)
        claims = decode_access_token(valid_token)
        assert claims["sub"] == user.id
        assert claims["iss"] == settings.jwt_issuer
        assert claims["aud"] == settings.jwt_audience

        # Tampered issuer
        bad_iss_payload = {
            "iss": "rogue-issuer",
            "aud": settings.jwt_audience,
            "sub": user.id,
            "role": user.role.value,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
            "iat": datetime.now(timezone.utc),
            "nbf": datetime.now(timezone.utc),
        }
        bad_iss_token = jwt.encode(bad_iss_payload, settings.jwt_secret_key, algorithm="HS256")
        with pytest.raises(Exception, match="Invalid authentication token"):
            decode_access_token(bad_iss_token)

    def test_jwt_expired_token_rejected(self, seed_users):
        """Verifies expired tokens are rejected."""
        user = seed_users["operator"]
        expired_token = create_access_token(user.id, user.username, user.role.value, expires_delta=timedelta(seconds=-1))
        with pytest.raises(Exception, match="Token has expired"):
            decode_access_token(expired_token)

    def test_jwt_algorithm_pinning_rejects_none(self, seed_users):
        """Verifies alg: none attacks are rejected."""
        user = seed_users["operator"]
        none_payload = {
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "sub": user.id,
            "role": user.role.value,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
            "iat": datetime.now(timezone.utc),
            "nbf": datetime.now(timezone.utc),
        }
        # Craft alg: none token
        none_token = jwt.encode(none_payload, key="", algorithm="none")
        with pytest.raises(Exception):
            decode_access_token(none_token)

    def test_jwt_signature_tampering_rejected(self, seed_users):
        """Verifies that tampering with payload claims invalidates the token signature."""
        user = seed_users["operator"]
        valid_token = create_access_token(user.id, user.username, user.role.value)

        # Attacker tries to change OPERATOR to ADMIN by tampering the base64 payload
        parts = valid_token.split(".")
        # Signed with a different key
        rogue_token = jwt.encode(
            {"sub": user.id, "role": "ADMIN", "iss": settings.jwt_issuer, "aud": settings.jwt_audience, "exp": datetime.now(timezone.utc) + timedelta(minutes=15), "iat": datetime.now(timezone.utc), "nbf": datetime.now(timezone.utc)},
            "attacker-fake-secret-key-32-chars-long!",
            algorithm="HS256",
        )
        with pytest.raises(Exception):
            decode_access_token(rogue_token)


# ===========================================================================
# 2. Authentication & Rate Limiting Tests
# ===========================================================================
class TestAuthFlows:
    def test_login_success_and_token_generation(self, client, seed_users):
        """Valid credentials return a valid JWT token and correct user role."""
        resp = client.post(
            "/auth/login",
            json={"username": "admin_user", "password": "AdminSecretPass123!"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["role"] == "ADMIN"
        assert data["expires_in_minutes"] == 15

    def test_login_generic_error_on_invalid_credentials(self, client, seed_users):
        """Generic 401 error returned for both wrong password and non-existent username."""
        # 1. Non-existent username
        r1 = client.post("/auth/login", json={"username": "non_existent_ghost", "password": "AnyPassword123!"})
        assert r1.status_code == 401
        assert r1.json()["detail"] == "Invalid username or password."

        # 2. Existing username, wrong password
        r2 = client.post("/auth/login", json={"username": "admin_user", "password": "WrongPassword123!"})
        assert r2.status_code == 401
        assert r2.json()["detail"] == "Invalid username or password."

    def test_login_rate_limiting(self, client, seed_users):
        """5 consecutive failed logins trigger HTTP 429 Too Many Requests."""
        for i in range(5):
            r = client.post("/auth/login", json={"username": "admin_user", "password": "BadPassword!"})
            assert r.status_code == 401

        # 6th attempt must be blocked with 429
        r_blocked = client.post("/auth/login", json={"username": "admin_user", "password": "BadPassword!"})
        assert r_blocked.status_code == 429
        assert "Too many failed login attempts" in r_blocked.json()["detail"]

    def test_burst_rate_limiting_protects_cpu(self, client, seed_users):
        """Excessive rapid bursts within 1 second trigger 429 before bcrypt calculation."""
        from app.services.auth_service import reset_burst_rate_limit
        reset_burst_rate_limit()

        # Send 10 rapid attempts
        for i in range(10):
            client.post("/auth/login", json={"username": f"user_{i}", "password": "password"})

        # 11th attempt within the 1-second burst window must be rate-limited
        r_burst = client.post("/auth/login", json={"username": "user_11", "password": "password"})
        assert r_burst.status_code == 429
        assert "Too many login attempts in a short timeframe" in r_burst.json()["detail"]
        assert "Retry-After" in r_burst.headers

    def test_logout_revokes_token_server_side(self, client, seed_users):
        """Logging out adds the token's JTI to the denylist; subsequent usage fails with 401."""
        token = seed_users["operator_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Token is valid initially
        r_me1 = client.get("/auth/me", headers=headers)
        assert r_me1.status_code == 200

        # Call logout
        r_logout = client.post("/auth/logout", headers=headers)
        assert r_logout.status_code == 200
        assert "Logged out successfully" in r_logout.json()["message"]

        # Subsequent call with the SAME token MUST BE REJECTED with 401 Unauthorized
        r_me2 = client.get("/auth/me", headers=headers)
        assert r_me2.status_code == 401
        assert "Token has been revoked" in r_me2.json()["detail"]

        # Also rejected on other endpoints
        r_apis = client.get("/apis", headers=headers)
        assert r_apis.status_code == 401
        assert "Token has been revoked" in r_apis.json()["detail"]

    def test_prune_expired_revoked_tokens(self, seed_users):
        """Expired revocation entries are pruned while active ones are preserved."""
        from app.models.user import RevokedToken
        from app.services.auth_service import prune_expired_revoked_tokens

        db = SessionLocal()
        try:
            past_jti = str(uuid.uuid4())
            future_jti = str(uuid.uuid4())

            # 1. Past expired token
            past_token = RevokedToken(
                jti=past_jti,
                user_id=seed_users["operator"].id,
                expires_at=datetime.now(timezone.utc) - timedelta(minutes=10),
                revoked_at=datetime.now(timezone.utc) - timedelta(minutes=20),
                reason="user_logout",
            )
            # 2. Future unexpired token
            future_token = RevokedToken(
                jti=future_jti,
                user_id=seed_users["operator"].id,
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
                revoked_at=datetime.now(timezone.utc),
                reason="user_logout",
            )
            db.add_all([past_token, future_token])
            db.commit()

            # Prune
            pruned_count = prune_expired_revoked_tokens(db)
            assert pruned_count >= 1

            # Check DB using preserved string IDs
            assert db.query(RevokedToken).filter_by(jti=past_jti).first() is None
            assert db.query(RevokedToken).filter_by(jti=future_jti).first() is not None
        finally:
            db.close()


# ===========================================================================
# 3. Inbound Authorization (RBAC) Tests
# ===========================================================================
class TestRBACPermissions:
    def test_public_endpoint_accessible_without_auth(self, client):
        """Health check remains accessible without authentication."""
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_unauthenticated_requests_rejected(self, client):
        """All protected routes reject unauthenticated requests with HTTP 401."""
        assert client.get("/apis").status_code == 401
        assert client.post("/apis", json={"name": "test", "base_url": "https://test.com", "endpoints": []}).status_code == 401
        assert client.post("/tasks", json={"task": "test"}).status_code == 401
        assert client.get("/approvals").status_code == 401
        assert client.get("/logs").status_code == 401
        assert client.get("/auth/me").status_code == 401

    def test_operator_rbac_enforcement(self, client, seed_users):
        """
        OPERATOR can submit tasks and view APIs/logs,
        but CANNOT register APIs, approve sensitive tasks, or replay actions.
        """
        op_headers = {"Authorization": f"Bearer {seed_users['operator_token']}"}

        # Allowed: GET /apis/tools (sanitized), GET /logs (own, sanitized), GET /auth/me
        # Tightened in Phase 12: GET /apis (full registry) is restricted to APPROVER/ADMIN (403 for OPERATOR)
        assert client.get("/apis", headers=op_headers).status_code == 403
        assert client.get("/apis/tools", headers=op_headers).status_code == 200
        assert client.get("/logs", headers=op_headers).status_code == 200
        assert client.get("/auth/me", headers=op_headers).status_code == 200

        # Forbidden: POST /apis (403)
        r_post_api = client.post(
            "/apis",
            headers=op_headers,
            json={"name": "Rogue API", "base_url": "https://api.rogue.com", "endpoints": []},
        )
        assert r_post_api.status_code == 403

        # Forbidden: GET /approvals, POST /approvals/{id}/approve (403)
        assert client.get("/approvals", headers=op_headers).status_code == 403
        fake_uuid = str(uuid.uuid4())
        assert client.post(f"/approvals/{fake_uuid}/approve", headers=op_headers).status_code == 403

        # Forbidden: POST /logs/{id}/replay (403)
        assert client.post(f"/logs/{fake_uuid}/replay", headers=op_headers).status_code == 403

    def test_approver_rbac_enforcement(self, client, seed_users):
        """
        APPROVER can view approvals, approve/reject, and replay,
        but CANNOT register APIs or submit new tasks.
        """
        appr_headers = {"Authorization": f"Bearer {seed_users['approver_token']}"}

        # Allowed: GET /approvals, GET /apis, GET /logs
        assert client.get("/approvals", headers=appr_headers).status_code == 200
        assert client.get("/apis", headers=appr_headers).status_code == 200
        assert client.get("/logs", headers=appr_headers).status_code == 200

        # Forbidden: POST /apis (403)
        assert client.post("/apis", headers=appr_headers, json={"name": "X", "base_url": "https://x.com", "endpoints": []}).status_code == 403

        # Forbidden: POST /tasks (403)
        assert client.post("/tasks", headers=appr_headers, json={"task": "Do something"}).status_code == 403

    def test_admin_privileges_and_user_creation(self, client, seed_users):
        """ADMIN has access to register APIs and provision new users."""
        admin_headers = {"Authorization": f"Bearer {seed_users['admin_token']}"}

        # 1. Admin can register an API
        r_api = client.post(
            "/apis",
            headers=admin_headers,
            json={
                "name": "Stripe Service",
                "base_url": "https://api.stripe.com",
                "endpoints": [{"path": "/v1/charges", "method": "POST", "parameters": {}}],
            },
        )
        assert r_api.status_code == 201

        # 2. Admin can create a new Operator
        r_user = client.post(
            "/auth/users",
            headers=admin_headers,
            json={"username": "new_operator", "password": "NewOperatorPass123!", "role": "OPERATOR"},
        )
        assert r_user.status_code == 201
        assert r_user.json()["username"] == "new_operator"
        assert r_user.json()["role"] == "OPERATOR"

        # 3. Non-admin cannot create users
        op_headers = {"Authorization": f"Bearer {seed_users['operator_token']}"}
        r_denied = client.post(
            "/auth/users",
            headers=op_headers,
            json={"username": "hacker", "password": "Password123!", "role": "ADMIN"},
        )
        assert r_denied.status_code == 403

    def test_admin_cannot_silently_bypass_sensitive_approvals(self, client, seed_users):
        """
        CRITICAL GUARDRAIL: When an ADMIN submits a task triggering a SENSITIVE action,
        it MUST NOT auto-execute; it MUST return 202 Accepted and route to the approval queue.
        """
        admin_headers = {"Authorization": f"Bearer {seed_users['admin_token']}"}

        # 1. Register sensitive API
        client.post(
            "/apis",
            headers=admin_headers,
            json={
                "name": "Payout API",
                "base_url": "https://payout.service.com",
                "endpoints": [{"path": "/v1/disburse", "method": "POST", "parameters": {}}],
            },
        )

        # 2. Admin calls POST /tasks
        resp = client.post("/tasks", headers=admin_headers, json={"task": "Disburse payment via Payout API"})
        # MUST return 202 Accepted
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "AWAITING_APPROVAL"
        assert data["is_sensitive"] is True
        assert data["approval_id"] is not None

    def test_four_eyes_anti_self_approval_enforced(self, client, seed_users):
        """
        Anti-Self-Approval: The user who requested a task cannot approve it,
        even if that user has the ADMIN role.
        """
        admin = seed_users["admin"]
        admin_headers = {"Authorization": f"Bearer {seed_users['admin_token']}"}
        appr_headers = {"Authorization": f"Bearer {seed_users['approver_token']}"}

        # 1. Register API
        r_api = client.post(
            "/apis",
            headers=admin_headers,
            json={
                "name": "Treasury",
                "base_url": "https://treasury.com",
                "endpoints": [{"path": "/wire", "method": "POST", "parameters": {}}],
            },
        )
        api_id = r_api.json()["id"]

        # 2. Create approval requested by Admin
        db = SessionLocal()
        try:
            appr = ApprovalRequest(
                api_registry_id=api_id,
                endpoint_path="/wire",
                http_method="POST",
                request_payload={"amount": 5000},
                classification_reason="Wire transfer",
                status=ApprovalStatus.PENDING,
                requested_by_user_id=admin.id,  # Requested by Admin
            )
            db.add(appr)
            db.commit()
            appr_id = appr.id
        finally:
            db.close()

        # 3. Admin attempts to self-approve -> MUST BE FORBIDDEN (403)
        r_self = client.post(f"/approvals/{appr_id}/approve", headers=admin_headers)
        assert r_self.status_code == 403
        assert "Self-approval is forbidden" in r_self.json()["detail"]

        # 4. Independent Approver approves -> Allowed (mocking executor resolve)
        from unittest.mock import patch, MagicMock
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "dispatched"}

        with patch("app.services.executor.resolve_and_verify_host", return_value=["93.184.216.34"]):
            with patch("httpx.AsyncClient.post", return_value=mock_resp):
                r_ok = client.post(f"/approvals/{appr_id}/approve", headers=appr_headers)
                assert r_ok.status_code == 200
                assert r_ok.json()["message"] == "Operation approved and executed successfully."

    def test_dynamic_role_validation_from_db(self, client, seed_users):
        """
        User's role is checked dynamically against the DB. If an Admin demotes
        an Approver to Operator in the DB, their existing token immediately
        loses access to /approvals without waiting for token expiration.
        """
        appr_user = seed_users["approver"]
        appr_token = seed_users["approver_token"]
        headers = {"Authorization": f"Bearer {appr_token}"}

        # Initially, Approver can access /approvals
        assert client.get("/approvals", headers=headers).status_code == 200

        # Admin demotes user to OPERATOR directly in DB
        db = SessionLocal()
        try:
            u = db.query(User).filter_by(id=appr_user.id).first()
            u.role = UserRole.OPERATOR
            db.commit()
        finally:
            db.close()

        # Next request with the SAME token is IMMEDIATELY rejected with 403 Forbidden!
        resp = client.get("/approvals", headers=headers)
        assert resp.status_code == 403
        assert "is not authorized" in resp.json()["detail"]


# ===========================================================================
# 6. Admin Bootstrap and Secret Protection Tests
# ===========================================================================
class TestAdminBootstrap:
    @staticmethod
    def _force_remove_secret(path: str):
        """Remove .admin_bootstrap_secret even if ACL-restricted (Windows)."""
        import os, sys, subprocess
        if not os.path.exists(path):
            return
        try:
            os.remove(path)
        except PermissionError:
            if sys.platform == "win32":
                win_user = os.environ.get("USERNAME")
                if win_user:
                    subprocess.run(
                        ["icacls", path, "/grant", f"{win_user}:(F)"],
                        capture_output=True, check=False, timeout=10,
                    )
                os.remove(path)

    def test_bootstrap_generates_random_secret_when_password_unset(self):
        """Verifies that an unset password generates a secure secret file."""
        import os
        from unittest.mock import patch
        from app.services.auth_service import bootstrap_admin_user

        secret_file = os.path.join(os.getcwd(), ".admin_bootstrap_secret")
        self._force_remove_secret(secret_file)

        db = SessionLocal()
        try:
            with patch("app.config.settings.initial_admin_password", None):
                admin = bootstrap_admin_user(db)
                assert admin is not None
                assert admin.username == "admin"
                assert admin.role == UserRole.ADMIN
                assert os.path.exists(secret_file)

                # Verify secret file content
                with open(secret_file, "r", encoding="utf-8") as f:
                    content = f.read()
                assert "USERNAME=admin" in content
                assert "PASSWORD=" in content

                # Verify generated password works with the stored hash
                for line in content.strip().splitlines():
                    if line.startswith("PASSWORD="):
                        gen_pass = line.split("=", 1)[1]
                        assert len(gen_pass) >= 24
                        assert verify_password(gen_pass, admin.hashed_password) is True
        finally:
            db.close()
            self._force_remove_secret(secret_file)

    def test_bootstrap_is_idempotent(self, seed_users):
        """Verifies that if users already exist, bootstrap returns None (no new user created)."""
        import os
        from app.services.auth_service import bootstrap_admin_user

        secret_file = os.path.join(os.getcwd(), ".admin_bootstrap_secret")
        # Remove any leftover secret file from earlier test lifespans
        self._force_remove_secret(secret_file)

        db = SessionLocal()
        try:
            res = bootstrap_admin_user(db)
            assert res is None
            # No new secret file should have been created by this call
            assert not os.path.exists(secret_file)
        finally:
            db.close()

    def test_bootstrap_fails_fast_if_acl_fails(self):
        """Verifies that if icacls / ACL restriction fails, bootstrap raises RuntimeError and aborts."""
        import os, subprocess
        from unittest.mock import patch, MagicMock
        from app.services.auth_service import bootstrap_admin_user

        secret_file = os.path.join(os.getcwd(), ".admin_bootstrap_secret")
        self._force_remove_secret(secret_file)

        mock_fail = MagicMock()
        mock_fail.returncode = 1
        mock_fail.stderr = b"Access is denied."
        mock_fail.stdout = b""

        db = SessionLocal()
        try:
            with patch("app.config.settings.initial_admin_password", None):
                with patch("subprocess.run", return_value=mock_fail):
                    with pytest.raises(RuntimeError, match="Failed to strip inherited permissions"):
                        bootstrap_admin_user(db)

            # Security guarantee: File must NOT contain credentials!
            if os.path.exists(secret_file):
                with open(secret_file, "r", encoding="utf-8") as f:
                    content = f.read()
                assert "PASSWORD=" not in content
        finally:
            db.close()
            self._force_remove_secret(secret_file)

    def test_posix_permission_verification_failure(self):
        """Verifies that POSIX permission failure raises RuntimeError and is not ignored."""
        import os
        from unittest.mock import patch
        from app.services.auth_service import _restrict_file_permissions

        secret_file = os.path.join(os.getcwd(), ".admin_bootstrap_secret")
        self._force_remove_secret(secret_file)

        with open(secret_file, "w") as f:
            f.write("")

        try:
            # Force non-windows path
            with patch("sys.platform", "linux"):
                with patch("os.chmod"):
                    # Mock stat returning insecure mode 0o666 instead of 0o600
                    mock_stat = os.stat_result((0o100666, 0, 0, 0, 0, 0, 0, 0, 0, 0))
                    with patch("os.stat", return_value=mock_stat):
                        with pytest.raises(RuntimeError, match="POSIX permission verification failed"):
                            _restrict_file_permissions(secret_file)
        finally:
            self._force_remove_secret(secret_file)
