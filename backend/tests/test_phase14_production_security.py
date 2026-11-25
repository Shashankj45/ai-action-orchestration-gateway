"""
backend/tests/test_phase14_production_security.py

Phase 14: Production Hardening & README/Config Verification.

Verifies:
1. render.yaml sets ALLOWED_HOSTS=ai-action-orchestration-gateway.onrender.com (not '*').
2. Production FastAPI app (APP_ENV=production) disables /docs, /redoc, and /openapi.json.
3. Production FastAPI app activates TrustedHostMiddleware:
   - Accepts Host: ai-action-orchestration-gateway.onrender.com on /health, API calls, and CORS preflight.
   - Rejects spoofed/invalid Host headers (evil.attacker.com, localhost, 127.0.0.1) with 400.
4. Root README.md excludes /docs, /redoc, /openapi.json links and exposes no credentials/secrets.
"""

import os
import re
import subprocess
import sys
import tempfile


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BACKEND_DIR = os.path.join(REPO_ROOT, "backend")


def test_render_yaml_enforces_exact_allowed_hosts():
    """render.yaml must pin ALLOWED_HOSTS to ai-action-orchestration-gateway.onrender.com."""
    render_path = os.path.join(REPO_ROOT, "render.yaml")
    with open(render_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert 'value: "*"' not in content, "ALLOWED_HOSTS must not be wildcard '*' in render.yaml"
    assert "ALLOWED_HOSTS" in content
    assert "ai-action-orchestration-gateway.onrender.com" in content
    assert "value: production" in content


def test_readme_cleanup_and_no_sensitive_exposure():
    """README.md keeps only safe public links and removes Swagger/ReDoc/OpenAPI URLs and secrets."""
    readme_path = os.path.join(REPO_ROOT, "README.md")
    with open(readme_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Required kept links
    assert "https://github.com/Shashankj45/ai-action-orchestration-gateway" in content
    assert "https://ai-action-orchestration-gateway.vercel.app" in content
    assert "https://ai-action-orchestration-gateway.onrender.com/health" in content

    # Removed documentation/unused links
    assert "/docs" not in content
    assert "/redoc" not in content
    assert "/openapi.json" not in content
    assert "**Live Backend API (Render):**" not in content

    # Ensure no secret tokens, passwords, or DB connection strings appear in README
    forbidden_patterns = [
        r"rnd_[A-Za-z0-9]+",
        r"Fn60Pn1",
        r"OperatorPass",
        r"ApproverPass",
        r"sk-[A-Za-z0-9]{16,}",
        r"5Sps4BvH",
        r"dpg-[A-Za-z0-9-]+",
    ]
    for pattern in forbidden_patterns:
        assert not re.search(pattern, content), f"Sensitive pattern '{pattern}' found in README.md"


def test_production_trusted_host_and_disabled_docs():
    """
    Boots the real app.main:app in APP_ENV=production with ALLOWED_HOSTS=ai-action-orchestration-gateway.onrender.com
    in an isolated subprocess and verifies:
    - TrustedHostMiddleware is active.
    - /health returns 200 {"status": "ok"} for valid Host.
    - /docs, /redoc, /openapi.json return 404 for valid Host.
    - Legitimate CORS preflight + POST /auth/demo-login + GET /auth/me succeed for valid Host.
    - Invalid Host headers are rejected with 400 on GET /health, POST /auth/demo-login, and OPTIONS preflight.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "prod_sec_test.db").replace("\\", "/")
        env = os.environ.copy()
        env.update(
            {
                "APP_ENV": "production",
                "ALLOWED_HOSTS": "ai-action-orchestration-gateway.onrender.com",
                "ALLOWED_ORIGINS": "https://ai-action-orchestration-gateway.vercel.app",
                "DATABASE_URL": f"sqlite:///{db_path}",
                "SECRET_KEY": "a" * 64,
                "JWT_SECRET_KEY": "b" * 64,
                "INITIAL_ADMIN_PASSWORD": "ProdTestAdminPass123!",
            }
        )

        script = """
import asyncio, sys
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from fastapi.testclient import TestClient
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from app.main import app

has_trusted_host = any(m.cls is TrustedHostMiddleware for m in app.user_middleware)
assert has_trusted_host, "TrustedHostMiddleware was not registered in production!"

VALID_HOST = "ai-action-orchestration-gateway.onrender.com"
VERCEL_ORIGIN = "https://ai-action-orchestration-gateway.vercel.app"

with TestClient(app) as client:
    # 1. Valid host on /health -> 200 {"status": "ok"}
    r_health = client.get("/health", headers={"Host": VALID_HOST})
    assert r_health.status_code == 200, f"Unexpected health status: {r_health.status_code} {r_health.text}"
    assert r_health.json() == {"status": "ok"}

    # 2. Docs & OpenAPI remain disabled in production -> 404
    for doc_path in ("/docs", "/redoc", "/openapi.json"):
        r_doc = client.get(doc_path, headers={"Host": VALID_HOST})
        assert r_doc.status_code == 404, f"{doc_path} returned {r_doc.status_code}"

    # 3. Legitimate CORS preflight from Vercel frontend -> allowed (200)
    r_preflight = client.options(
        "/auth/demo-login",
        headers={
            "Host": VALID_HOST,
            "Origin": VERCEL_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,authorization",
        },
    )
    assert r_preflight.status_code == 200, f"CORS preflight failed: {r_preflight.status_code} {r_preflight.text}"
    assert r_preflight.headers.get("access-control-allow-origin") == VERCEL_ORIGIN

    # 4. Legitimate API request flow (POST /auth/demo-login -> GET /auth/me)
    r_demo = client.post(
        "/auth/demo-login",
        headers={"Host": VALID_HOST, "Origin": VERCEL_ORIGIN},
        json={"role": "user"},
    )
    assert r_demo.status_code == 200, f"Demo login failed: {r_demo.status_code} {r_demo.text}"
    token = r_demo.json()["access_token"]
    r_me = client.get(
        "/auth/me",
        headers={"Host": VALID_HOST, "Authorization": f"Bearer {token}"},
    )
    assert r_me.status_code == 200
    assert r_me.json()["role"] == "OPERATOR"

    # 5. Invalid/spoofed Host headers rejected with 400 Invalid host header
    for bad_host in ("evil.attacker.com", "localhost", "127.0.0.1"):
        r_bad_health = client.get("/health", headers={"Host": bad_host})
        assert r_bad_health.status_code == 400, f"Expected 400 for Host={bad_host}, got {r_bad_health.status_code}"
        r_bad_api = client.post("/auth/demo-login", headers={"Host": bad_host}, json={"role": "user"})
        assert r_bad_api.status_code == 400, f"Expected 400 for API Host={bad_host}, got {r_bad_api.status_code}"
        r_bad_opt = client.options(
            "/auth/demo-login",
            headers={
                "Host": bad_host,
                "Origin": VERCEL_ORIGIN,
                "Access-Control-Request-Method": "POST",
            },
        )
        assert r_bad_opt.status_code == 400, f"Expected 400 for OPTIONS Host={bad_host}, got {r_bad_opt.status_code}"

print("PROD_SECURITY_OK")
"""
        res = subprocess.run(
            [sys.executable, "-c", script],
            cwd=BACKEND_DIR,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert res.returncode == 0, (
            f"Production security subprocess failed (rc={res.returncode}):\n"
            f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
        )
        assert "PROD_SECURITY_OK" in res.stdout
