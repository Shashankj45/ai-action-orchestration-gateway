"""
conftest.py

Shared pytest configuration and fixtures.

Windows fix: Python 3.8+ on Windows defaults to IocpProactor event loop,
which can conflict with anyio / starlette's TestClient when lifespan
is involved. Force SelectorEventLoop for all tests.
"""
import asyncio
import sys
import pytest
from starlette.testclient import TestClient

if sys.platform == "win32":
    # Force the selector event loop on Windows to prevent IocpProactor
    # from conflicting with anyio-based TestClient lifespan handling.
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


def create_test_admin_client():
    """Helper to create an authenticated Admin TestClient for legacy tests."""
    from app.main import app
    from app.database import SessionLocal
    from app.models.user import User
    from app.models.enums import UserRole
    from app.utils.auth import hash_password, create_access_token

    db = SessionLocal()
    try:
        admin = db.query(User).filter_by(username="test_admin").first()
        if not admin:
            admin = User(
                id="00000000-0000-0000-0000-000000000001",
                username="test_admin",
                hashed_password=hash_password("admin_pass123"),
                role=UserRole.ADMIN,
                is_active=True,
            )
            db.add(admin)
            db.commit()
            db.refresh(admin)
        token = create_access_token(admin.id, admin.username, admin.role.value)
    finally:
        db.close()

    with TestClient(app) as c:
        c.headers["Authorization"] = f"Bearer {token}"
        yield c
