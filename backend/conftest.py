"""
Root-level conftest.py — loaded by pytest BEFORE any test file.

Windows compatibility:
Python 3.12 on Windows defaults to IocpProactor event loop which
conflicts with anyio's thread-based TestClient when ASGI lifespan
is involved. Force SelectorEventLoop globally before pytest collects.
"""
import asyncio
import os
import sys

# Provide deterministic test secrets if not set in the environment
os.environ.setdefault("SECRET_KEY", "test-secret-key-32-chars-long-for-testing-purposes-123")
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-at-least-32-chars-long-for-testing-purposes")

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
