"""
Root-level conftest.py — loaded by pytest BEFORE any test file.

Windows compatibility:
Python 3.12 on Windows defaults to IocpProactor event loop which
conflicts with anyio's thread-based TestClient when ASGI lifespan
is involved. Force SelectorEventLoop globally before pytest collects.
"""
import asyncio
import sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
