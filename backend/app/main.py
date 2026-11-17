"""
app/main.py

FastAPI application entry point.

Security controls implemented here:
1. CORS: restricted to ALLOWED_ORIGINS from config (not wildcard '*').
2. TrustedHostMiddleware: rejects requests with unexpected Host headers
   (prevents host-header injection attacks).
3. Request size limit: rejects oversized bodies before they hit any handler.
4. Security headers: added via middleware (X-Content-Type-Options, etc.).
5. /health endpoint: returns minimal info (never exposes internals).
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware  # used in production
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
import time

from app.config import settings
from app.database import engine, Base, SessionLocal
from app.routers.auth import router as auth_router
from app.routers.registry import router as registry_router
from app.routers.tasks import router as tasks_router
from app.routers.approvals import router as approvals_router
from app.routers.logs import router as logs_router
from app.services.auth_service import bootstrap_admin_user, prune_expired_revoked_tokens

# ---------------------------------------------------------------------------
# Logging setup — structured, level-aware
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG if not settings.is_production else logging.WARNING,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("gateway")


# ---------------------------------------------------------------------------
# Lifespan: runs on startup and shutdown
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Gateway starting up — environment: %s", settings.app_env)
    # Create all DB tables (Alembic handles migrations in prod; this covers dev)
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables verified/created.")
    # Initialize Admin account if no users exist
    try:
        with SessionLocal() as db:
            bootstrap_admin_user(db)
            pruned = prune_expired_revoked_tokens(db)
            if pruned > 0:
                logger.info("Pruned %d expired revoked tokens from denylist.", pruned)
    except Exception as exc:
        logger.warning("Admin bootstrap / token maintenance encountered: %s", exc)
    yield
    logger.info("Gateway shutting down.")


# ---------------------------------------------------------------------------
# App instance
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Guardrailed AI Action & API Orchestration Gateway",
    description=(
        "A backend middleware that sits between an AI assistant and "
        "external REST APIs, with built-in safety guardrails."
    ),
    version="0.1.0",
    # Disable docs in production — they expose your full API surface
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
    openapi_url=None if settings.is_production else "/openapi.json",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Middleware 1: Trusted Host (prevents host-header injection)
# ---------------------------------------------------------------------------
if settings.is_production and settings.allowed_hosts != "*":
    trusted_hosts = [h.strip() for h in settings.allowed_hosts.split(",") if h.strip()]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts)


# ---------------------------------------------------------------------------
# Middleware 2: CORS — explicit allow-list, not wildcard
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)


# ---------------------------------------------------------------------------
# Middleware 3: Security headers
# ---------------------------------------------------------------------------
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
    if settings.is_production:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response


# ---------------------------------------------------------------------------
# Middleware 4: Request size enforcement
# ---------------------------------------------------------------------------
@app.middleware("http")
async def enforce_request_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.max_request_size:
        return JSONResponse(
            status_code=413,
            content={"detail": "Request body too large."},
        )
    return await call_next(request)


# ---------------------------------------------------------------------------
# Middleware 5: Request timing (for observability)
# ---------------------------------------------------------------------------
@app.middleware("http")
async def add_timing_header(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    response.headers["X-Response-Time-Ms"] = str(duration_ms)
    return response


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(auth_router, prefix="/auth", tags=["Authentication & RBAC"])
app.include_router(registry_router, prefix="/apis", tags=["API Registry"])
app.include_router(tasks_router, prefix="/tasks", tags=["Tasks & Orchestration"])
app.include_router(approvals_router, prefix="/approvals", tags=["Approvals"])
app.include_router(logs_router, prefix="/logs", tags=["Audit & Logs"])


# ---------------------------------------------------------------------------
# Health check — minimal, no internals exposed
# ---------------------------------------------------------------------------
@app.get("/health", tags=["System"])
def health_check():
    """
    Returns service liveness. Does NOT expose version, DB status,
    or any internal configuration.
    """
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Root redirect to docs (dev only)
# ---------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
def root():
    if settings.is_production:
        return {"detail": "Not found"}
    return {"message": "Gateway running. Visit /docs for API documentation."}
