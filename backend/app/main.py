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

from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware  # used in production
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
import time

from sqlalchemy.orm import Session
from sqlalchemy import inspect, text
from app.config import settings
from app.database import engine, Base, SessionLocal, get_db
from app.routers.auth import router as auth_router
from app.routers.registry import router as registry_router
from app.routers.tasks import router as tasks_router
from app.routers.approvals import router as approvals_router
from app.routers.logs import router as logs_router
from app.dependencies.auth import require_roles
from app.models.enums import UserRole, ApprovalStatus
from app.models.user import User
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
    # Safe idempotent column check for existing deployments (PostgreSQL & SQLite)
    try:
        inspector = inspect(engine)
        existing_tables = set(inspector.get_table_names())
        if "approval_requests" in existing_tables:
            cols = {c["name"] for c in inspector.get_columns("approval_requests")}
            if "rejection_reason" not in cols:
                with engine.begin() as conn:
                    conn.execute(text("ALTER TABLE approval_requests ADD COLUMN rejection_reason TEXT"))
                logger.info("Added missing column 'rejection_reason' to approval_requests.")
        for table_name in ("users", "api_registry", "approval_requests", "execution_logs"):
            if table_name in existing_tables:
                cols = {c["name"] for c in inspector.get_columns(table_name)}
                if "is_demo" not in cols:
                    with engine.begin() as conn:
                        conn.execute(
                            text(f"ALTER TABLE {table_name} ADD COLUMN is_demo BOOLEAN NOT NULL DEFAULT FALSE")
                        )
                    logger.info("Added missing column 'is_demo' to %s.", table_name)
                if "demo_session_id" not in cols:
                    with engine.begin() as conn:
                        conn.execute(
                            text(f"ALTER TABLE {table_name} ADD COLUMN demo_session_id VARCHAR(36)")
                        )
                    logger.info("Added missing column 'demo_session_id' to %s.", table_name)
    except Exception as exc:
        logger.warning("Schema column verification encountered: %s", exc)
    logger.info("Database tables verified/created.")
    # Initialize Admin account if no users exist, prune expired tokens & expired demo sessions
    try:
        from app.services.demo_service import cleanup_expired_demo_sessions
        with SessionLocal() as db:
            bootstrap_admin_user(db)
            pruned = prune_expired_revoked_tokens(db)
            if pruned > 0:
                logger.info("Pruned %d expired revoked tokens from denylist.", pruned)
            cleaned_demos = cleanup_expired_demo_sessions(db)
            if cleaned_demos > 0:
                logger.info("Pruned %d expired demo sessions.", cleaned_demos)
    except Exception as exc:
        logger.warning("Admin bootstrap / maintenance encountered: %s", exc)
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
# Middleware 1: CORS — explicit allow-list, not wildcard
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)


# ---------------------------------------------------------------------------
# Middleware 2: Trusted Host (runs outside CORS so even preflights reject bad hosts)
# ---------------------------------------------------------------------------
if settings.is_production and settings.allowed_hosts != "*":
    trusted_hosts = [h.strip() for h in settings.allowed_hosts.split(",") if h.strip()]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts)


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
# Administrative System Telemetry (Admin Only)
# ---------------------------------------------------------------------------
@app.get("/system/metrics", tags=["System"])
def system_metrics(
    current_user: User = Depends(require_roles([UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """
    Returns administrative telemetry, counts, and security settings (Admin only).
    Demo Admin strictly receives demo-scoped counts and masked sandbox configuration.
    """
    from sqlalchemy import func
    from app.models.api_registry import APIRegistry
    from app.models.approval_request import ApprovalRequest
    from app.models.execution_log import ExecutionLog

    demo_scope = bool(current_user.is_demo)
    demo_session_id = current_user.demo_session_id

    api_q = db.query(func.count(APIRegistry.id)).filter(APIRegistry.is_demo == demo_scope)
    user_q = db.query(func.count(User.id)).filter(User.is_demo == demo_scope)
    appr_q = db.query(func.count(ApprovalRequest.id)).filter(
        ApprovalRequest.status == ApprovalStatus.PENDING,
        ApprovalRequest.is_demo == demo_scope,
    )
    log_q = db.query(func.count(ExecutionLog.id)).filter(ExecutionLog.is_demo == demo_scope)

    if demo_scope:
        api_q = api_q.filter(APIRegistry.demo_session_id == demo_session_id)
        user_q = user_q.filter(User.demo_session_id == demo_session_id)
        appr_q = appr_q.filter(ApprovalRequest.demo_session_id == demo_session_id)
        log_q = log_q.filter(ExecutionLog.demo_session_id == demo_session_id)

    total_apis = api_q.scalar() or 0
    total_users = user_q.scalar() or 0
    pending_approvals = appr_q.scalar() or 0
    total_executions = log_q.scalar() or 0

    if demo_scope:
        return {
            "status": "healthy",
            "app_env": "demo-sandbox",
            "is_demo": True,
            "total_apis": total_apis,
            "total_users": total_users,
            "pending_approvals": pending_approvals,
            "total_executions": total_executions,
            "jwt_issuer": settings.jwt_issuer,
            "jwt_audience": settings.jwt_audience,
            "jwt_expire_minutes": settings.jwt_access_token_expire_minutes,
            "allowed_hosts": "demo-sandbox (restricted)",
            "allowed_origins": ["demo-sandbox (restricted)"],
        }

    return {
        "status": "healthy",
        "app_env": settings.app_env,
        "is_demo": False,
        "total_apis": total_apis,
        "total_users": total_users,
        "pending_approvals": pending_approvals,
        "total_executions": total_executions,
        "jwt_issuer": settings.jwt_issuer,
        "jwt_audience": settings.jwt_audience,
        "jwt_expire_minutes": settings.jwt_access_token_expire_minutes,
        "allowed_hosts": settings.allowed_hosts,
        "allowed_origins": settings.cors_origins,
    }


# ---------------------------------------------------------------------------
# Root redirect to docs (dev only)
# ---------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
def root():
    if settings.is_production:
        return {"detail": "Not found"}
    return {"message": "Gateway running. Visit /docs for API documentation."}
