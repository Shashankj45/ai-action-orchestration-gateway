"""
app/routers/tasks.py

FastAPI router for natural-language tasks and guardrailed orchestration.

Security & RBAC rules:
1. Permitted roles: OPERATOR, ADMIN. (APPROVER cannot submit tasks).
2. Admin No-Bypass Rule: Even if an ADMIN submits a task, if the operation
   is SENSITIVE, it MUST enter the approval queue (HTTP 202).
3. Identity attribution: stamps requested_by_user_id on ApprovalRequest.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.api_registry import APIRegistry
from app.models.enums import UserRole
from app.models.user import User
from app.dependencies.auth import require_roles
from app.schemas.tasks import TaskRequest, TaskExecutionResult
from app.services.orchestrator import orchestrate_task
from app.services.classifier import classify_action
from app.services.approval_service import create_approval_request
from app.services.executor import execute_api_call
from app.services import demo_service

router = APIRouter()


@router.post(
    "",
    response_model=TaskExecutionResult,
    summary="Process natural-language task with guardrails",
)
async def process_task(
    payload: TaskRequest,
    response: Response,
    current_user: User = Depends(require_roles([UserRole.OPERATOR, UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """
    Submits a task for AI translation, strict parameter validation, and safety routing.
    - OPERATOR and ADMIN roles permitted (Demo Admin is read-only and blocked).
    - SENSITIVE actions halt in the approval queue regardless of submitter's role.
    - Demo sessions are strictly isolated to demo APIs and simulated sandbox execution.
    """
    if current_user.is_demo and current_user.role == UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Task execution is disabled for Demo Admin. Switch to User Demo to submit requests.",
        )

    is_demo_session = bool(current_user.is_demo)
    demo_session_id = current_user.demo_session_id

    # Rate limit enforcement on POST /tasks (stricter cap for demo sessions + total per-session action limit)
    try:
        demo_service.check_task_rate_limit(current_user.id, is_demo=is_demo_session)
        if is_demo_session and demo_session_id:
            demo_service.enforce_demo_session_action_limit(db, demo_session_id)
    except demo_service.DemoRateLimitExceededError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            headers={"Retry-After": "60"},
        )

    # 1. Orchestrate: convert task -> validated tool action
    plan = await orchestrate_task(
        db,
        payload.task,
        is_demo=is_demo_session,
        demo_session_id=demo_session_id,
    )

    # If the orchestrator could not produce a plan (e.g. no tools, validation failure)
    if plan.status != "PLAN_CREATED":
        if current_user.role == UserRole.OPERATOR:
            return TaskExecutionResult(
                status=plan.status,
                api_name=plan.api_name,
                message="We could not complete your request. Please rephrase what you need or verify the details you provided.",
            )
        return TaskExecutionResult(
            status=plan.status,
            api_id=plan.api_id,
            api_name=plan.api_name,
            endpoint_path=plan.endpoint_path,
            http_method=plan.http_method,
            is_sensitive=plan.is_sensitive,
            message=plan.message,
        )

    # 2. Safety Classification
    is_sensitive, reason = classify_action(
        http_method=plan.http_method,
        endpoint_path=plan.endpoint_path,
        api_is_sensitive=bool(plan.is_sensitive),
    )

    api = db.query(APIRegistry).filter(APIRegistry.id == plan.api_id).first()

    # 3. Branch A: SENSITIVE Operation -> Hold for human review
    # Security Rule: Admin DOES NOT bypass this check!
    if is_sensitive:
        approval = create_approval_request(
            db=db,
            api_id=plan.api_id,
            endpoint_path=plan.endpoint_path,
            http_method=plan.http_method,
            request_payload=plan.request_payload or {},
            classification_reason=reason,
            requested_by_user_id=current_user.id,
            is_demo=is_demo_session,
            demo_session_id=demo_session_id,
        )
        response.status_code = status.HTTP_202_ACCEPTED
        # Sanitize response for OPERATOR: hide internal API details
        if current_user.role == UserRole.OPERATOR:
            return TaskExecutionResult(
                status="AWAITING_APPROVAL",
                api_name=plan.api_name,
                is_sensitive=True,
                approval_id=approval.id,
                message="Your request has been submitted and is awaiting approval before it can be completed.",
            )
        return TaskExecutionResult(
            status="AWAITING_APPROVAL",
            api_id=plan.api_id,
            api_name=plan.api_name,
            endpoint_path=plan.endpoint_path,
            http_method=plan.http_method,
            is_sensitive=True,
            request_payload=plan.request_payload,
            approval_id=approval.id,
            classification_reason=reason,
            message="Operation classified as SENSITIVE. Human approval required before execution.",
        )

    # 4. Branch B: SAFE Operation -> Auto-execute directly (or sandbox-simulate in Demo Mode)
    exec_log = await execute_api_call(
        db=db,
        api=api,
        endpoint_path=plan.endpoint_path,
        http_method=plan.http_method,
        payload=plan.request_payload or {},
        executed_by_user_id=current_user.id,
        is_demo_execution=is_demo_session,
        demo_session_id=demo_session_id,
    )

    response.status_code = status.HTTP_200_OK
    # Sanitize response for OPERATOR: hide internal API and HTTP details
    if current_user.role == UserRole.OPERATOR:
        return TaskExecutionResult(
            status="EXECUTED_SAFE",
            api_name=plan.api_name,
            is_sensitive=False,
            execution_log_id=exec_log.id,
            execution_status=exec_log.status.value,
            duration_ms=exec_log.duration_ms,
            message="Your request was completed successfully.",
        )
    return TaskExecutionResult(
        status="EXECUTED_SAFE",
        api_id=plan.api_id,
        api_name=plan.api_name,
        endpoint_path=plan.endpoint_path,
        http_method=plan.http_method,
        is_sensitive=False,
        request_payload=plan.request_payload,
        classification_reason=reason,
        execution_log_id=exec_log.id,
        execution_status=exec_log.status.value,
        response_status_code=exec_log.response_status_code,
        response_body=exec_log.response_body,
        duration_ms=exec_log.duration_ms,
        message="Operation classified as SAFE and executed automatically.",
    )
