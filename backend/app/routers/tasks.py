"""
app/routers/tasks.py

FastAPI router for natural-language tasks and guardrailed orchestration.

Security & RBAC rules:
1. Permitted roles: OPERATOR, ADMIN. (APPROVER cannot submit tasks).
2. Admin No-Bypass Rule: Even if an ADMIN submits a task, if the operation
   is SENSITIVE, it MUST enter the approval queue (HTTP 202).
3. Identity attribution: stamps requested_by_user_id on ApprovalRequest.
"""

from fastapi import APIRouter, Depends, status, Response
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
    - OPERATOR and ADMIN roles permitted.
    - SENSITIVE actions halt in the approval queue regardless of submitter's role.
    """
    # 1. Orchestrate: convert task -> validated tool action
    plan = await orchestrate_task(db, payload.task)

    # If the orchestrator could not produce a plan (e.g. no tools, validation failure)
    if plan.status != "PLAN_CREATED":
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
        )
        response.status_code = status.HTTP_202_ACCEPTED
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

    # 4. Branch B: SAFE Operation -> Auto-execute directly
    exec_log = await execute_api_call(
        db=db,
        api=api,
        endpoint_path=plan.endpoint_path,
        http_method=plan.http_method,
        payload=plan.request_payload or {},
        executed_by_user_id=current_user.id,
    )

    response.status_code = status.HTTP_200_OK
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
