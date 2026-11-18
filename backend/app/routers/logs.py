"""
app/routers/logs.py

FastAPI router for Audit Logs and Operation Replay.

Security & RBAC rules:
1. Log inspection: OPERATOR, APPROVER, ADMIN.
2. Replay execution: Restricted to APPROVER and ADMIN.
3. Sensitive replays: Always re-routed to human approval queue.
"""

import uuid
from typing import List, Optional, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query, Response
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.database import get_db
from app.models.enums import ExecutionStatus, UserRole
from app.models.user import User
from app.dependencies.auth import require_roles
from app.schemas.execution_log import ExecutionLogResponse
from app.services import audit_service
from app.utils.security import sanitize_user_result_data

router = APIRouter()


class ReplayResult(BaseModel):
    status: str
    is_sensitive: bool
    original_log_id: str
    new_log_id: Optional[str] = None
    approval_id: Optional[str] = None
    execution_status: Optional[str] = None
    response_status_code: Optional[int] = None
    response_body: Optional[Any] = None
    message: str


def _validate_uuid(id_str: str) -> str:
    try:
        uuid.UUID(id_str)
        return id_str
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid UUID identifier: '{id_str}'",
        )


def _serialize_log(log, role: UserRole) -> ExecutionLogResponse:
    """
    Serializes an ExecutionLog according to the caller's role.
    Security guarantee: OPERATOR responses NEVER expose internal API IDs,
    endpoint paths, HTTP methods, raw payloads, or raw upstream response bodies.
    """
    if role == UserRole.OPERATOR:
        safe_error = (
            (
                log.error_message
                if (bool(log.is_demo) and log.error_message)
                else "The request could not be completed. Please try again or contact support."
            )
            if log.status == ExecutionStatus.FAILED
            else None
        )
        sanitized_result = (
            sanitize_user_result_data(log.response_body)
            if log.status == ExecutionStatus.SUCCESS
            else None
        )
        return ExecutionLogResponse(
            id=log.id,
            api_name=log.api_name or "Connected Service",
            approval_request_id=log.approval_request_id,
            executed_by_user_id=log.executed_by_user_id,
            executed_by_username=log.executed_by_username,
            status=log.status,
            result_data=sanitized_result,
            is_demo_result=bool(log.is_demo),
            error_message=safe_error,
            duration_ms=log.duration_ms,
            executed_at=log.executed_at,
        )
    return ExecutionLogResponse.model_validate(log)


@router.get(
    "",
    response_model=List[ExecutionLogResponse],
    summary="List execution logs (Role-Scoped)",
)
def list_logs(
    api_id: Optional[str] = Query(None, description="Filter by API ID"),
    status_filter: Optional[ExecutionStatus] = Query(None, alias="status", description="Filter by status"),
    only_approvals: bool = Query(False, description="Filter only operations resulting from human approval"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=200),
    current_user: User = Depends(require_roles([UserRole.OPERATOR, UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """
    Retrieves immutable audit logs scoped strictly by role:
    - OPERATOR: own execution logs only, sanitized (no HTTP internals or raw payloads).
    - APPROVER: approval-linked and failed execution records only (no unrestricted system logs).
    - ADMIN: full system-wide audit trail.
    """
    if api_id:
        _validate_uuid(api_id)

    executed_by = current_user.id if current_user.role == UserRole.OPERATOR else None
    approver_scoped = current_user.role == UserRole.APPROVER

    records = audit_service.list_execution_logs(
        db,
        api_id=api_id,
        status_filter=status_filter,
        executed_by_user_id=executed_by,
        only_approvals=only_approvals,
        approver_scoped=approver_scoped,
        is_demo=bool(current_user.is_demo),
        demo_session_id=current_user.demo_session_id,
        skip=skip,
        limit=limit,
    )
    return [_serialize_log(r, current_user.role) for r in records]


@router.get(
    "/{id}",
    response_model=ExecutionLogResponse,
    summary="Get execution log by ID (Role-Scoped)",
)
def get_log(
    id: str,
    current_user: User = Depends(require_roles([UserRole.OPERATOR, UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """Retrieves details of a specific execution log entry (Tenant, session isolation, ownership & role-scope enforced)."""
    _validate_uuid(id)
    log = audit_service.get_execution_log_by_id(db, id)
    if not log:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execution log not found.")

    # Hard Demo & Per-Session Isolation
    if bool(log.is_demo) != bool(current_user.is_demo) or (
        current_user.is_demo and log.demo_session_id != current_user.demo_session_id
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Cross-environment or cross-session execution log access is forbidden.",
        )

    # IDOR Protection: Operators can only inspect their own execution logs
    if current_user.role == UserRole.OPERATOR and log.executed_by_user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You can only view your own execution records.",
        )

    # Scope Protection: Approvers can only inspect approval-linked or failed logs
    if (
        current_user.role == UserRole.APPROVER
        and log.approval_request_id is None
        and log.status != ExecutionStatus.FAILED
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Approvers can only inspect approval-linked or failed execution records.",
        )

    return _serialize_log(log, current_user.role)


@router.post(
    "/{id}/replay",
    response_model=ReplayResult,
    summary="Replay previous operation (Approver or Admin only)",
)
async def replay_log(
    id: str,
    response: Response,
    current_user: User = Depends(require_roles([UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """
    Replays a previous API call using its stored payload.
    - Restricted to non-demo APPROVER and ADMIN roles (disabled in Recruiter Demo Mode).
    - APPROVER can only replay approval-linked or failed execution logs (matches GET /logs scope).
    - Real users cannot replay isolated demo logs.
    - If the operation is SAFE, executes immediately (200 OK).
    - If the operation is SENSITIVE, routes to human approval queue (202 Accepted).
    """
    if current_user.is_demo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation replay is disabled in Recruiter Demo Mode.",
        )
    _validate_uuid(id)
    existing_log = audit_service.get_execution_log_by_id(db, id)
    if existing_log and bool(existing_log.is_demo):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Cannot replay isolated demo execution records.",
        )
    if current_user.role == UserRole.APPROVER:
        if not existing_log:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Execution log '{id}' not found.")
        if existing_log.approval_request_id is None and existing_log.status != ExecutionStatus.FAILED:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Approvers can only replay approval-linked or failed execution records.",
            )
    try:
        result = await audit_service.replay_execution(db, id, user_id=current_user.id)
        if result.get("is_sensitive"):
            response.status_code = status.HTTP_202_ACCEPTED
        else:
            response.status_code = status.HTTP_200_OK
        return ReplayResult(**result)

    except audit_service.LogNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except audit_service.TargetAPINotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
