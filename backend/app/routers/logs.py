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


@router.get(
    "",
    response_model=List[ExecutionLogResponse],
    summary="List execution logs",
)
def list_logs(
    api_id: Optional[str] = Query(None, description="Filter by API ID"),
    status_filter: Optional[ExecutionStatus] = Query(None, alias="status", description="Filter by status"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=200),
    current_user: User = Depends(require_roles([UserRole.OPERATOR, UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """Retrieves immutable audit logs for external API calls."""
    if api_id:
        _validate_uuid(api_id)
    return audit_service.list_execution_logs(
        db, api_id=api_id, status_filter=status_filter, skip=skip, limit=limit
    )


@router.get(
    "/{id}",
    response_model=ExecutionLogResponse,
    summary="Get execution log by ID",
)
def get_log(
    id: str,
    current_user: User = Depends(require_roles([UserRole.OPERATOR, UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """Retrieves full details of a specific execution log entry."""
    _validate_uuid(id)
    log = audit_service.get_execution_log_by_id(db, id)
    if not log:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execution log not found.")
    return log


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
    - Restricted to APPROVER and ADMIN roles.
    - If the operation is SAFE, executes immediately (200 OK).
    - If the operation is SENSITIVE, routes to human approval queue (202 Accepted).
    """
    _validate_uuid(id)
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
