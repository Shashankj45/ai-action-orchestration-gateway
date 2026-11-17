"""
app/routers/approvals.py

FastAPI router for Human Approval workflows.

Security & RBAC rules:
1. Permitted roles: APPROVER, ADMIN.
2. Anti-Self-Approval (Four-Eyes Principle): A user cannot approve a sensitive
   action that they themselves submitted.
3. Frozen payload execution: executes strictly from DB record.
"""

import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.database import get_db
from app.models.enums import ApprovalStatus, UserRole
from app.models.user import User
from app.dependencies.auth import require_roles
from app.schemas.approval_request import (
    ApprovalRequestResponse,
    ApprovalDecisionRequest,
)
from app.schemas.execution_log import ExecutionLogResponse
from app.services import approval_service

router = APIRouter()


class ApprovalActionResult(BaseModel):
    approval: ApprovalRequestResponse
    execution: Optional[ExecutionLogResponse] = None
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
    response_model=List[ApprovalRequestResponse],
    summary="List pending approvals",
)
def list_approvals(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=200),
    current_user: User = Depends(require_roles([UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """Retrieves all pending human approval requests (Approver or Admin only)."""
    return approval_service.list_pending_approvals(db, skip=skip, limit=limit)


@router.get(
    "/{id}",
    response_model=ApprovalRequestResponse,
    summary="Get approval request details",
)
def get_approval(
    id: str,
    current_user: User = Depends(require_roles([UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """Retrieves details of an approval request by UUID (Approver or Admin only)."""
    _validate_uuid(id)
    approval = approval_service.get_approval_by_id(db, id)
    if not approval:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval request not found.")
    return approval


@router.post(
    "/{id}/approve",
    response_model=ApprovalActionResult,
    summary="Approve sensitive operation",
)
async def approve_request(
    id: str,
    current_user: User = Depends(require_roles([UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """
    Approves a pending sensitive operation and triggers execution against the external API.
    - Restricted to APPROVER and ADMIN roles.
    - Anti-Self-Approval: Cannot approve an action you requested.
    - Frozen payload execution: executes strictly from DB record.
    """
    _validate_uuid(id)
    try:
        appr, exec_log = await approval_service.process_approval_decision(
            db=db,
            approval_id=id,
            decision=ApprovalStatus.APPROVED,
            decided_by_user_id=current_user.id,
        )
        return ApprovalActionResult(
            approval=ApprovalRequestResponse.model_validate(appr),
            execution=ExecutionLogResponse.model_validate(exec_log) if exec_log else None,
            message="Operation approved and executed successfully.",
        )
    except approval_service.ApprovalNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except approval_service.InvalidApprovalStateError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except approval_service.SelfApprovalForbiddenError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))


@router.post(
    "/{id}/reject",
    response_model=ApprovalActionResult,
    summary="Reject sensitive operation",
)
async def reject_request(
    id: str,
    current_user: User = Depends(require_roles([UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """Rejects a pending sensitive operation (Approver or Admin only)."""
    _validate_uuid(id)
    try:
        appr, _ = await approval_service.process_approval_decision(
            db=db,
            approval_id=id,
            decision=ApprovalStatus.REJECTED,
            decided_by_user_id=current_user.id,
        )
        return ApprovalActionResult(
            approval=ApprovalRequestResponse.model_validate(appr),
            execution=None,
            message="Operation rejected by user.",
        )
    except approval_service.ApprovalNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except approval_service.InvalidApprovalStateError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
