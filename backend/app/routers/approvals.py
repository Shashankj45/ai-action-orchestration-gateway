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
from fastapi import APIRouter, Depends, HTTPException, status, Query, Body
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field, field_validator

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


class RejectionRequest(BaseModel):
    reason: str = Field(
        ...,
        min_length=3,
        max_length=500,
        description="Mandatory reason for rejection (3-500 characters)",
    )

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Rejection reason cannot be blank or whitespace only.")
        if len(cleaned) < 3:
            raise ValueError("Rejection reason must be at least 3 characters.")
        return cleaned


def _serialize_approval(approval, role: UserRole) -> ApprovalRequestResponse:
    """
    Serializes an ApprovalRequest according to the caller's role.
    Security guarantee: OPERATOR responses NEVER include internal API IDs,
    endpoint paths, HTTP methods, raw request payloads, or internal security reasoning.
    """
    if role == UserRole.OPERATOR:
        service_label = approval.api_name or "Connected Service"
        return ApprovalRequestResponse(
            id=approval.id,
            api_name=service_label,
            summary=f"Sensitive request via {service_label}",
            status=approval.status,
            requested_by_user_id=approval.requested_by_user_id,
            requested_by_username=approval.requested_by_username,
            decided_by_username=approval.decided_by_username,
            decided_at=approval.decided_at,
            rejection_reason=approval.rejection_reason,
            created_at=approval.created_at,
        )
    return ApprovalRequestResponse.model_validate(approval)


def _validate_uuid(id_str: str) -> str:
    try:
        uuid.UUID(id_str)
        return id_str
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid UUID identifier: '{id_str}'",
        )


def _assert_approval_tenant_access(approval, current_user: User) -> None:
    """Enforces both demo-vs-production isolation AND per-session isolation across concurrent demo visitors."""
    if bool(approval.is_demo) != bool(current_user.is_demo):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Cross-environment approval access is forbidden.",
        )
    if current_user.is_demo and approval.demo_session_id != current_user.demo_session_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Cross-session demo approval access is forbidden.",
        )


@router.get(
    "/my",
    response_model=List[ApprovalRequestResponse],
    summary="List current user's submitted requests",
)
def list_my_requests(
    status_filter: Optional[ApprovalStatus] = Query(None, alias="status", description="Filter by status (PENDING, APPROVED, REJECTED)"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=200),
    current_user: User = Depends(require_roles([UserRole.OPERATOR, UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """Retrieves approval requests requested specifically by the authenticated user (sanitized for Operators, demo-session isolated)."""
    records = approval_service.list_approvals(
        db,
        status_filter=status_filter,
        requested_by_user_id=current_user.id,
        is_demo=bool(current_user.is_demo),
        demo_session_id=current_user.demo_session_id,
        skip=skip,
        limit=limit,
    )
    return [_serialize_approval(r, current_user.role) for r in records]


@router.get(
    "",
    response_model=List[ApprovalRequestResponse],
    summary="List approvals (Approver or Admin only)",
)
def list_approvals(
    status_filter: Optional[ApprovalStatus] = Query(None, alias="status", description="Filter by status; defaults to PENDING if omitted"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=200),
    current_user: User = Depends(require_roles([UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """Retrieves approval requests scoped strictly by tenant and demo session."""
    target_status = status_filter if status_filter is not None else ApprovalStatus.PENDING
    return approval_service.list_approvals(
        db,
        status_filter=target_status,
        is_demo=bool(current_user.is_demo),
        demo_session_id=current_user.demo_session_id,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/{id}",
    response_model=ApprovalRequestResponse,
    summary="Get approval request details",
)
def get_approval(
    id: str,
    current_user: User = Depends(require_roles([UserRole.OPERATOR, UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """Retrieves details of an approval request by UUID (tenant, session isolation & ownership enforced)."""
    _validate_uuid(id)
    approval = approval_service.get_approval_by_id(db, id)
    if not approval:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval request not found.")

    _assert_approval_tenant_access(approval, current_user)

    # IDOR Protection: Operators can only inspect their own requests
    if current_user.role == UserRole.OPERATOR and approval.requested_by_user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You can only view your own approval requests.",
        )
    return _serialize_approval(approval, current_user.role)


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
    Approves a pending sensitive operation and triggers execution against the external API (or demo sandbox).
    - Restricted to APPROVER and real ADMIN roles (Demo Admin is read-only).
    - Anti-Self-Approval: Cannot approve an action you requested.
    - Hard Tenant & Session Isolation: Demo Approvers can only approve requests inside their own demo_session_id.
    - Frozen payload execution: executes strictly from DB record.
    """
    if current_user.is_demo and current_user.role == UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Approval execution is disabled for Demo Admin. Switch to Approver Demo to decide requests.",
        )
    _validate_uuid(id)
    target = approval_service.get_approval_by_id(db, id)
    if target:
        _assert_approval_tenant_access(target, current_user)
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
    body: RejectionRequest = Body(...),
    current_user: User = Depends(require_roles([UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """Rejects a pending sensitive operation (Approver or real Admin only). Requires a validated rejection reason."""
    if current_user.is_demo and current_user.role == UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Approval rejection is disabled for Demo Admin. Switch to Approver Demo to decide requests.",
        )
    _validate_uuid(id)
    target = approval_service.get_approval_by_id(db, id)
    if target:
        _assert_approval_tenant_access(target, current_user)
    try:
        appr, _ = await approval_service.process_approval_decision(
            db=db,
            approval_id=id,
            decision=ApprovalStatus.REJECTED,
            decided_by_user_id=current_user.id,
            rejection_reason=body.reason,
        )
        return ApprovalActionResult(
            approval=ApprovalRequestResponse.model_validate(appr),
            execution=None,
            message="Operation rejected.",
        )
    except approval_service.ApprovalNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except approval_service.InvalidApprovalStateError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except approval_service.InvalidRejectionReasonError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
