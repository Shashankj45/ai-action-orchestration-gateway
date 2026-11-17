"""
app/services/approval_service.py

Human-in-the-loop Approval Workflow Service.

Security guarantees:
1. Replay / Reuse Prevention: Once decided, an approval request cannot be
   decided again (raises InvalidApprovalStateError).
2. Parameter Tampering Prevention: The executed payload is read strictly from
   the frozen request_payload stored in the DB row at task submission time.
3. Traceability: ExecutionLog is linked directly to the ApprovalRequest ID
   and records requested_by_user_id and decided_by_user_id.
4. Four-Eyes Principle: Forbids self-approval when the approver is the same
   user who requested the sensitive operation.
"""

from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any
from sqlalchemy.orm import Session

from app.models.approval_request import ApprovalRequest
from app.models.api_registry import APIRegistry
from app.models.enums import ApprovalStatus
from app.models.execution_log import ExecutionLog
from app.services.executor import execute_api_call


class InvalidApprovalStateError(Exception):
    """Raised when attempting to decide an approval that is not in PENDING status."""
    pass


class ApprovalNotFoundError(Exception):
    """Raised when approval request UUID is not found."""
    pass


class SelfApprovalForbiddenError(Exception):
    """Raised when the user who requested a sensitive task attempts to approve it."""
    pass


def create_approval_request(
    db: Session,
    api_id: str,
    endpoint_path: str,
    http_method: str,
    request_payload: Dict[str, Any],
    classification_reason: str,
    requested_by_user_id: Optional[str] = None,
) -> ApprovalRequest:
    """
    Creates a new PENDING approval request.
    Payload is frozen at creation time.
    """
    approval = ApprovalRequest(
        api_registry_id=api_id,
        endpoint_path=endpoint_path,
        http_method=http_method.strip().upper(),
        request_payload=request_payload,
        status=ApprovalStatus.PENDING,
        classification_reason=classification_reason,
        requested_by_user_id=requested_by_user_id,
    )
    db.add(approval)
    db.commit()
    db.refresh(approval)
    return approval


def list_pending_approvals(db: Session, skip: int = 0, limit: int = 100) -> List[ApprovalRequest]:
    """Retrieves all pending approval requests."""
    return (
        db.query(ApprovalRequest)
        .filter(ApprovalRequest.status == ApprovalStatus.PENDING)
        .order_by(ApprovalRequest.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


def get_approval_by_id(db: Session, approval_id: str) -> Optional[ApprovalRequest]:
    """Retrieves an approval request by UUID."""
    return db.query(ApprovalRequest).filter(ApprovalRequest.id == approval_id).first()


async def process_approval_decision(
    db: Session,
    approval_id: str,
    decision: ApprovalStatus,
    comment: Optional[str] = None,
    decided_by_user_id: Optional[str] = None,
) -> Tuple[ApprovalRequest, Optional[ExecutionLog]]:
    """
    Processes human approval/rejection.
    If APPROVED: executes the frozen payload against the target external API.
    If REJECTED: transitions state to REJECTED.
    Raises InvalidApprovalStateError if request was already decided.
    Raises SelfApprovalForbiddenError if requested_by == decided_by.
    """
    approval = get_approval_by_id(db, approval_id)
    if not approval:
        raise ApprovalNotFoundError(f"Approval request '{approval_id}' was not found.")

    # 1. State machine guard: only PENDING requests can be decided
    if approval.status != ApprovalStatus.PENDING:
        raise InvalidApprovalStateError(
            f"Approval request '{approval_id}' is already {approval.status.value} and cannot be modified."
        )

    # 2. Four-Eyes Principle / Anti-Self-Approval Enforcement
    if (
        decision == ApprovalStatus.APPROVED
        and approval.requested_by_user_id
        and decided_by_user_id
        and approval.requested_by_user_id == decided_by_user_id
    ):
        raise SelfApprovalForbiddenError(
            "Security Policy Violation: Self-approval is forbidden. "
            "A different authorized approver or admin must approve this action."
        )

    now = datetime.now(timezone.utc)
    approval.decided_at = now
    approval.decided_by_user_id = decided_by_user_id

    # 3. Rejection handling
    if decision == ApprovalStatus.REJECTED:
        approval.status = ApprovalStatus.REJECTED
        db.commit()
        db.refresh(approval)
        return approval, None

    # 4. Approval handling: Execute frozen request
    approval.status = ApprovalStatus.APPROVED
    db.commit()
    db.refresh(approval)

    api = db.query(APIRegistry).filter(APIRegistry.id == approval.api_registry_id).first()
    if not api:
        raise ValueError("Target API registry entry has been deleted.")

    # Execute with frozen payload from the database row
    execution_log = await execute_api_call(
        db=db,
        api=api,
        endpoint_path=approval.endpoint_path,
        http_method=approval.http_method,
        payload=approval.request_payload,
        approval_request_id=approval.id,
        executed_by_user_id=decided_by_user_id,
    )

    return approval, execution_log
