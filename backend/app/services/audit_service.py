"""
app/services/audit_service.py

Audit Logging and Secure Replay Service.

Responsibilities:
1. Query execution audit logs with filtering and pagination.
2. Securely replay previous operations:
   - Preserves original logs (immutable).
   - Verifies target API still exists.
   - Enforces safety classification: replaying a SENSITIVE action creates a new
     ApprovalRequest (preventing replay attacks from bypassing approval guardrails).
   - Re-runs DNS checks and socket safety prior to replay execution.
"""

from typing import List, Optional, Tuple, Dict, Any
from sqlalchemy.orm import Session

from app.models.execution_log import ExecutionLog
from app.models.api_registry import APIRegistry
from app.models.enums import ExecutionStatus, ApprovalStatus
from app.models.approval_request import ApprovalRequest
from app.services.classifier import classify_action
from app.services.approval_service import create_approval_request
from app.services.executor import execute_api_call


class LogNotFoundError(Exception):
    """Raised when an execution log UUID is not found."""
    pass


class TargetAPINotFoundError(Exception):
    """Raised when replaying an operation whose target API was deleted."""
    pass


def list_execution_logs(
    db: Session,
    api_id: Optional[str] = None,
    status_filter: Optional[ExecutionStatus] = None,
    executed_by_user_id: Optional[str] = None,
    only_approvals: bool = False,
    skip: int = 0,
    limit: int = 100,
) -> List[ExecutionLog]:
    """Retrieves paginated audit logs with optional filtering (supports tenancy & approval relevance)."""
    query = db.query(ExecutionLog)
    if api_id:
        query = query.filter(ExecutionLog.api_registry_id == api_id)
    if status_filter:
        query = query.filter(ExecutionLog.status == status_filter)
    if executed_by_user_id:
        query = query.filter(ExecutionLog.executed_by_user_id == executed_by_user_id)
    if only_approvals:
        query = query.filter(ExecutionLog.approval_request_id.isnot(None))

    return query.order_by(ExecutionLog.executed_at.desc()).offset(skip).limit(limit).all()


def get_execution_log_by_id(db: Session, log_id: str) -> Optional[ExecutionLog]:
    """Retrieves a single execution log entry by UUID."""
    return db.query(ExecutionLog).filter(ExecutionLog.id == log_id).first()


async def replay_execution(
    db: Session,
    log_id: str,
    user_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Replays a previously executed operation.
    
    Security Controls:
    1. Immutability: Original execution log is NEVER modified.
    2. Target Existence: Checks if the destination API still exists.
    3. Replay Attack Prevention: If the replayed action is SENSITIVE, it cannot
       auto-execute; it is routed to the human approval queue.
    4. Safe Replays: If the action is SAFE, it re-verifies DNS and executes,
       generating a fresh ExecutionLog.
    """
    original_log = get_execution_log_by_id(db, log_id)
    if not original_log:
        raise LogNotFoundError(f"Execution log '{log_id}' not found.")

    api = db.query(APIRegistry).filter(APIRegistry.id == original_log.api_registry_id).first()
    if not api:
        raise TargetAPINotFoundError("Cannot replay: Target API has been deleted from the registry.")

    # 1. Safety Classification on the replayed operation
    is_sensitive, reason = classify_action(
        http_method=original_log.http_method,
        endpoint_path=original_log.endpoint_path,
        api_is_sensitive=bool(api.is_sensitive),
    )

    # 2. If SENSITIVE: Route to human approval (prevents replay backdoor)
    if is_sensitive:
        approval = create_approval_request(
            db=db,
            api_id=api.id,
            endpoint_path=original_log.endpoint_path,
            http_method=original_log.http_method,
            request_payload=original_log.request_payload,
            classification_reason=f"Replay Request: {reason}",
            requested_by_user_id=user_id,
        )
        return {
            "status": "AWAITING_APPROVAL",
            "is_sensitive": True,
            "original_log_id": original_log.id,
            "approval_id": approval.id,
            "message": "Replay operation is SENSITIVE. Human approval required before re-executing.",
        }

    # 3. If SAFE: Re-execute directly with DNS verification
    new_log = await execute_api_call(
        db=db,
        api=api,
        endpoint_path=original_log.endpoint_path,
        http_method=original_log.http_method,
        payload=original_log.request_payload,
        approval_request_id=None,
        executed_by_user_id=user_id,
    )

    return {
        "status": "REPLAYED",
        "is_sensitive": False,
        "original_log_id": original_log.id,
        "new_log_id": new_log.id,
        "execution_status": new_log.status.value,
        "response_status_code": new_log.response_status_code,
        "response_body": new_log.response_body,
        "message": "Safe operation successfully replayed.",
    }
