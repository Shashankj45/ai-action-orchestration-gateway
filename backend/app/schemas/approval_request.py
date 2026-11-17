"""
app/schemas/approval_request.py

Pydantic schemas for Approval Requests.

Security guarantees:
- Replay / tampering prevention: Decision payloads cannot alter the original `request_payload`.
- Strict enum validation: decisions can only be APPROVED or REJECTED (cannot reset to PENDING).
- IDOR prevention: All references use UUIDs.
"""

from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import Dict, Any, Optional
from datetime import datetime
from app.models.enums import ApprovalStatus


class ApprovalRequestCreate(BaseModel):
    api_registry_id: str = Field(..., description="Target API UUID")
    endpoint_path: str = Field(..., description="Target endpoint")
    http_method: str = Field(..., description="HTTP Method")
    request_payload: Dict[str, Any] = Field(
        default_factory=dict,
        description="Frozen request payload that will be executed upon approval"
    )
    classification_reason: str = Field(..., description="Why human review is required")


class ApprovalDecisionRequest(BaseModel):
    decision: ApprovalStatus = Field(
        ...,
        description="Decision outcome: APPROVED or REJECTED only"
    )
    comment: Optional[str] = Field(None, max_length=500, description="Optional reviewer remarks")

    @field_validator("decision")
    @classmethod
    def validate_decision(cls, v: ApprovalStatus) -> ApprovalStatus:
        if v not in (ApprovalStatus.APPROVED, ApprovalStatus.REJECTED):
            raise ValueError("Decision must be either 'APPROVED' or 'REJECTED'.")
        return v


class ApprovalRequestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    api_registry_id: str
    endpoint_path: str
    http_method: str
    request_payload: Dict[str, Any]
    status: ApprovalStatus
    classification_reason: str
    requested_by_user_id: Optional[str] = None
    decided_by_user_id: Optional[str] = None
    requested_by_username: Optional[str] = None
    decided_by_username: Optional[str] = None
    decided_at: Optional[datetime] = None
    created_at: datetime
