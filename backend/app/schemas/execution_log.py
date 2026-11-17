"""
app/schemas/execution_log.py

Pydantic schemas for Execution Logs.

Security guarantees:
- Immutability: Execution logs cannot be modified via API, only appended.
- Traceability: Logs clearly link to original approval requests (if sensitive) or record direct execution.
- Large payload handling: Responses are validated and safe for storage and serialization.
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Dict, Any, Optional
from datetime import datetime
from app.models.enums import ExecutionStatus


class ExecutionLogCreate(BaseModel):
    api_registry_id: str
    approval_request_id: Optional[str] = None
    endpoint_path: str
    http_method: str
    request_payload: Dict[str, Any] = Field(default_factory=dict)
    response_body: Optional[Any] = None
    response_status_code: Optional[int] = None
    status: ExecutionStatus
    error_message: Optional[str] = None
    duration_ms: Optional[float] = None


class ExecutionLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    api_registry_id: str
    approval_request_id: Optional[str] = None
    executed_by_user_id: Optional[str] = None
    executed_by_username: Optional[str] = None
    endpoint_path: str
    http_method: str
    request_payload: Dict[str, Any]
    response_body: Optional[Any] = None
    response_status_code: Optional[int] = None
    status: ExecutionStatus
    error_message: Optional[str] = None
    duration_ms: Optional[float] = None
    executed_at: datetime


class ReplayResponse(BaseModel):
    original_log_id: str
    new_log_id: str
    status: ExecutionStatus
    http_status_code: Optional[int] = None
    message: str
