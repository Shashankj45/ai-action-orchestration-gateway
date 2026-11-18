"""
app/schemas/tasks.py

Pydantic schemas for natural-language task requests and execution outcomes.
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Dict, Any, Optional


class TaskRequest(BaseModel):
    task: str = Field(
        ...,
        min_length=3,
        max_length=2000,
        description="Natural language instruction for the AI assistant",
        examples=["Send $50 to Alice via Stripe", "Get weather for Tokyo"],
    )


class TaskExecutionResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    status: str = Field(
        ...,
        description="Outcome: EXECUTED_SAFE, AWAITING_APPROVAL, NO_TOOLS, NO_TOOL_SELECTED, VALIDATION_FAILED, ERROR"
    )
    api_id: Optional[str] = None
    api_name: Optional[str] = None
    endpoint_path: Optional[str] = None
    http_method: Optional[str] = None
    is_sensitive: Optional[bool] = None
    request_payload: Optional[Dict[str, Any]] = None

    # Sensitive / Approval fields
    approval_id: Optional[str] = Field(None, description="UUID of created approval request if SENSITIVE")
    classification_reason: Optional[str] = Field(None, description="Why this action was deemed SAFE or SENSITIVE")

    # Safe execution fields
    execution_log_id: Optional[str] = Field(None, description="UUID of execution log if auto-executed")
    execution_status: Optional[str] = None
    response_status_code: Optional[int] = None
    response_body: Optional[Any] = None
    result_data: Optional[Any] = Field(None, description="Sanitized structured result data safe for user display")
    is_demo_result: Optional[bool] = Field(None, description="Indicates result came from isolated demo fixture")
    duration_ms: Optional[float] = None

    message: Optional[str] = None


# Alias for backward-compatibility with Phase 4 orchestrator
ActionPlanResponse = TaskExecutionResult
