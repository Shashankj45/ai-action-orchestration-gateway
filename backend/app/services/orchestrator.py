"""
app/services/orchestrator.py

Orchestrator Service:
Sits between the user, database, and LLM to parse natural-language instructions
into validated, secure action plans.

Security flow:
1. Fetch registered APIs.
2. Build tool definitions with strictly constrained parameter schemas.
3. Call LLM with security-focused system prompt.
4. Verify tool call matches an explicitly registered endpoint.
5. Validate LLM-generated arguments against parameter specs.
6. Return structured ActionPlan (ready for classification in Phase 5).
"""

import logging
from typing import Optional
from sqlalchemy.orm import Session

from app.models.api_registry import APIRegistry
from app.services.tool_builder import build_tools_from_apis
from app.services.validator import validate_arguments, ParameterValidationError
from app.schemas.tasks import ActionPlanResponse
from app.utils.llm_client import LLMClient, default_llm_client, LLMError

logger = logging.getLogger("gateway.orchestrator")


async def orchestrate_task(
    db: Session,
    user_task: str,
    llm_client: Optional[LLMClient] = None,
    is_demo: bool = False,
    demo_session_id: Optional[str] = None,
) -> ActionPlanResponse:
    """
    Coordinates tool compilation, LLM querying, and parameter validation.
    Demo tasks are strictly isolated to the caller's demo_session_id APIs and deterministic mock matching.
    """
    if is_demo:
        client = LLMClient(provider="mock", api_key="mock")
    else:
        client = llm_client or default_llm_client

    # 1. Fetch registered APIs strictly scoped to demo session vs real tenant
    query = db.query(APIRegistry).filter(APIRegistry.is_demo == bool(is_demo))
    if is_demo:
        query = query.filter(APIRegistry.demo_session_id == demo_session_id)
    apis = query.all()
    if not apis:
        return ActionPlanResponse(
            status="NO_TOOLS",
            message="No external APIs have been registered yet. Register an API first.",
        )

    # 2. Build Tool Registry
    tool_registry = build_tools_from_apis(apis)
    if not tool_registry.tools:
        return ActionPlanResponse(
            status="NO_TOOLS",
            message="Registered APIs do not expose any endpoints.",
        )

    # 3. Query LLM
    try:
        llm_response = await client.call(user_task, tool_registry.tools)
    except LLMError as exc:
        logger.error("LLM call failed: %s", exc)
        return ActionPlanResponse(
            status="ERROR",
            message=f"LLM communication failed: {exc}",
        )

    # 4. Handle text-only response (no tool chosen)
    if not llm_response.has_tool_call:
        return ActionPlanResponse(
            status="NO_TOOL_SELECTED",
            message=llm_response.text_content or "No appropriate tool was matched for this task.",
        )

    # 5. Security Check: Validate tool exists in our registry
    tool_name = llm_response.tool_name
    metadata = tool_registry.get_tool_metadata(tool_name)
    if not metadata:
        logger.warning("LLM hallucinated unregistered tool: %s", tool_name)
        return ActionPlanResponse(
            status="INVALID_TOOL",
            message=f"Security Refusal: The LLM attempted to call an unregistered tool '{tool_name}'.",
        )

    # 6. Security Check: Parameter validation
    try:
        validated_args = validate_arguments(
            metadata["parameter_specs"],
            llm_response.arguments,
        )
    except ParameterValidationError as exc:
        logger.warning("Parameter validation failed for %s: %s", tool_name, exc)
        return ActionPlanResponse(
            status="VALIDATION_FAILED",
            api_id=metadata["api_id"],
            api_name=metadata["api_name"],
            endpoint_path=metadata["endpoint_path"],
            http_method=metadata["http_method"],
            message=f"Parameter validation failed: {exc}",
        )

    # 7. Success: Return verified ActionPlan
    return ActionPlanResponse(
        status="PLAN_CREATED",
        api_id=metadata["api_id"],
        api_name=metadata["api_name"],
        endpoint_path=metadata["endpoint_path"],
        http_method=metadata["http_method"],
        is_sensitive=metadata["is_sensitive"],
        request_payload=validated_args,
        message=f"Successfully resolved task to {metadata['http_method']} {metadata['endpoint_path']} on {metadata['api_name']}",
    )
