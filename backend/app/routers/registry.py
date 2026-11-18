"""
app/routers/registry.py

FastAPI router for API Registration endpoints.

Security & RBAC:
- Read endpoints (GET /apis): Restricted to APPROVER, ADMIN only.
- GET /apis/tools: Sanitized summary for OPERATOR (name + description only, no credentials or endpoints).
- Mutation endpoints (POST, PUT, DELETE): Restricted strictly to ADMIN.
"""

import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.database import get_db
from app.models.enums import UserRole
from app.models.user import User
from app.dependencies.auth import require_roles
from app.schemas.api_registry import (
    APIRegistryCreate,
    APIRegistryUpdate,
    APIRegistryResponse,
)
from app.services import registry_service

router = APIRouter()


class APIToolSummary(BaseModel):
    """Sanitized API summary for OPERATOR — exposes only display metadata, no credentials or internal endpoints."""
    id: str
    name: str
    description: Optional[str] = None


def _validate_uuid(id_str: str) -> str:
    """Validates that a path parameter string is a valid UUIDv4."""
    try:
        uuid.UUID(id_str)
        return id_str
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid UUID identifier: '{id_str}'",
        )


@router.post(
    "",
    response_model=APIRegistryResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new external API (Admin only)",
)
def register_api(
    api_in: APIRegistryCreate,
    current_user: User = Depends(require_roles([UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """
    Registers a new external API specification for AI orchestration.
    - Restricted to real ADMIN role (disabled in Recruiter Demo Mode).
    - Validates base URL against SSRF attack vectors.
    - Encrypts credentials at rest before storage.
    - Returns registered API info with credentials masked.
    """
    if current_user.is_demo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registering external APIs is disabled in Recruiter Demo Mode.",
        )
    try:
        return registry_service.create_api(db, api_in)
    except registry_service.DuplicateAPINameError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )


@router.get(
    "/tools",
    response_model=List[APIToolSummary],
    summary="List available API tools (sanitized, Operator view)",
)
def list_api_tools(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=200),
    current_user: User = Depends(require_roles([UserRole.OPERATOR, UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """
    Returns a sanitized list of available APIs for OPERATOR role.
    Does NOT expose base_url, endpoint paths, HTTP methods, or authentication headers.
    """
    apis = registry_service.list_apis(
        db,
        skip=skip,
        limit=limit,
        is_demo=bool(current_user.is_demo),
        demo_session_id=current_user.demo_session_id,
    )
    return [APIToolSummary(id=a.id, name=a.name, description=a.description) for a in apis]


@router.get(
    "",
    response_model=List[APIRegistryResponse],
    summary="List registered APIs (Approver / Admin only)",
)
def list_apis(
    skip: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=200, description="Items per page"),
    current_user: User = Depends(require_roles([UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """Lists registered APIs scoped strictly by tenant and demo session, with credentials omitted."""
    return registry_service.list_apis(
        db,
        skip=skip,
        limit=limit,
        is_demo=bool(current_user.is_demo),
        demo_session_id=current_user.demo_session_id,
    )


@router.get(
    "/{id}",
    response_model=APIRegistryResponse,
    summary="Get registered API details (Approver / Admin only)",
)
def get_api(
    id: str,
    current_user: User = Depends(require_roles([UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """Retrieves metadata and endpoints for a specific API by UUID (tenant & session isolated)."""
    _validate_uuid(id)
    api = registry_service.get_api_by_id(db, id)
    if not api:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API with ID '{id}' was not found.",
        )
    if bool(api.is_demo) != bool(current_user.is_demo) or (
        current_user.is_demo and api.demo_session_id != current_user.demo_session_id
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Cross-environment or cross-session API access is forbidden.",
        )
    return api


@router.put(
    "/{id}",
    response_model=APIRegistryResponse,
    summary="Update registered API (Admin only)",
)
def update_api(
    id: str,
    api_update: APIRegistryUpdate,
    current_user: User = Depends(require_roles([UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """Updates configuration or endpoints of a registered API (real Admin only)."""
    if current_user.is_demo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Modifying APIs is disabled in Recruiter Demo Mode.",
        )
    _validate_uuid(id)
    existing = registry_service.get_api_by_id(db, id)
    if existing and bool(existing.is_demo):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot modify isolated demo API records.",
        )
    try:
        return registry_service.update_api(db, id, api_update)
    except registry_service.APINotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except registry_service.DuplicateAPINameError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )


@router.delete(
    "/{id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a registered API (Admin only)",
)
def delete_api(
    id: str,
    current_user: User = Depends(require_roles([UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """
    Deletes a registered API and cascades deletion to linked logs and approvals (real Admin only).
    """
    if current_user.is_demo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Deleting APIs is disabled in Recruiter Demo Mode.",
        )
    _validate_uuid(id)
    existing = registry_service.get_api_by_id(db, id)
    if existing and bool(existing.is_demo):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot delete isolated demo API records.",
        )
    deleted = registry_service.delete_api(db, id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API with ID '{id}' was not found.",
        )
    return None
