"""
app/routers/registry.py

FastAPI router for API Registration endpoints.

Security & RBAC:
- Read endpoints (GET): Accessible to OPERATOR, APPROVER, ADMIN.
- Mutation endpoints (POST, PUT, DELETE): Restricted strictly to ADMIN.
"""

import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

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
    - Restricted to ADMIN role.
    - Validates base URL against SSRF attack vectors.
    - Encrypts credentials at rest before storage.
    - Returns registered API info with credentials masked.
    """
    try:
        return registry_service.create_api(db, api_in)
    except registry_service.DuplicateAPINameError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )


@router.get(
    "",
    response_model=List[APIRegistryResponse],
    summary="List registered APIs",
)
def list_apis(
    skip: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=200, description="Items per page"),
    current_user: User = Depends(require_roles([UserRole.OPERATOR, UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """Lists all registered APIs with credentials securely omitted."""
    return registry_service.list_apis(db, skip=skip, limit=limit)


@router.get(
    "/{id}",
    response_model=APIRegistryResponse,
    summary="Get registered API details",
)
def get_api(
    id: str,
    current_user: User = Depends(require_roles([UserRole.OPERATOR, UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
):
    """Retrieves metadata and endpoints for a specific API by UUID."""
    _validate_uuid(id)
    api = registry_service.get_api_by_id(db, id)
    if not api:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API with ID '{id}' was not found.",
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
    """Updates configuration or endpoints of a registered API (Admin only)."""
    _validate_uuid(id)
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
    Deletes a registered API and cascades deletion to linked logs and approvals (Admin only).
    """
    _validate_uuid(id)
    deleted = registry_service.delete_api(db, id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API with ID '{id}' was not found.",
        )
    return None
