"""
app/services/registry_service.py

Business logic for the API Registry.

Handles creation, retrieval, updates, and deletion of registered external APIs.
Enforces unique constraints and domain error handling.
"""

from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.models.api_registry import APIRegistry
from app.schemas.api_registry import APIRegistryCreate, APIRegistryUpdate


class DuplicateAPINameError(Exception):
    """Raised when an API with the given name already exists."""
    pass


class APINotFoundError(Exception):
    """Raised when an API is not found by ID."""
    pass


def create_api(db: Session, data: APIRegistryCreate) -> APIRegistry:
    """
    Registers a new external API.
    Raises DuplicateAPINameError if an API with the same name exists.
    """
    existing = db.query(APIRegistry).filter(APIRegistry.name == data.name).first()
    if existing:
        raise DuplicateAPINameError(f"API with name '{data.name}' already exists.")

    api_record = APIRegistry(
        name=data.name,
        base_url=data.base_url,
        description=data.description,
        auth_header_name=data.auth_header_name,
        auth_header_value=data.auth_header_value,
        is_sensitive=data.is_sensitive,
        endpoints=[ep.model_dump() for ep in data.endpoints],
    )
    db.add(api_record)
    try:
        db.commit()
        db.refresh(api_record)
        return api_record
    except IntegrityError as exc:
        db.rollback()
        raise DuplicateAPINameError(f"API with name '{data.name}' already exists.") from exc


def list_apis(db: Session, skip: int = 0, limit: int = 100) -> List[APIRegistry]:
    """Retrieves paginated list of registered APIs."""
    return db.query(APIRegistry).order_by(APIRegistry.created_at.desc()).offset(skip).limit(limit).all()


def get_api_by_id(db: Session, api_id: str) -> Optional[APIRegistry]:
    """Retrieves a single API by its UUID."""
    return db.query(APIRegistry).filter(APIRegistry.id == api_id).first()


def get_api_by_name(db: Session, name: str) -> Optional[APIRegistry]:
    """Retrieves a single API by its unique name."""
    return db.query(APIRegistry).filter(APIRegistry.name == name).first()


def update_api(db: Session, api_id: str, data: APIRegistryUpdate) -> APIRegistry:
    """
    Updates an existing API.
    Raises APINotFoundError if not found.
    Raises DuplicateAPINameError if renamed to an already existing name.
    """
    api_record = get_api_by_id(db, api_id)
    if not api_record:
        raise APINotFoundError(f"API with ID '{api_id}' not found.")

    update_dict = data.model_dump(exclude_unset=True)

    if "name" in update_dict and update_dict["name"] != api_record.name:
        existing = db.query(APIRegistry).filter(APIRegistry.name == update_dict["name"]).first()
        if existing:
            raise DuplicateAPINameError(f"API with name '{update_dict['name']}' already exists.")

    if "endpoints" in update_dict and update_dict["endpoints"] is not None:
        update_dict["endpoints"] = [
            ep.model_dump() if hasattr(ep, "model_dump") else ep for ep in data.endpoints
        ]

    for field, value in update_dict.items():
        setattr(api_record, field, value)

    try:
        db.commit()
        db.refresh(api_record)
        return api_record
    except IntegrityError as exc:
        db.rollback()
        raise DuplicateAPINameError(f"API with name '{update_dict.get('name')}' already exists.") from exc


def delete_api(db: Session, api_id: str) -> bool:
    """
    Deletes a registered API by UUID.
    Cascades to delete linked approval requests and execution logs.
    Returns True if deleted, False if not found.
    """
    api_record = get_api_by_id(db, api_id)
    if not api_record:
        return False
    db.delete(api_record)
    db.commit()
    return True
