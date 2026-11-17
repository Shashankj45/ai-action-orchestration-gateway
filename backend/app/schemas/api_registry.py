"""
app/schemas/api_registry.py

Pydantic schemas for the API Registry.

Security guarantees:
- Base URL is strictly validated against SSRF attacks (no internal/loopback/cloud metadata).
- auth_header_value is NEVER returned in response models (preventing token leakage).
- Endpoint paths must start with '/' and methods must be standard HTTP verbs.
"""

from pydantic import BaseModel, Field, field_validator, model_validator, ConfigDict
from typing import List, Dict, Any, Optional
from datetime import datetime
from app.utils.security import validate_safe_url

VALID_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}


class ParameterDefinition(BaseModel):
    """Schema for individual parameter requirements."""
    type: str = Field(..., description="Data type: string, integer, number, boolean, object, array")
    description: Optional[str] = Field(None, description="Explanation of parameter purpose")
    required: bool = Field(default=False, description="Whether parameter is mandatory")
    default: Optional[Any] = Field(None, description="Default value if not provided")


class EndpointDefinition(BaseModel):
    """Schema defining an individual API endpoint exposed to the LLM."""
    path: str = Field(..., description="Relative path, e.g. /v1/customers")
    method: str = Field(..., description="HTTP Method: GET, POST, PUT, PATCH, DELETE")
    description: Optional[str] = Field(None, description="Human/LLM description of what endpoint does")
    parameters: Dict[str, ParameterDefinition] = Field(
        default_factory=dict,
        description="Dictionary mapping parameter name to parameter definition"
    )

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith("/"):
            raise ValueError("Endpoint path must start with '/'")
        return v

    @field_validator("method")
    @classmethod
    def validate_method(cls, v: str) -> str:
        method_upper = v.strip().upper()
        if method_upper not in VALID_HTTP_METHODS:
            raise ValueError(f"HTTP method must be one of: {', '.join(sorted(VALID_HTTP_METHODS))}")
        return method_upper


class APIRegistryBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100, description="Unique API identifier")
    base_url: str = Field(..., description="Root URL of the external API")
    description: Optional[str] = Field(None, description="API overview")
    auth_header_name: Optional[str] = Field(None, max_length=100, description="e.g. Authorization or X-API-Key")
    is_sensitive: bool = Field(default=False, description="If true, ALL actions require human approval")
    endpoints: List[EndpointDefinition] = Field(default_factory=list, description="Registered endpoints")

    @field_validator("base_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        return validate_safe_url(v)


class APIRegistryCreate(APIRegistryBase):
    """Payload accepted when registering a new API. Contains sensitive auth token."""
    auth_header_value: Optional[str] = Field(
        None,
        description="Auth secret or API key. Stored securely and never returned in API responses."
    )


class APIRegistryUpdate(BaseModel):
    """Payload for updating an existing registered API."""
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    base_url: Optional[str] = None
    description: Optional[str] = None
    auth_header_name: Optional[str] = None
    auth_header_value: Optional[str] = None
    is_sensitive: Optional[bool] = None
    endpoints: Optional[List[EndpointDefinition]] = None

    @field_validator("base_url")
    @classmethod
    def validate_url(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return validate_safe_url(v)
        return v


class APIRegistryResponse(BaseModel):
    """
    Public response model for registered APIs.
    SECURITY CONTROL: auth_header_value is deliberately omitted to prevent credential theft.
    """
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    base_url: str
    description: Optional[str] = None
    auth_header_name: Optional[str] = None
    has_auth: bool = Field(default=False, description="Indicates if credentials are saved without exposing them")
    is_sensitive: bool
    endpoints: List[EndpointDefinition]
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="before")
    @classmethod
    def compute_has_auth(cls, data: Any) -> Any:
        if isinstance(data, dict):
            auth_val = data.get("auth_header_value")
            data["has_auth"] = bool(auth_val)
        elif hasattr(data, "auth_header_value"):
            # SQLAlchemy model instance
            has_auth = bool(getattr(data, "auth_header_value", None))
            # If reading from ORM object, inject has_auth attribute
            setattr(data, "has_auth", has_auth)
        return data
