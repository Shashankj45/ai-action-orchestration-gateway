"""
app/services/tool_builder.py

Converts registered external APIs and their endpoints into standard
OpenAI/Gemini function calling tool definitions.

Security controls:
- Sanitizes function names to match standard regex ^[a-zA-Z0-9_]{1,64}$.
- Generates strict parameter schemas (properties + required fields).
- Maintains a bidirectional lookup map: tool_name -> (api_id, method, path, parameter_specs)
  to ensure LLM tool calls can only resolve to explicitly registered endpoints.
"""

import re
from typing import List, Dict, Any, Tuple, Optional
from app.models.api_registry import APIRegistry


def sanitize_name(text: str) -> str:
    """Replaces non-alphanumeric characters with underscores and limits length to 64."""
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", text)
    # Deduplicate consecutive underscores
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    return cleaned[:64]


def generate_tool_name(api_name: str, method: str, path: str) -> str:
    """
    Generates a unique, deterministic tool name:
    Example: 'Stripe API', 'POST', '/v1/charges' -> 'stripe_api__post__v1_charges'
    """
    clean_api = sanitize_name(api_name.lower())
    clean_method = method.strip().lower()
    clean_path = sanitize_name(path.strip("/").replace("/", "_").lower())
    full_name = f"{clean_api}__{clean_method}__{clean_path}"
    return full_name[:64]


class ToolRegistry:
    """
    Holds generated tool definitions for the LLM and the lookup mapping
    to translate an LLM function call back to its verified API endpoint.
    """

    def __init__(self):
        self.tools: List[Dict[str, Any]] = []
        # Maps tool_name -> dict(api_id, api_name, endpoint_path, http_method, parameter_specs)
        self._lookup: Dict[str, Dict[str, Any]] = {}

    def add_api(self, api: APIRegistry) -> None:
        """Parses an APIRegistry model and registers all its endpoints as tools."""
        endpoints = api.endpoints or []

        for ep in endpoints:
            path = ep.get("path")
            method = ep.get("method", "GET").upper()
            description = ep.get("description") or f"{method} {path} on {api.name}"
            raw_params = ep.get("parameters") or {}

            tool_name = generate_tool_name(api.name, method, path)

            # Build JSON Schema properties
            properties: Dict[str, Any] = {}
            required_fields: List[str] = []

            for param_name, param_meta in raw_params.items():
                p_type = param_meta.get("type", "string").lower()
                # Normalize types to JSON Schema types
                if p_type in ("int", "integer"):
                    schema_type = "integer"
                elif p_type in ("float", "number"):
                    schema_type = "number"
                elif p_type in ("bool", "boolean"):
                    schema_type = "boolean"
                elif p_type in ("list", "array"):
                    schema_type = "array"
                elif p_type in ("dict", "object"):
                    schema_type = "object"
                else:
                    schema_type = "string"

                prop_def: Dict[str, Any] = {"type": schema_type}
                if param_meta.get("description"):
                    prop_def["description"] = param_meta["description"]
                if param_meta.get("default") is not None:
                    prop_def["default"] = param_meta["default"]

                properties[param_name] = prop_def

                if param_meta.get("required", False):
                    required_fields.append(param_name)

            tool_def = {
                "type": "function",
                "function": {
                    "name": tool_name,
                    "description": description[:1024],
                    "parameters": {
                        "type": "object",
                        "properties": properties,
                        "required": required_fields,
                        "additionalProperties": False,  # Strict schema enforcement
                    },
                },
            }

            self.tools.append(tool_def)
            self._lookup[tool_name] = {
                "api_id": api.id,
                "api_name": api.name,
                "endpoint_path": path,
                "http_method": method,
                "is_sensitive": api.is_sensitive,
                "parameter_specs": raw_params,
            }

    def get_tool_metadata(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """O(1) lookup of endpoint metadata from tool name."""
        return self._lookup.get(tool_name)

    def is_valid_tool(self, tool_name: str) -> bool:
        return tool_name in self._lookup


def build_tools_from_apis(apis: List[APIRegistry]) -> ToolRegistry:
    """Factory function: Builds ToolRegistry from a list of registered APIs."""
    registry = ToolRegistry()
    for api in apis:
        registry.add_api(api)
    return registry
