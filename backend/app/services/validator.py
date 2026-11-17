"""
app/services/validator.py

Zero-trust validation service for AI-generated tool calls.

Security guarantees:
1. Rejects missing required parameters.
2. Enforces strict data types (guards against type confusion attacks).
3. Rejects unexpected/extra parameters (guards against mass-assignment / parameter injection).
4. Sanitizes string values to prevent path traversal (../) or null-byte injections.
"""

from typing import Dict, Any, Tuple, Optional, List


class ParameterValidationError(Exception):
    """Raised when AI-generated tool arguments fail schema validation."""
    pass


def validate_arguments(
    parameter_specs: Dict[str, Any],
    provided_args: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Validates provided arguments against registered parameter definitions.
    Returns cleaned, validated parameters or raises ParameterValidationError.
    """
    if not isinstance(provided_args, dict):
        raise ParameterValidationError("Arguments must be a valid JSON object/dictionary.")

    validated: Dict[str, Any] = {}
    errors: List[str] = []

    # 1. Check for unexpected/extra parameters (disallow mass assignment)
    unexpected = set(provided_args.keys()) - set(parameter_specs.keys())
    if unexpected:
        errors.append(f"Unexpected parameters not permitted by API specification: {sorted(unexpected)}")

    # 2. Validate declared parameters
    for param_name, spec in parameter_specs.items():
        is_required = spec.get("required", False)
        expected_type = spec.get("type", "string").lower()
        default_val = spec.get("default")

        if param_name not in provided_args:
            if is_required:
                errors.append(f"Missing required parameter: '{param_name}'")
            elif default_val is not None:
                validated[param_name] = default_val
            continue

        raw_val = provided_args[param_name]

        # Null check
        if raw_val is None:
            if is_required:
                errors.append(f"Parameter '{param_name}' cannot be null.")
            else:
                validated[param_name] = None
            continue

        # Strict type checking (note: bool is a subclass of int in Python, so check bool first!)
        if expected_type in ("bool", "boolean"):
            if not isinstance(raw_val, bool):
                errors.append(f"Parameter '{param_name}' must be a boolean, got {type(raw_val).__name__}.")
            else:
                validated[param_name] = raw_val

        elif expected_type in ("int", "integer"):
            if isinstance(raw_val, bool) or not isinstance(raw_val, int):
                errors.append(f"Parameter '{param_name}' must be an integer, got {type(raw_val).__name__}.")
            else:
                validated[param_name] = raw_val

        elif expected_type in ("float", "number"):
            if isinstance(raw_val, bool) or not isinstance(raw_val, (int, float)):
                errors.append(f"Parameter '{param_name}' must be a number, got {type(raw_val).__name__}.")
            else:
                validated[param_name] = raw_val

        elif expected_type in ("str", "string"):
            if not isinstance(raw_val, str):
                errors.append(f"Parameter '{param_name}' must be a string, got {type(raw_val).__name__}.")
            else:
                # Security: check for path traversal / null byte injections
                if "\x00" in raw_val:
                    errors.append(f"Parameter '{param_name}' contains null byte injection.")
                elif "../" in raw_val or "..\\" in raw_val:
                    errors.append(f"Parameter '{param_name}' contains illegal path traversal pattern.")
                else:
                    validated[param_name] = raw_val

        elif expected_type in ("list", "array"):
            if not isinstance(raw_val, list):
                errors.append(f"Parameter '{param_name}' must be an array/list, got {type(raw_val).__name__}.")
            else:
                validated[param_name] = raw_val

        elif expected_type in ("dict", "object"):
            if not isinstance(raw_val, dict):
                errors.append(f"Parameter '{param_name}' must be an object/dict, got {type(raw_val).__name__}.")
            else:
                validated[param_name] = raw_val

        else:
            # Fallback for generic types
            validated[param_name] = raw_val

    if errors:
        raise ParameterValidationError("; ".join(errors))

    return validated
