"""
app/services/classifier.py

Deterministic Safety Classifier.

Classifies AI-generated API operations as SAFE or SENSITIVE.

Rules:
SENSITIVE if ANY of:
1. The registered API has is_sensitive=True (administrative override).
2. The HTTP method is state-mutating or destructive (POST, PUT, PATCH, DELETE).
3. The endpoint path contains sensitive or financial keywords:
   /delete, /remove, /transfer, /pay, /send, /update, /cancel, /terminate, /drop, /charge

SAFE if:
1. The HTTP method is GET.
2. AND none of the sensitive keywords match.
3. AND the API is not tagged sensitive.
"""

from typing import Tuple

SENSITIVE_HTTP_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

SENSITIVE_PATH_KEYWORDS = (
    "delete",
    "remove",
    "transfer",
    "pay",
    "send",
    "update",
    "cancel",
    "terminate",
    "drop",
    "charge",
    "modify",
    "auth",
    "login",
    "grant",
    "revoke",
)


def classify_action(
    http_method: str,
    endpoint_path: str,
    api_is_sensitive: bool = False,
) -> Tuple[bool, str]:
    """
    Classifies an operation.
    Returns: (is_sensitive: bool, reason: str)
    """
    method_upper = http_method.strip().upper()
    path_lower = endpoint_path.strip().lower()

    # Rule 1: Administrative override on the API
    if api_is_sensitive:
        return True, "Operation is SENSITIVE: API is explicitly flagged as sensitive by administrator."

    # Rule 2: State-changing HTTP verbs
    if method_upper in SENSITIVE_HTTP_METHODS:
        return True, f"Operation is SENSITIVE: HTTP method '{method_upper}' is a state-changing or destructive operation."

    # Rule 3: Sensitive path keywords
    # Split path segments and clean punctuation
    path_segments = [seg for seg in path_lower.replace("-", "_").split("/") if seg]
    for seg in path_segments:
        for kw in SENSITIVE_PATH_KEYWORDS:
            if kw in seg:
                return True, f"Operation is SENSITIVE: Endpoint path contains sensitive keyword '{kw}'."

    # Rule 4: Method must be GET to be SAFE
    if method_upper == "GET":
        return False, "Read-only GET query with no sensitive operation keywords."

    # Default to sensitive for unknown/uncommon HTTP methods (fail-closed)
    return True, f"HTTP method '{method_upper}' is unclassified and defaults to SENSITIVE."
