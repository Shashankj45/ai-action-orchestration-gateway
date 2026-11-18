"""
app/utils/security.py

Zero-trust security utilities:
- SSRF prevention: Strict URL and host validation against private, loopback,
  link-local, cloud metadata, and internal network targets.
- Payload sanitation / truncation to prevent database bloat and memory exhaustion.
"""

import ipaddress
from urllib.parse import urlparse
from typing import Any, Dict, Optional

FORBIDDEN_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "metadata.google.internal",
    "instance-data",
}

CLOUD_METADATA_IPS = {
    "169.254.169.254",  # AWS, GCP, Azure, OpenStack metadata service
    "169.254.169.253",
}

FORBIDDEN_DOMAINS_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".home.arpa",
)


def validate_safe_url(url: str) -> str:
    """
    Validates that a URL does not point to internal, private, loopback,
    or cloud metadata endpoints (SSRF Defense).
    
    Raises ValueError if URL fails safety checks.
    """
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string.")

    parsed = urlparse(url.strip())

    # 1. Scheme check
    from app.config import settings
    if settings.is_production and parsed.scheme.lower() != "https":
        raise ValueError("Production Security: External APIs must use HTTPS in production environments.")
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(
            f"Invalid URL scheme '{parsed.scheme}'. Only 'http' and 'https' are allowed."
        )

    # 2. Reject credentials in URL (e.g., http://admin:pass@example.com)
    if parsed.username or parsed.password:
        raise ValueError("SSRF Protection: URLs containing embedded user credentials are not allowed.")

    # 3. Hostname check
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must contain a valid hostname.")

    hostname_lower = hostname.lower()

    # Exact forbidden hostnames
    if hostname_lower in FORBIDDEN_HOSTS or hostname_lower in CLOUD_METADATA_IPS:
        raise ValueError(f"SSRF Protection: Access to host '{hostname}' is strictly forbidden.")

    # Forbidden internal domain suffixes
    for suffix in FORBIDDEN_DOMAINS_SUFFIXES:
        if hostname_lower.endswith(suffix):
            raise ValueError(
                f"SSRF Protection: Access to internal domain '{hostname}' is strictly forbidden."
            )

    # 4. IP address validation (if hostname is an IP literal)
    try:
        ip = ipaddress.ip_address(hostname_lower)
        if ip.is_private:
            raise ValueError(f"SSRF Protection: Target IP {ip} is in a private network range.")
        if ip.is_loopback:
            raise ValueError(f"SSRF Protection: Target IP {ip} is a loopback address.")
        if ip.is_link_local:
            raise ValueError(f"SSRF Protection: Target IP {ip} is a link-local/cloud-metadata address.")
        if ip.is_multicast:
            raise ValueError(f"SSRF Protection: Target IP {ip} is a multicast address.")
        if ip.is_reserved:
            raise ValueError(f"SSRF Protection: Target IP {ip} is a reserved address.")
        if ip.is_unspecified:
            raise ValueError(f"SSRF Protection: Target IP {ip} is an unspecified address.")
    except ValueError as e:
        # Re-raise if it was our explicit security error
        if "SSRF Protection" in str(e):
            raise
        # Otherwise, hostname is a standard domain name (e.g., "api.stripe.com"), which is valid

    return url.strip()


def truncate_payload(data: Any, max_bytes: int = 50_000) -> Any:
    """
    Ensures response bodies or large payloads do not exceed maximum storage limits.
    Prevents database denial-of-service / memory exhaustion.
    """
    if data is None:
        return None
    try:
        import json
        serialized = json.dumps(data)
        if len(serialized.encode("utf-8")) > max_bytes:
            return {
                "_truncated": True,
                "_original_size_bytes": len(serialized.encode("utf-8")),
                "_message": f"Payload truncated to prevent storage bloat (exceeded {max_bytes} bytes).",
                "_preview": serialized[:1000] + "...",
            }
        return data
    except Exception:
        # If not JSON serializable, fallback to string representation
        str_val = str(data)
        if len(str_val.encode("utf-8")) > max_bytes:
            return {
                "_truncated": True,
                "_message": f"Payload truncated (exceeded {max_bytes} bytes).",
                "_preview": str_val[:1000] + "...",
            }
        return data


_SENSITIVE_RESULT_KEY_TOKENS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "auth_header",
    "credential",
    "private_key",
    "internal_",
    "stack_trace",
    "traceback",
    "raw_headers",
    "headers",
    "sql",
    "debug",
)

_HIDDEN_EXACT_RESULT_KEYS = {
    "sandbox",
    "_truncated",
    "_original_size_bytes",
    "_message",
    "_preview",
    "raw",
}


def _is_sensitive_result_key(key: str) -> bool:
    k = str(key).strip().lower()
    if not k or k in _HIDDEN_EXACT_RESULT_KEYS or k.startswith("_"):
        return True
    return any(tok in k for tok in _SENSITIVE_RESULT_KEY_TOKENS)


def sanitize_user_result_data(data: Any, _depth: int = 0) -> Optional[Any]:
    """
    Produces a clean, user-safe structured representation of an API response.
    - Strips internal, credential, header, debug, and infrastructure metadata keys recursively.
    - Never fabricates fields that were not returned by the API or demo fixture.
    - Returns None for empty/null responses so callers can render an explicit empty state.
    """
    if data is None or _depth > 3:
        return None

    if isinstance(data, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in data.items():
            if len(cleaned) >= 25:
                break
            if _is_sensitive_result_key(k):
                continue
            if isinstance(v, (dict, list)):
                nested = sanitize_user_result_data(v, _depth=_depth + 1)
                if nested is not None:
                    cleaned[str(k)] = nested
            elif v is not None and v != "":
                cleaned[str(k)] = v
        return cleaned if cleaned else None

    if isinstance(data, list):
        items = []
        for item in data[:20]:
            if isinstance(item, (dict, list)):
                nested = sanitize_user_result_data(item, _depth=_depth + 1)
                if nested is not None:
                    items.append(nested)
            elif item is not None and item != "":
                items.append(item)
        return items if items else None

    if isinstance(data, (str, int, float, bool)):
        if isinstance(data, str) and not data.strip():
            return None
        return {"value": data}

    return None
