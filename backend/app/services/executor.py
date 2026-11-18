"""
app/services/executor.py

External API Execution Engine.

Responsibilities:
1. Validates destination host against DNS Rebinding attacks.
2. Injects decrypted authentication headers.
3. Dispatches HTTP call via HTTPX AsyncClient.
4. Truncates response payload to protect DB storage.
5. Records immutable audit entry in ExecutionLog table.
"""

import time
import inspect
import logging
from typing import Dict, Any, Optional
from urllib.parse import urljoin
import httpx
import httpcore
from httpcore._backends.anyio import AnyIOBackend
from sqlalchemy.orm import Session

from app.config import settings
from app.models.api_registry import APIRegistry
from app.models.execution_log import ExecutionLog
from app.models.enums import ExecutionStatus
from app.utils.network import resolve_and_verify_host, DNSRebindingError
from app.utils.security import truncate_payload

logger = logging.getLogger("gateway.executor")


class PinnedNetworkBackend(AnyIOBackend):
    """
    Forces socket connections to bind exclusively to the pre-validated IP address,
    preventing Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks while
    preserving SNI (Server Name Indication) and TLS certificate verification.
    """
    def __init__(self, pinned_ip: str):
        super().__init__()
        self.pinned_ip = pinned_ip

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Optional[Any] = None,
    ):
        # Override remote host to connect directly to the verified pinned IP
        return await super().connect_tcp(
            self.pinned_ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


class PinnedHTTPTransport(httpx.AsyncHTTPTransport):
    """HTTPX Transport pinned directly to a pre-verified destination IP address."""
    def __init__(self, pinned_ip: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._pool = httpcore.AsyncConnectionPool(network_backend=PinnedNetworkBackend(pinned_ip))


async def execute_api_call(
    db: Session,
    api: APIRegistry,
    endpoint_path: str,
    http_method: str,
    payload: Dict[str, Any],
    approval_request_id: Optional[str] = None,
    executed_by_user_id: Optional[str] = None,
    is_demo_execution: bool = False,
    demo_session_id: Optional[str] = None,
) -> ExecutionLog:
    """
    Executes an external REST API request and records the result in execution_logs.
    Security guarantee: Demo APIs or demo executions NEVER perform DNS lookups
    or outbound network requests; they execute strictly in the in-process demo sandbox.
    """
    if bool(api.is_demo) or bool(is_demo_execution):
        from app.services.demo_service import simulate_demo_api_call
        return simulate_demo_api_call(
            db=db,
            api=api,
            endpoint_path=endpoint_path,
            http_method=http_method,
            payload=payload,
            approval_request_id=approval_request_id,
            executed_by_user_id=executed_by_user_id,
            demo_session_id=demo_session_id or api.demo_session_id,
        )

    method_upper = http_method.strip().upper()
    base = api.base_url.rstrip("/") + "/"
    target_url = urljoin(base, endpoint_path.lstrip("/"))

    # 1. DNS Rebinding Verification & IP Pinning
    pinned_ip: Optional[str] = None
    try:
        resolved_ips = resolve_and_verify_host(target_url)
        if resolved_ips:
            pinned_ip = resolved_ips[0]
    except DNSRebindingError as exc:
        logger.error("DNS Rebinding attempt blocked for URL %s: %s", target_url, exc)
        log_entry = ExecutionLog(
            api_registry_id=api.id,
            approval_request_id=approval_request_id,
            executed_by_user_id=executed_by_user_id,
            endpoint_path=endpoint_path,
            http_method=method_upper,
            request_payload=payload,
            response_body={"error": str(exc)},
            response_status_code=403,
            status=ExecutionStatus.FAILED,
            error_message=f"Security Refusal: {exc}",
            duration_ms=0.0,
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)
        return log_entry

    # 2. Prepare headers (transparently decrypted by ORM)
    headers = {
        "User-Agent": "Guardrailed-AI-Gateway/1.0",
        "Accept": "application/json",
    }
    if api.auth_header_name and api.auth_header_value:
        headers[api.auth_header_name] = api.auth_header_value

    start_time = time.perf_counter()
    status_code: Optional[int] = None
    response_data: Any = None
    exec_status = ExecutionStatus.FAILED
    error_message: Optional[str] = None

    # 3. HTTP Execution with Pinned Transport and Strict Redirect Policy
    transport = PinnedHTTPTransport(pinned_ip) if pinned_ip else None
    try:
        async with httpx.AsyncClient(
            transport=transport,
            timeout=settings.external_api_timeout,
            follow_redirects=False,
        ) as client:
            if method_upper == "GET":
                resp = await client.get(target_url, headers=headers, params=payload)
            elif method_upper == "POST":
                resp = await client.post(target_url, headers=headers, json=payload)
            elif method_upper == "PUT":
                resp = await client.put(target_url, headers=headers, json=payload)
            elif method_upper == "PATCH":
                resp = await client.patch(target_url, headers=headers, json=payload)
            elif method_upper == "DELETE":
                resp = await client.delete(target_url, headers=headers, params=payload)
            else:
                resp = await client.request(method_upper, target_url, headers=headers, json=payload)

            status_code = resp.status_code
            try:
                data = resp.json()
                if inspect.iscoroutine(data):
                    response_data = await data
                else:
                    response_data = data
            except Exception:
                response_data = {"raw": getattr(resp, "text", "")[:500]}

            # 2xx and 3xx considered SUCCESS
            if 200 <= status_code < 400:
                exec_status = ExecutionStatus.SUCCESS
            else:
                exec_status = ExecutionStatus.FAILED
                error_message = f"External API returned HTTP status {status_code}"

    except httpx.TimeoutException as exc:
        exec_status = ExecutionStatus.FAILED
        error_message = f"External API call timed out after {settings.external_api_timeout}s"
        response_data = {"error": "Timeout"}
    except httpx.RequestError as exc:
        exec_status = ExecutionStatus.FAILED
        error_message = f"Network communication failed: {exc}"
        response_data = {"error": str(exc)}
    except Exception as exc:
        exec_status = ExecutionStatus.FAILED
        error_message = f"Unexpected execution error: {exc}"
        response_data = {"error": str(exc)}

    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

    # 4. Truncate response to protect DB storage
    safe_response_body = truncate_payload(response_data)

    # 5. Persist Execution Log
    log_entry = ExecutionLog(
        api_registry_id=api.id,
        approval_request_id=approval_request_id,
        executed_by_user_id=executed_by_user_id,
        endpoint_path=endpoint_path,
        http_method=method_upper,
        request_payload=payload,
        response_body=safe_response_body,
        response_status_code=status_code,
        status=exec_status,
        error_message=error_message,
        duration_ms=duration_ms,
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)

    return log_entry
