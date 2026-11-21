"""Cross-Site Request Forgery (CSRF) protection for web forms and state-changing APIs."""
from __future__ import annotations

import secrets
from fastapi import HTTPException, Request, status


def get_csrf_token(request: Request) -> str:
    """Retrieve existing CSRF token from session or generate a new one."""
    if "session" not in request.scope:
        return ""
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


async def verify_csrf_token(request: Request) -> None:
    """FastAPI dependency verifying CSRF token on state-changing requests.

    STRICT CSRF ENFORCEMENT RULES:
    1. Safe methods (GET, HEAD, OPTIONS) do not require CSRF tokens.
    2. Bearer token requests (Authorization: Bearer <token>) are exempt because browsers
       cannot inject custom Authorization headers across origins without CORS preflight approval.
    3. Dedicated machine router endpoints (/api/router/*) are exempt ONLY if a valid
       X-Router-Token header is provided. Cookie-only requests to these endpoints are rejected.
    4. Paystack webhooks (/api/webhook/paystack) are exempt ONLY if an x-paystack-signature
       header is present.
    5. Any other state-changing endpoint—regardless of URL path prefix—is REQUIRED to validate
       a CSRF token if session cookies are present.
    """
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return

    # 1. Bearer token API requests (browsers cannot inject Authorization headers on cross-site requests)
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return

    # 2. Router machine endpoints: MUST supply X-Router-Token
    if request.url.path.startswith("/api/router/"):
        if request.headers.get("x-router-token"):
            return
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required X-Router-Token header on router API.",
        )

    # 3. Paystack webhooks (platform and tenant): MUST supply HMAC signature header
    if request.url.path.startswith("/api/webhook/paystack"):
        if request.headers.get("x-paystack-signature"):
            return
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing required x-paystack-signature header.",
        )

    # 4. Safaricom M-Pesa Daraja webhooks: machine-to-machine callback
    if request.url.path.startswith("/api/webhook/mpesa/"):
        return

    # 5. Public customer portal purchase and checkout endpoints
    if request.url.path in ("/checkout/initiate", "/api/portal/purchase"):
        return

    # 6. All cookie/session-authenticated requests MUST supply a valid CSRF token
    session_token = request.session.get("csrf_token") if "session" in request.scope else None
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing session CSRF token. Please refresh the page and try again.",
        )

    # Check X-CSRF-Token header first (used by fetch/AJAX/SPAs)
    header_token = request.headers.get("X-CSRF-Token") or request.headers.get("x-csrf-token")
    if header_token and secrets.compare_digest(header_token, session_token):
        return

    # Check form body
    try:
        form_data = await request.form()
        form_token = form_data.get("csrf_token")
        if form_token and isinstance(form_token, str) and secrets.compare_digest(form_token, session_token):
            return
    except Exception:
        pass

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="CSRF verification failed: invalid or missing CSRF token.",
    )
