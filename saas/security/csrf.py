"""Cross-Site Request Forgery (CSRF) protection for web forms."""
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

    Exempts machine/API paths (e.g. /api/router/*, /api/health).
    """
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return

    # Exempt router machine endpoints and public webhooks
    if request.url.path.startswith("/api/"):
        return

    # Exempt Bearer token API requests (browsers cannot inject Authorization headers on cross-site requests)
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return

    session_token = request.session.get("csrf_token") if "session" in request.scope else None
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing session CSRF token. Please refresh the page and try again.",
        )

    # Check X-CSRF-Token header first
    header_token = request.headers.get("X-CSRF-Token")
    if header_token and secrets.compare_digest(header_token, session_token):
        return

    # Check form body
    form_data = await request.form()
    form_token = form_data.get("csrf_token")
    if form_token and isinstance(form_token, str) and secrets.compare_digest(form_token, session_token):
        return

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="CSRF verification failed: invalid or missing CSRF token.",
    )
