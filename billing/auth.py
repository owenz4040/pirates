"""Session-cookie auth gate for the admin dashboard."""

from __future__ import annotations

import secrets

from fastapi import HTTPException, Request

from billing.config import settings


class NotAuthenticated(Exception):
    """Raised by require_admin; caught in main.py to redirect to /login."""

    def __init__(self, next_path: str) -> None:
        self.next_path = next_path


def verify_credentials(username: str, password: str) -> bool:
    valid_username = secrets.compare_digest(username, settings.admin_username)
    valid_password = secrets.compare_digest(password, settings.admin_password)
    return valid_username and valid_password


def require_admin(request: Request) -> str:
    if not settings.admin_password:
        raise HTTPException(
            500,
            "ADMIN_PASSWORD is not set - refusing to serve the dashboard with no password configured.",
        )
    username = request.session.get("admin_user")
    if not username:
        raise NotAuthenticated(request.url.path)
    return username
