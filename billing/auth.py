"""Session-cookie auth gate for the admin dashboard."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from billing.config import settings
from billing.models import LoginAttempt

# Lock an IP out after this many failed logins within the window.
MAX_FAILURES = 5
LOCKOUT_WINDOW = timedelta(minutes=15)


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


def client_ip(request: Request) -> str:
    # Vercel puts the real client address first in X-Forwarded-For.
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:45]
    return (request.client.host if request.client else "unknown")[:45]


def lockout_remaining(db: Session, ip: str) -> timedelta | None:
    """How long this IP stays locked out, or None if it may try to log in."""
    since = datetime.now(timezone.utc) - LOCKOUT_WINDOW
    failures, latest = db.execute(
        select(func.count(), func.max(LoginAttempt.created_at)).where(
            LoginAttempt.ip == ip, LoginAttempt.created_at > since
        )
    ).one()
    if failures < MAX_FAILURES or latest is None:
        return None
    if latest.tzinfo is None:
        latest = latest.replace(tzinfo=timezone.utc)
    return latest + LOCKOUT_WINDOW - datetime.now(timezone.utc)


def record_failure(db: Session, ip: str, username: str) -> None:
    db.add(LoginAttempt(ip=ip, username=username[:128], created_at=datetime.now(timezone.utc)))
    # Old rows are no longer useful - keep the table small.
    db.execute(delete(LoginAttempt).where(LoginAttempt.created_at < datetime.now(timezone.utc) - timedelta(days=1)))
    db.commit()
    print(f"Failed admin login for {username!r} from {ip}")


def clear_failures(db: Session, ip: str) -> None:
    db.execute(delete(LoginAttempt).where(LoginAttempt.ip == ip))
    db.commit()
