"""Database-backed rate limiting for tenant authentication across serverless instances."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session

from saas.models.tenant import TenantLoginAttempt

LOCKOUT_THRESHOLD = 5
LOCKOUT_MINUTES = 15
EXTENDED_LOCKOUT_THRESHOLD = 10
EXTENDED_LOCKOUT_MINUTES = 60


def _get_or_create_attempt(db: Session, key: str) -> TenantLoginAttempt:
    record = db.scalar(select(TenantLoginAttempt).where(TenantLoginAttempt.key == key))
    if not record:
        record = TenantLoginAttempt(key=key, failed_attempts=0)
        db.add(record)
        db.flush()
    return record


def is_rate_limited(db: Session, ip: str | None, email: str | None) -> tuple[bool, int]:
    """Check if the given IP or email is currently locked out.

    Returns (is_locked, remaining_seconds).
    Enforces persistent shared storage lockout across both target account and originating IP,
    preventing attackers from bypassing limits by rotating email addresses.
    """
    now = datetime.now(timezone.utc)
    keys_to_check = []
    if ip:
        keys_to_check.append(f"ip:{ip.strip()}")
    if email:
        keys_to_check.append(f"email:{email.strip().lower()}")

    for k in keys_to_check:
        record = db.scalar(select(TenantLoginAttempt).where(TenantLoginAttempt.key == k))
        if record and record.locked_until:
            # Ensure aware comparison
            locked_until = record.locked_until
            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=timezone.utc)
            if locked_until > now:
                remaining = int((locked_until - now).total_seconds())
                return True, max(1, remaining)

    return False, 0


def record_failed_login(db: Session, ip: str | None, email: str | None) -> None:
    """Record a failed login attempt for both IP and email, applying lockout when thresholds are exceeded."""
    now = datetime.now(timezone.utc)
    keys_to_update = []
    if ip:
        keys_to_update.append(f"ip:{ip.strip()}")
    if email:
        keys_to_update.append(f"email:{email.strip().lower()}")

    for k in keys_to_update:
        record = _get_or_create_attempt(db, k)
        record.failed_attempts += 1
        record.updated_at = now

        if record.failed_attempts >= EXTENDED_LOCKOUT_THRESHOLD:
            record.locked_until = now + timedelta(minutes=EXTENDED_LOCKOUT_MINUTES)
        elif record.failed_attempts >= LOCKOUT_THRESHOLD:
            record.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)

    db.commit()


def clear_failed_logins(db: Session, ip: str | None, email: str | None) -> None:
    """Reset failed attempts on a successful authentication.

    Resets the user's email lockout. Resets IP failure count only if the IP
    is not actively locked out.
    """
    now = datetime.now(timezone.utc)
    if email:
        email_record = db.scalar(
            select(TenantLoginAttempt).where(TenantLoginAttempt.key == f"email:{email.strip().lower()}")
        )
        if email_record:
            email_record.failed_attempts = 0
            email_record.locked_until = None

    if ip:
        ip_record = db.scalar(
            select(TenantLoginAttempt).where(TenantLoginAttempt.key == f"ip:{ip.strip()}")
        )
        if ip_record:
            locked_until = ip_record.locked_until
            if locked_until and locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=timezone.utc)
            # Only reset if not actively locked
            if not locked_until or locked_until <= now:
                ip_record.failed_attempts = 0
                ip_record.locked_until = None

    db.commit()
