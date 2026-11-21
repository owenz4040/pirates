"""Secure CLI Superadmin Bootstrap Process for Platform Owner."""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from saas.config import saas_settings
from saas.models.audit import SuperadminAuditLog
from saas.models.tenant import SuperadminEnrollment, TenantUser, UserRole
from saas.security.auth import hash_token
from saas.services.email import send_superadmin_otp_email

logger = logging.getLogger("saas.bootstrap")


class SuperadminBootstrapError(RuntimeError):
    """Raised when Superadmin bootstrap fails validation."""
    pass


def initiate_superadmin_bootstrap(
    db: Session,
    email: str | None = None,
    full_name: str = "Platform Owner",
) -> dict[str, Any]:
    """
    Initiates the secure CLI bootstrap process for the Platform Superadmin owner identity.
    Only invoked via CLI command; public self-registration is strictly prohibited.
    
    1. Reads PLATFORM_SUPERADMIN_EMAIL (default owenzcolin@gmail.com).
    2. Enforces idempotency: does not duplicate already-activated superadmin accounts.
    3. Generates a secure single-use 6-digit email OTP (expires in 15 mins).
    4. Records the bootstrap event in the SuperadminAuditLog.
    5. Dispatches verification OTP email.
    """
    target_email = (email or saas_settings.platform_superadmin_email or "owenzcolin@gmail.com").strip().lower()
    configured_owner = (saas_settings.platform_superadmin_email or "owenzcolin@gmail.com").strip().lower()

    # Safeguard 10 & 4: Only the configured PLATFORM_SUPERADMIN_EMAIL may be bootstrapped
    if target_email != configured_owner:
        raise SuperadminBootstrapError(
            f"Unauthorized bootstrap email '{target_email}'. Only configured PLATFORM_SUPERADMIN_EMAIL ('{configured_owner}') can be bootstrapped."
        )

    # Safeguard 4: Prevent creating unauthorized additional Superadmins
    existing_superadmin_any = db.scalar(
        select(TenantUser).where(TenantUser.role == UserRole.superadmin, TenantUser.is_active == True)
    )
    if existing_superadmin_any and existing_superadmin_any.email != target_email:
        raise SuperadminBootstrapError(
            f"A platform superadmin ({existing_superadmin_any.email}) is already configured. Creating additional superadmins via bootstrap is prohibited."
        )

    # Safeguard 12: Check if enrollment is already completed or user is already active
    if existing_superadmin_any and existing_superadmin_any.mfa_enabled and existing_superadmin_any.is_active:
        logger.info("Superadmin account for %s is already active. Skipping duplicate creation.", target_email)
        return {
            "status": "already_active",
            "email": target_email,
            "message": "Superadmin account already exists and is fully activated.",
            "user_id": existing_superadmin_any.id,
        }

    enrollment = db.scalar(
        select(SuperadminEnrollment).where(SuperadminEnrollment.email == target_email)
    )
    if enrollment and enrollment.is_completed:
        logger.info("Superadmin enrollment for %s is already completed. Refusing bootstrap overwrite.", target_email)
        return {
            "status": "already_active",
            "email": target_email,
            "message": "Superadmin enrollment is already completed. Bypassing completed enrollment is prohibited.",
        }

    # Generate single-use 6-digit OTP
    otp_code = f"{secrets.randbelow(900000) + 100000}"
    otp_hashed = hash_token(otp_code)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

    # Upsert SuperadminEnrollment
    if not enrollment:
        enrollment = SuperadminEnrollment(
            email=target_email,
            full_name=full_name,
            otp_hash=otp_hashed,
            otp_expires_at=expires_at,
            is_email_verified=False,
            failed_attempts=0,
            is_completed=False,
        )
        db.add(enrollment)
    else:
        enrollment.otp_hash = otp_hashed
        enrollment.otp_expires_at = expires_at
        enrollment.is_email_verified = False
        enrollment.failed_attempts = 0
        enrollment.is_completed = False

    db.flush()

    # Record event in immutable audit log
    audit_entry = SuperadminAuditLog(
        actor_user_id=None,
        actor_email="system.cli",
        action="superadmin.bootstrap_initiated",
        target_type="superadmin_enrollment",
        target_id=enrollment.id,
        reason=f"CLI bootstrap initiated for owner identity {target_email}",
    )
    db.add(audit_entry)
    db.commit()

    # Dispatch email OTP
    email_sent = send_superadmin_otp_email(to_email=target_email, otp_code=otp_code)

    logger.info("Superadmin bootstrap initiated for %s. OTP dispatched: %s", target_email, email_sent)

    return {
        "status": "otp_dispatched",
        "email": target_email,
        "otp": otp_code,
        "expires_in_minutes": 15,
        "setup_url": f"{saas_settings.saas_public_base_url.rstrip('/')}/superadmin/setup?email={target_email}",
        "email_sent": email_sent,
    }


def bootstrap_superadmin(
    db: Session,
    email: str | None = None,
    password: str | None = None,
    full_name: str = "Platform Superadmin",
) -> TenantUser | None:
    """Convenience helper for programmatic or testing setup of superadmin."""
    from saas.security.auth import hash_password

    target_email = (email or saas_settings.platform_superadmin_email or "owenzcolin@gmail.com").strip().lower()
    target_pass = password or saas_settings.superadmin_password

    if not target_pass:
        return None

    user = db.scalar(
        select(TenantUser).where(TenantUser.email == target_email, TenantUser.role == UserRole.superadmin)
    )
    if not user:
        user = TenantUser(
            tenant_id=None,
            email=target_email,
            full_name=full_name,
            hashed_password=hash_password(target_pass),
            role=UserRole.superadmin,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    return user

