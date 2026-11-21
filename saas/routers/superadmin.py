"""Platform Superadmin management routes, analytics, and tenant controls."""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from saas.config import saas_settings
from saas.database import get_saas_db
from saas.models.audit import SuperadminAuditLog
from saas.models.payments import SubscriptionTransaction
from saas.models.router import Router
from saas.models.tenant import (
    SubscriptionTier,
    SuperadminEnrollment,
    Tenant,
    TenantStatus,
    TenantSubscription,
    TenantUser,
    TenantUserRecoveryCode,
    UserRole,
)
from saas.security.auth import hash_password, hash_token, verify_password
from saas.security.crypto import decrypt_secret, encrypt_secret
from saas.security.totp import generate_totp_secret, get_totp_uri, verify_totp

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

superadmin_router = APIRouter(prefix="/superadmin", tags=["superadmin"])


def get_current_superadmin(request: Request, db: Session = Depends(get_saas_db)) -> TenantUser | None:
    """Helper to retrieve authenticated superadmin from session with session rotation & expiry checks."""
    user_id = None
    if "session" in request.scope:
        user_id = request.session.get("superadmin_user_id") or request.session.get("user_id")

    if not user_id:
        return None

    user = db.scalar(
        select(TenantUser).where(
            TenantUser.id == user_id,
            TenantUser.role == UserRole.superadmin,
            TenantUser.is_active == True,
        )
    )
    if not user:
        return None

    # Verify session age (max 12 hours = 43200 seconds)
    if "session" in request.scope:
        login_time = request.session.get("superadmin_login_time")
        if login_time:
            now_ts = int(datetime.now(timezone.utc).timestamp())
            if now_ts - int(login_time) > 43200:
                request.session.pop("superadmin_user_id", None)
                request.session.pop("superadmin_login_time", None)
                request.session.pop("superadmin_session_version", None)
                return None

        # Verify session version against revocation
        expected_version = request.session.get("superadmin_session_version")
        if expected_version is not None and expected_version != user.session_version:
            request.session.pop("superadmin_user_id", None)
            request.session.pop("superadmin_login_time", None)
            request.session.pop("superadmin_session_version", None)
            return None

    return user


def require_superadmin(request: Request, db: Session = Depends(get_saas_db)) -> TenantUser:
    """Dependency that strictly guarantees superadmin authorization or redirects to login."""
    user = get_current_superadmin(request, db)
    if not user:
        # Check authorization header fallback for API/tests
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            bearer_user = db.scalar(
                select(TenantUser).where(
                    TenantUser.id == token,
                    TenantUser.role == UserRole.superadmin,
                    TenantUser.is_active == True,
                )
            )
            if bearer_user:
                return bearer_user

        # Redirect to login for web browsers
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/superadmin/login"},
        )
    return user


def _as_utc(dt: datetime | None) -> datetime:
    """Ensures a datetime is timezone-aware UTC for safe comparisons on SQLite & Postgres."""
    if dt is None:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _log_audit_action(
    db: Session,
    actor: TenantUser,
    action: str,
    target_type: str,
    target_id: str,
    reason: str | None = None,
    ip_address: str | None = None,
) -> None:
    """Safely appends an entry to the immutable audit log."""
    log = SuperadminAuditLog(
        actor_user_id=actor.id,
        actor_email=actor.email,
        action=action,
        target_type=target_type,
        target_id=target_id,
        reason=reason,
        ip_address=ip_address,
    )
    db.add(log)
    db.commit()


# ---------------------------------------------------------
# Authentication (Login / Logout)
# ---------------------------------------------------------
@superadmin_router.get("/login", response_class=HTMLResponse)
def superadmin_login_page(request: Request, db: Session = Depends(get_saas_db)):
    """Superadmin login screen."""
    user = get_current_superadmin(request, db)
    if user:
        return RedirectResponse(url="/superadmin", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="superadmin/login.html",
        context={"current_superadmin": None, "error": None},
    )


@superadmin_router.post("/login")
def superadmin_login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_saas_db),
):
    """Authenticates platform superadmin and establishes secure session."""
    user = db.scalar(
        select(TenantUser).where(
            TenantUser.email == email.strip().lower(),
            TenantUser.role == UserRole.superadmin,
            TenantUser.is_active == True,
        )
    )
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(
            request=request,
            name="superadmin/login.html",
            context={"current_superadmin": None, "error": "Invalid administrative credentials."},
            status_code=401,
        )

    # Mandatory TOTP MFA Verification if enabled
    if user.mfa_enabled:
        if "session" in request.scope:
            request.session["mfa_pending_user_id"] = user.id
        return RedirectResponse(url="/superadmin/mfa", status_code=303)

    if "session" in request.scope:
        request.session["superadmin_user_id"] = user.id

    return RedirectResponse(url="/superadmin", status_code=303)


@superadmin_router.get("/mfa", response_class=HTMLResponse)
def superadmin_mfa_page(request: Request, db: Session = Depends(get_saas_db)):
    """Displays TOTP authenticator challenge."""
    user_id = request.session.get("mfa_pending_user_id") if "session" in request.scope else None
    if not user_id:
        return RedirectResponse(url="/superadmin/login", status_code=303)

    user = db.scalar(select(TenantUser).where(TenantUser.id == user_id))
    email = user.email if user else ""

    return templates.TemplateResponse(
        request=request,
        name="superadmin/mfa_challenge.html",
        context={"current_superadmin": None, "email": email, "error": None},
    )


@superadmin_router.post("/mfa")
def superadmin_mfa_submit(
    request: Request,
    totp_code: str = Form(...),
    db: Session = Depends(get_saas_db),
):
    """Verifies TOTP authenticator code or emergency MFA recovery code to finalize superadmin login."""
    user_id = request.session.get("mfa_pending_user_id") if "session" in request.scope else None
    if not user_id:
        return RedirectResponse(url="/superadmin/login", status_code=303)

    user = db.scalar(select(TenantUser).where(TenantUser.id == user_id))
    if not user or not user.totp_secret_encrypted:
        return RedirectResponse(url="/superadmin/login", status_code=303)

    code_clean = totp_code.strip()
    is_valid = False
    recovery_used = False

    # 1. Check if it's a valid 6-digit TOTP code
    secret = decrypt_secret(user.totp_secret_encrypted)
    if code_clean.isdigit() and len(code_clean) == 6:
        is_valid = verify_totp(secret, code_clean)
    else:
        # 2. Check if it's an emergency MFA recovery code
        code_hash = hash_token(code_clean.upper())
        recovery_rec = db.scalar(
            select(TenantUserRecoveryCode).where(
                TenantUserRecoveryCode.user_id == user.id,
                TenantUserRecoveryCode.code_hash == code_hash,
                TenantUserRecoveryCode.is_used == False,
            )
        )
        if recovery_rec:
            recovery_rec.is_used = True
            recovery_rec.used_at = datetime.now(timezone.utc)
            db.commit()
            is_valid = True
            recovery_used = True

    if not is_valid:
        _log_audit_action(
            db=db,
            actor=user,
            action="superadmin.mfa_failed",
            target_type="user",
            target_id=user.id,
            reason="Invalid TOTP MFA or recovery code submitted",
            ip_address=request.client.host if request.client else None,
        )
        return templates.TemplateResponse(
            request=request,
            name="superadmin/mfa_challenge.html",
            context={"current_superadmin": None, "email": user.email, "error": "Invalid authenticator code. Please check your app and try again."},
            status_code=401,
        )

    # Valid MFA: clear pending and establish active session with rotation & timestamp
    if "session" in request.scope:
        request.session.pop("mfa_pending_user_id", None)
        request.session["superadmin_user_id"] = user.id
        request.session["superadmin_session_version"] = user.session_version
        request.session["superadmin_login_time"] = int(datetime.now(timezone.utc).timestamp())

    _log_audit_action(
        db=db,
        actor=user,
        action="superadmin.recovery_code_used" if recovery_used else "superadmin.login_success",
        target_type="user",
        target_id=user.id,
        reason="Emergency recovery code used for login" if recovery_used else "Successful authentication with mandatory TOTP MFA",
        ip_address=request.client.host if request.client else None,
    )

    return RedirectResponse(url="/superadmin", status_code=303)


# ---------------------------------------------------------
# Owner Identity Verification & Mandatory MFA Setup
# ---------------------------------------------------------
@superadmin_router.get("/setup", response_class=HTMLResponse)
def superadmin_setup_page(request: Request, email: str | None = None, db: Session = Depends(get_saas_db)):
    """Step 1: Enter single-use 6-digit OTP dispatched by CLI bootstrap."""
    configured_owner = saas_settings.platform_superadmin_email.strip().lower()
    target_email = (email or configured_owner).strip().lower()
    return templates.TemplateResponse(
        request=request,
        name="superadmin/setup_otp.html",
        context={"current_superadmin": None, "email": target_email, "error": None},
    )


@superadmin_router.post("/setup/verify-otp")
def superadmin_verify_otp(
    request: Request,
    email: str = Form(...),
    otp: str = Form(...),
    db: Session = Depends(get_saas_db),
):
    """Verifies single-use OTP and stages TOTP MFA enrollment secret."""
    target_email = email.strip().lower()
    configured_owner = saas_settings.platform_superadmin_email.strip().lower()
    if target_email != configured_owner:
        return templates.TemplateResponse(
            request=request,
            name="superadmin/setup_otp.html",
            context={
                "current_superadmin": None,
                "email": target_email,
                "error": "Unauthorized owner email. Bootstrap is restricted to the configured platform owner.",
            },
            status_code=403,
        )

    now = datetime.now(timezone.utc)
    otp_clean = otp.strip().replace(" ", "")

    enrollment = db.scalar(
        select(SuperadminEnrollment).where(
            SuperadminEnrollment.email == target_email,
        )
    )

    if not enrollment or enrollment.is_completed:
        return templates.TemplateResponse(
            request=request,
            name="superadmin/setup_otp.html",
            context={
                "current_superadmin": None,
                "email": target_email,
                "error": "No pending superadmin bootstrap found. Completed enrollments cannot be reused.",
            },
            status_code=404,
        )

    # Brute-force & rate-limiting protection: max 5 failed attempts
    if enrollment.failed_attempts >= 5:
        return templates.TemplateResponse(
            request=request,
            name="superadmin/setup_otp.html",
            context={
                "current_superadmin": None,
                "email": target_email,
                "error": "Maximum verification attempts exceeded. For security, please run the CLI bootstrap command again.",
            },
            status_code=429,
        )

    # Prevent OTP reuse
    if enrollment.is_email_verified or enrollment.otp_hash == "USED":
        return templates.TemplateResponse(
            request=request,
            name="superadmin/setup_otp.html",
            context={
                "current_superadmin": None,
                "email": target_email,
                "error": "This verification code has already been used.",
            },
            status_code=400,
        )

    if _as_utc(enrollment.otp_expires_at) < now:
        return templates.TemplateResponse(
            request=request,
            name="superadmin/setup_otp.html",
            context={
                "current_superadmin": None,
                "email": target_email,
                "error": "This verification code has expired. Please run the CLI bootstrap command again.",
            },
            status_code=400,
        )

    if enrollment.otp_hash != hash_token(otp_clean):
        enrollment.failed_attempts += 1
        db.commit()
        remaining = max(0, 5 - enrollment.failed_attempts)
        return templates.TemplateResponse(
            request=request,
            name="superadmin/setup_otp.html",
            context={
                "current_superadmin": None,
                "email": target_email,
                "error": f"Invalid verification code. {remaining} attempt(s) remaining.",
            },
            status_code=400,
        )

    # Valid OTP: Generate fresh Base32 TOTP secret for Step 2 and single-use setup session token
    raw_secret = generate_totp_secret()
    setup_token = secrets.token_urlsafe(32)

    enrollment.totp_secret_encrypted = encrypt_secret(raw_secret)
    enrollment.is_email_verified = True
    enrollment.otp_hash = "USED"
    enrollment.setup_session_token = setup_token
    db.commit()

    if "session" in request.scope:
        request.session["enrollment_verified_email"] = target_email
        request.session["enrollment_token"] = setup_token

    return RedirectResponse(url="/superadmin/setup/mfa", status_code=303)


@superadmin_router.get("/setup/mfa", response_class=HTMLResponse)
def superadmin_setup_mfa_page(request: Request, db: Session = Depends(get_saas_db)):
    """Step 2: Password setup and mandatory TOTP MFA enrollment."""
    verified_email = request.session.get("enrollment_verified_email") if "session" in request.scope else None
    enrollment_token = request.session.get("enrollment_token") if "session" in request.scope else None
    if not verified_email or not enrollment_token:
        return RedirectResponse(url="/superadmin/setup", status_code=303)

    enrollment = db.scalar(
        select(SuperadminEnrollment).where(
            SuperadminEnrollment.email == verified_email,
            SuperadminEnrollment.is_email_verified == True,
            SuperadminEnrollment.is_completed == False,
        )
    )
    if not enrollment or not enrollment.totp_secret_encrypted or enrollment.setup_session_token != enrollment_token:
        return RedirectResponse(url="/superadmin/setup", status_code=303)

    now = datetime.now(timezone.utc)
    if _as_utc(enrollment.otp_expires_at) < now:
        return RedirectResponse(url="/superadmin/setup", status_code=303)

    raw_secret = decrypt_secret(enrollment.totp_secret_encrypted)
    totp_uri = get_totp_uri(raw_secret, verified_email, issuer="COwen")

    return templates.TemplateResponse(
        request=request,
        name="superadmin/setup_mfa.html",
        context={
            "current_superadmin": None,
            "email": verified_email,
            "totp_secret": raw_secret,
            "totp_uri": totp_uri,
            "error": None,
        },
    )


@superadmin_router.post("/setup/complete")
def superadmin_setup_complete(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    totp_code: str = Form(...),
    db: Session = Depends(get_saas_db),
):
    """
    Validates password and TOTP code.
    Generates 8 single-use emergency MFA recovery codes.
    ONLY marks the account as PLATFORM_SUPERADMIN upon full verification.
    """
    target_email = email.strip().lower()
    configured_owner = saas_settings.platform_superadmin_email.strip().lower()
    if target_email != configured_owner:
        return templates.TemplateResponse(
            request=request,
            name="superadmin/setup_otp.html",
            context={
                "current_superadmin": None,
                "email": target_email,
                "error": "Unauthorized owner email. Enrollment is restricted to the configured platform owner.",
            },
            status_code=403,
        )

    enrollment_token = request.session.get("enrollment_token") if "session" in request.scope else None
    enrollment = db.scalar(
        select(SuperadminEnrollment).where(
            SuperadminEnrollment.email == target_email,
            SuperadminEnrollment.is_email_verified == True,
            SuperadminEnrollment.is_completed == False,
        )
    )
    if not enrollment or not enrollment.totp_secret_encrypted:
        return RedirectResponse(url="/superadmin/setup", status_code=303)

    if enrollment_token and enrollment.setup_session_token and enrollment.setup_session_token != enrollment_token:
        return RedirectResponse(url="/superadmin/setup", status_code=303)

    raw_secret = decrypt_secret(enrollment.totp_secret_encrypted)
    totp_uri = get_totp_uri(raw_secret, target_email, issuer="COwen")

    if len(password) < 10:
        return templates.TemplateResponse(
            request=request,
            name="superadmin/setup_mfa.html",
            context={
                "current_superadmin": None,
                "email": target_email,
                "totp_secret": raw_secret,
                "totp_uri": totp_uri,
                "error": "Password must be at least 10 characters.",
            },
            status_code=400,
        )

    if password != password_confirm:
        return templates.TemplateResponse(
            request=request,
            name="superadmin/setup_mfa.html",
            context={
                "current_superadmin": None,
                "email": target_email,
                "totp_secret": raw_secret,
                "totp_uri": totp_uri,
                "error": "Passwords do not match.",
            },
            status_code=400,
        )

    # Verify TOTP code submitted from user's authenticator app
    if not verify_totp(raw_secret, totp_code):
        return templates.TemplateResponse(
            request=request,
            name="superadmin/setup_mfa.html",
            context={
                "current_superadmin": None,
                "email": target_email,
                "totp_secret": raw_secret,
                "totp_uri": totp_uri,
                "error": "Invalid 6-digit authenticator code. Check your app and try again.",
            },
            status_code=400,
        )

    # Verification successful: Create or upgrade TenantUser to PLATFORM_SUPERADMIN
    user = db.scalar(select(TenantUser).where(TenantUser.email == target_email))
    if not user:
        user = TenantUser(
            tenant_id=None,
            email=target_email,
            full_name=enrollment.full_name,
            hashed_password=hash_password(password),
            role=UserRole.superadmin,
            totp_secret_encrypted=enrollment.totp_secret_encrypted,
            mfa_enabled=True,
            is_active=True,
            email_verified=True,
            session_version=1,
        )
        db.add(user)
    else:
        user.role = UserRole.superadmin
        user.hashed_password = hash_password(password)
        user.totp_secret_encrypted = enrollment.totp_secret_encrypted
        user.mfa_enabled = True
        user.is_active = True
        user.email_verified = True
        user.tenant_id = None
        user.session_version = (user.session_version or 1) + 1

    db.flush()

    # Generate 8 single-use emergency MFA recovery codes
    raw_recovery_codes: list[str] = []
    for _ in range(8):
        code = f"{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
        raw_recovery_codes.append(code)
        rec = TenantUserRecoveryCode(
            user_id=user.id,
            code_hash=hash_token(code),
            is_used=False,
        )
        db.add(rec)

    enrollment.is_completed = True
    enrollment.setup_session_token = None
    db.commit()
    db.refresh(user)

    # Record event in immutable audit log
    _log_audit_action(
        db=db,
        actor=user,
        action="superadmin.activated",
        target_type="user",
        target_id=user.id,
        reason="Owner identity verified with OTP, mandatory TOTP MFA enrolled and 8 recovery codes generated",
        ip_address=request.client.host if request.client else None,
    )

    # Establish superadmin session with version rotation and timestamp
    if "session" in request.scope:
        request.session.pop("enrollment_verified_email", None)
        request.session.pop("enrollment_token", None)
        request.session["superadmin_user_id"] = user.id
        request.session["superadmin_session_version"] = user.session_version
        request.session["superadmin_login_time"] = int(datetime.now(timezone.utc).timestamp())
        request.session["superadmin_recovery_codes"] = raw_recovery_codes

    return RedirectResponse(url="/superadmin", status_code=303)


@superadmin_router.get("/recovery-codes", response_class=HTMLResponse)
def superadmin_recovery_codes_page(
    request: Request,
    current_user: TenantUser = Depends(require_superadmin),
):
    """Displays newly generated emergency MFA recovery codes."""
    recovery_codes = request.session.get("superadmin_recovery_codes", [])
    return templates.TemplateResponse(
        request=request,
        name="superadmin/setup_complete.html",
        context={
            "current_superadmin": current_user,
            "email": current_user.email,
            "recovery_codes": recovery_codes,
        },
    )


@superadmin_router.post("/revoke-sessions")
def superadmin_revoke_sessions(
    request: Request,
    current_user: TenantUser = Depends(require_superadmin),
    db: Session = Depends(get_saas_db),
):
    """Revokes all active superadmin sessions across devices by incrementing session_version."""
    current_user.session_version = (current_user.session_version or 1) + 1
    db.commit()

    _log_audit_action(
        db=db,
        actor=current_user,
        action="superadmin.sessions_revoked",
        target_type="user",
        target_id=current_user.id,
        reason="All active administrative sessions revoked",
        ip_address=request.client.host if request.client else None,
    )

    if "session" in request.scope:
        request.session.pop("superadmin_user_id", None)
        request.session.pop("superadmin_session_version", None)
        request.session.pop("superadmin_login_time", None)

    return RedirectResponse(url="/superadmin/login", status_code=303)


@superadmin_router.get("/logout")
def superadmin_logout(request: Request):
    """Logs out superadmin."""
    if "session" in request.scope:
        request.session.pop("superadmin_user_id", None)
        request.session.pop("superadmin_session_version", None)
        request.session.pop("superadmin_login_time", None)
        request.session.pop("mfa_pending_user_id", None)
        request.session.pop("enrollment_verified_email", None)
        request.session.pop("enrollment_token", None)
    return RedirectResponse(url="/superadmin/login", status_code=303)


# ---------------------------------------------------------
# Executive Dashboard Overview
# ---------------------------------------------------------
@superadmin_router.get("", response_class=HTMLResponse)
def superadmin_dashboard(
    request: Request,
    current_user: TenantUser = Depends(require_superadmin),
    db: Session = Depends(get_saas_db),
):
    """Platform Executive Overview with live database KPIs."""
    now = datetime.now(timezone.utc)

    # 1. Tenant counts
    total_tenants = db.scalar(select(func.count(Tenant.id))) or 0
    active_tenants = db.scalar(select(func.count(Tenant.id)).where(Tenant.status == TenantStatus.active)) or 0
    suspended_tenants = db.scalar(select(func.count(Tenant.id)).where(Tenant.status == TenantStatus.suspended)) or 0

    # 2. Subscriptions & MRR
    active_subs = db.scalars(
        select(TenantSubscription).where(TenantSubscription.is_active == True)
    ).all()
    mrr_kes = sum(s.monthly_price_kes for s in active_subs)
    active_subscriptions_count = len(active_subs)

    # 3. Router stats
    total_routers = db.scalar(select(func.count(Router.id))) or 0

    # 4. Payment stats
    successful_txns = db.scalars(
        select(SubscriptionTransaction).where(SubscriptionTransaction.status == "success")
    ).all()
    total_paid_volume_kes = sum(tx.amount_kes for tx in successful_txns)
    successful_payments_count = len(successful_txns)

    # 5. Recent signups
    recent_tenants = db.scalars(
        select(Tenant).order_by(Tenant.created_at.desc()).limit(5)
    ).all()

    # 6. Upcoming expirations (next 7 days)
    seven_days = now + timedelta(days=7)
    expiring_subscriptions = db.scalars(
        select(TenantSubscription).where(
            TenantSubscription.is_active == True,
            TenantSubscription.expires_at <= seven_days,
            TenantSubscription.expires_at >= now,
        ).order_by(TenantSubscription.expires_at.asc()).limit(10)
    ).all()

    metrics = {
        "total_tenants": total_tenants,
        "active_tenants": active_tenants,
        "suspended_tenants": suspended_tenants,
        "mrr_kes": mrr_kes,
        "active_subscriptions_count": active_subscriptions_count,
        "total_routers": total_routers,
        "total_paid_volume_kes": total_paid_volume_kes,
        "successful_payments_count": successful_payments_count,
    }

    return templates.TemplateResponse(
        request=request,
        name="superadmin/dashboard.html",
        context={
            "current_superadmin": current_user,
            "active_tab": "dashboard",
            "metrics": metrics,
            "recent_tenants": recent_tenants,
            "expiring_subscriptions": expiring_subscriptions,
        },
    )


# ---------------------------------------------------------
# Tenant Management
# ---------------------------------------------------------
@superadmin_router.get("/tenants", response_class=HTMLResponse)
def list_tenants(
    request: Request,
    q: str | None = None,
    status: str | None = None,
    current_user: TenantUser = Depends(require_superadmin),
    db: Session = Depends(get_saas_db),
):
    """Lists, searches, and filters registered tenants."""
    stmt = select(Tenant).order_by(Tenant.created_at.desc())

    if q and q.strip():
        term = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(
                Tenant.name.ilike(term),
                Tenant.slug.ilike(term),
                Tenant.contact_email.ilike(term),
            )
        )

    if status and status.strip():
        try:
            status_enum = TenantStatus(status.strip().lower())
            stmt = stmt.where(Tenant.status == status_enum)
        except ValueError:
            pass

    tenants = db.scalars(stmt).all()

    return templates.TemplateResponse(
        request=request,
        name="superadmin/tenants.html",
        context={
            "current_superadmin": current_user,
            "active_tab": "tenants",
            "tenants": tenants,
            "query": q,
            "status_filter": status,
        },
    )


@superadmin_router.get("/tenants/{tenant_id}", response_class=HTMLResponse)
def tenant_detail(
    tenant_id: str,
    request: Request,
    current_user: TenantUser = Depends(require_superadmin),
    db: Session = Depends(get_saas_db),
):
    """Detailed profile, subscription settings, and administrative overrides for a tenant."""
    tenant = db.scalar(select(Tenant).where(Tenant.id == tenant_id))
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found.")

    transactions = db.scalars(
        select(SubscriptionTransaction)
        .where(SubscriptionTransaction.tenant_id == tenant_id)
        .order_by(SubscriptionTransaction.created_at.desc())
    ).all()

    return templates.TemplateResponse(
        request=request,
        name="superadmin/tenant_detail.html",
        context={
            "current_superadmin": current_user,
            "active_tab": "tenants",
            "tenant": tenant,
            "transactions": transactions,
        },
    )


@superadmin_router.post("/tenants/{tenant_id}/suspend")
def suspend_tenant(
    tenant_id: str,
    request: Request,
    reason: str = Form("Administrative suspension"),
    current_user: TenantUser = Depends(require_superadmin),
    db: Session = Depends(get_saas_db),
):
    """Suspends a tenant ISP."""
    tenant = db.scalar(select(Tenant).where(Tenant.id == tenant_id))
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found.")

    tenant.status = TenantStatus.suspended
    db.commit()

    _log_audit_action(
        db=db,
        actor=current_user,
        action="tenant.suspend",
        target_type="tenant",
        target_id=tenant_id,
        reason=reason,
        ip_address=request.client.host if request.client else None,
    )

    return RedirectResponse(url=f"/superadmin/tenants/{tenant_id}", status_code=303)


@superadmin_router.post("/tenants/{tenant_id}/reactivate")
def reactivate_tenant(
    tenant_id: str,
    request: Request,
    reason: str = Form("Administrative reactivation"),
    current_user: TenantUser = Depends(require_superadmin),
    db: Session = Depends(get_saas_db),
):
    """Reactivates a suspended tenant ISP."""
    tenant = db.scalar(select(Tenant).where(Tenant.id == tenant_id))
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found.")

    tenant.status = TenantStatus.active
    db.commit()

    _log_audit_action(
        db=db,
        actor=current_user,
        action="tenant.reactivate",
        target_type="tenant",
        target_id=tenant_id,
        reason=reason,
        ip_address=request.client.host if request.client else None,
    )

    return RedirectResponse(url=f"/superadmin/tenants/{tenant_id}", status_code=303)


@superadmin_router.post("/tenants/{tenant_id}/change-tier")
def change_tenant_tier(
    tenant_id: str,
    request: Request,
    tier: str = Form(...),
    reason: str = Form(...),
    current_user: TenantUser = Depends(require_superadmin),
    db: Session = Depends(get_saas_db),
):
    """Changes a tenant's subscription tier and recalculates router limit & price."""
    tenant = db.scalar(select(Tenant).where(Tenant.id == tenant_id))
    if not tenant or not tenant.subscription:
        raise HTTPException(status_code=404, detail="Tenant or active subscription not found.")

    new_tier = SubscriptionTier(tier.lower())
    tenant.subscription.tier = new_tier
    tenant.subscription.max_routers = new_tier.max_routers
    tenant.subscription.monthly_price_kes = new_tier.monthly_price_kes
    db.commit()

    _log_audit_action(
        db=db,
        actor=current_user,
        action="tenant.change_tier",
        target_type="subscription",
        target_id=tenant.subscription.id,
        reason=f"Changed to {new_tier.value}: {reason}",
        ip_address=request.client.host if request.client else None,
    )

    return RedirectResponse(url=f"/superadmin/tenants/{tenant_id}", status_code=303)


@superadmin_router.post("/tenants/{tenant_id}/extend")
def extend_tenant_subscription(
    tenant_id: str,
    request: Request,
    days: int = Form(30),
    reason: str = Form(...),
    current_user: TenantUser = Depends(require_superadmin),
    db: Session = Depends(get_saas_db),
):
    """Extends a tenant's subscription expiration date."""
    tenant = db.scalar(select(Tenant).where(Tenant.id == tenant_id))
    if not tenant or not tenant.subscription:
        raise HTTPException(status_code=404, detail="Tenant or subscription not found.")

    tenant.subscription.expires_at += timedelta(days=days)
    tenant.subscription.is_active = True
    db.commit()

    _log_audit_action(
        db=db,
        actor=current_user,
        action="tenant.extend_subscription",
        target_type="subscription",
        target_id=tenant.subscription.id,
        reason=f"Extended by {days} days: {reason}",
        ip_address=request.client.host if request.client else None,
    )

    return RedirectResponse(url=f"/superadmin/tenants/{tenant_id}", status_code=303)


@superadmin_router.post("/tenants/{tenant_id}/override-router-limit")
def override_router_limit(
    tenant_id: str,
    request: Request,
    max_routers: int = Form(...),
    reason: str = Form(...),
    current_user: TenantUser = Depends(require_superadmin),
    db: Session = Depends(get_saas_db),
):
    """Applies a documented manual router limit override."""
    tenant = db.scalar(select(Tenant).where(Tenant.id == tenant_id))
    if not tenant or not tenant.subscription:
        raise HTTPException(status_code=404, detail="Tenant or subscription not found.")

    old_limit = tenant.subscription.max_routers
    tenant.subscription.max_routers = max_routers
    db.commit()

    _log_audit_action(
        db=db,
        actor=current_user,
        action="tenant.override_router_limit",
        target_type="subscription",
        target_id=tenant.subscription.id,
        reason=f"Override limit from {old_limit} to {max_routers}: {reason}",
        ip_address=request.client.host if request.client else None,
    )

    return RedirectResponse(url=f"/superadmin/tenants/{tenant_id}", status_code=303)


# ---------------------------------------------------------
# Financial Management
# ---------------------------------------------------------
@superadmin_router.get("/finance", response_class=HTMLResponse)
def finance_overview(
    request: Request,
    current_user: TenantUser = Depends(require_superadmin),
    db: Session = Depends(get_saas_db),
):
    """Platform subscription collections and financial segregation."""
    transactions = db.scalars(
        select(SubscriptionTransaction).order_by(SubscriptionTransaction.created_at.desc())
    ).all()

    successful_txns = [tx for tx in transactions if tx.status == "success"]
    total_revenue_kes = sum(tx.amount_kes for tx in successful_txns)

    active_subs = db.scalars(
        select(TenantSubscription).where(TenantSubscription.is_active == True)
    ).all()
    mrr_kes = sum(s.monthly_price_kes for s in active_subs)

    return templates.TemplateResponse(
        request=request,
        name="superadmin/finance.html",
        context={
            "current_superadmin": current_user,
            "active_tab": "finance",
            "transactions": transactions,
            "total_revenue_kes": total_revenue_kes,
            "successful_txns_count": len(successful_txns),
            "mrr_kes": mrr_kes,
        },
    )


# ---------------------------------------------------------
# Audit Logs
# ---------------------------------------------------------
@superadmin_router.get("/audit-logs", response_class=HTMLResponse)
def audit_logs_page(
    request: Request,
    current_user: TenantUser = Depends(require_superadmin),
    db: Session = Depends(get_saas_db),
):
    """Immutable audit trail of administrative modifications."""
    logs = db.scalars(
        select(SuperadminAuditLog).order_by(SuperadminAuditLog.created_at.desc()).limit(100)
    ).all()

    return templates.TemplateResponse(
        request=request,
        name="superadmin/audit_logs.html",
        context={
            "current_superadmin": current_user,
            "active_tab": "audit",
            "logs": logs,
        },
    )
