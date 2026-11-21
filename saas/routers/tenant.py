"""Tenant Admin Portal routes, management views, and MikroTik router sync APIs."""
from __future__ import annotations

import logging
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, Header, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from saas.config import saas_settings
from saas.database import get_saas_db
from saas.models.deployment import DeploymentStatus, HotspotDeployment
from saas.models.hotspot import (
    HotspotPackage,
    HotspotPortalDesign,
    HotspotVoucher,
    VoucherStatus,
)
from saas.models.payments import CustomerPayment, TenantPaymentConfig
from saas.models.pppoe import (
    ConnectionType,
    CustomerStatus,
    PPPoECustomer,
    PPPoEPlan,
)
from saas.models.router import (
    Router,
    RouterCommand,
    RouterCommandStatus,
    RouterStatus,
)
from saas.models.tenant import (
    SubscriptionTier,
    Tenant,
    TenantBranding,
    TenantStatus,
    TenantSubscription,
    TenantUser,
    UserRole,
)
from saas.security.auth import (
    generate_secure_token,
    hash_password,
    hash_token,
    verify_password,
)
from saas.security.context import (
    SubscriptionLimitExceededError,
    TenantContext,
)
from saas.security.csrf import get_csrf_token, verify_csrf_token
from saas.security.rate_limit import (
    clear_failed_logins,
    is_rate_limited,
    record_failed_login,
)
from saas.security.sanitizer import (
    CommandInjectionError,
    build_hotspot_profile_command,
    build_hotspot_user_command,
    build_mikrotik_rsc_file,
    build_mikrotik_sync_script_source,
    build_mikrotik_terminal_commands,
    build_pppoe_delete_command,
    build_pppoe_disable_command,
    build_pppoe_enable_command,
    build_pppoe_profile_command,
    build_pppoe_secret_command,
    quote_routeros,
    validate_package_name,
    validate_password,
    validate_plan_name,
    validate_pppoe_username,
    validate_rate_limit,
)

logger = logging.getLogger("saas.tenant")

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

# RouterOS payload size boundaries for in-memory fetch
BATCH_BYTES_ROS6 = 3500
BATCH_BYTES_ROS7 = 32768
# Explicit session lifetime policies:
SESSION_INACTIVITY_TIMEOUT = 43200  # 12 hours sliding inactivity timeout
SESSION_ABSOLUTE_LIFETIME = 86400   # 24 hours maximum absolute lifetime from initial login

tenant_router = APIRouter(tags=["tenant"])


def get_client_ip(request: Request) -> str:
    """Extract client IP respecting X-Forwarded-For and X-Real-IP reverse proxy headers."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


# =====================================================================
# Flash Messages Helpers
# =====================================================================

def set_flash(request: Request, msg: str | None = None, error: str | None = None) -> None:
    if "session" in request.scope:
        if msg:
            request.session["flash_msg"] = msg
        if error:
            request.session["flash_error"] = error


def pop_flashes(request: Request) -> tuple[str | None, str | None]:
    msg = None
    error = None
    if "session" in request.scope:
        msg = request.session.pop("flash_msg", None)
        error = request.session.pop("flash_error", None)
    # Query parameters fallback
    if not msg:
        msg = request.query_params.get("msg")
    if not error:
        error = request.query_params.get("error")
    return msg, error


# =====================================================================
# Dependency: Tenant Authentication, Context & Inactivity Timeout
# =====================================================================

def get_tenant_context_optional(request: Request, db: Session = Depends(get_saas_db)) -> TenantContext | None:
    """Extract authenticated TenantContext from session or bearer token."""
    user_id = None
    if "session" in request.scope:
        user_id = request.session.get("tenant_user_id") or request.session.get("user_id")

    user: TenantUser | None = None
    if user_id:
        user = db.scalar(
            select(TenantUser).where(TenantUser.id == user_id, TenantUser.is_active == True)
        )

    # Bearer token fallback for testing or programmatic calls
    if not user:
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            user = db.scalar(
                select(TenantUser).where(TenantUser.id == token, TenantUser.is_active == True)
            )

    if not user:
        return None

    # Session lifecycle validation for browser sessions
    if "session" in request.scope:
        now_ts = int(datetime.now(timezone.utc).timestamp())

        # 1. Session Version check (revokes session immediately upon password change or admin revocation)
        stored_version = request.session.get("session_version")
        if stored_version is not None and stored_version != user.session_version:
            request.session.clear()
            return None

        # 2. Absolute lifetime check (max 24 hours from original login)
        login_time = request.session.get("tenant_login_time")
        if login_time and (now_ts - int(login_time) > SESSION_ABSOLUTE_LIFETIME):
            request.session.clear()
            return None

        # 3. Sliding inactivity timeout check (12 hours since last request)
        last_activity = request.session.get("tenant_last_activity")
        if last_activity and (now_ts - int(last_activity) > SESSION_INACTIVITY_TIMEOUT):
            request.session.clear()
            return None

        # Refresh sliding activity timestamp
        request.session["tenant_last_activity"] = now_ts

    # Resolve tenant
    tenant: Tenant | None = None
    if user.tenant_id:
        tenant = db.scalar(select(Tenant).where(Tenant.id == user.tenant_id))
    elif user.role == UserRole.superadmin:
        target_slug = request.session.get("target_tenant_slug")
        if target_slug:
            tenant = db.scalar(select(Tenant).where(Tenant.slug == target_slug))
        if not tenant:
            tenant = db.scalar(select(Tenant).order_by(Tenant.created_at.asc()))

    if not tenant:
        return None

    return TenantContext(tenant=tenant, user=user)


def require_tenant_context(request: Request, db: Session = Depends(get_saas_db)) -> TenantContext:
    """Dependency that strictly enforces authenticated tenant admin access."""
    context = get_tenant_context_optional(request, db)
    if not context:
        if request.headers.get("accept", "").startswith("application/json"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Tenant authentication required.",
            )
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/tenant/login?error=Session+expired.+Please+log+in+again."},
        )

    if context.tenant.status == TenantStatus.suspended:
        request.session.clear()
        if request.headers.get("accept", "").startswith("application/json"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This ISP account has been suspended.",
            )
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/tenant/login?error=account_suspended"},
        )

    return context


# =====================================================================
# Authentication Routes (with Rate Limiting & CSRF)
# =====================================================================

@tenant_router.get("/tenant/login", response_class=HTMLResponse)
def tenant_login_page(request: Request, db: Session = Depends(get_saas_db)):
    """Tenant admin login page."""
    context = get_tenant_context_optional(request, db)
    if context:
        return RedirectResponse(url="/tenant/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    msg, error = pop_flashes(request)
    csrf_token = get_csrf_token(request)

    return templates.TemplateResponse(
        request=request,
        name="tenant/login.html",
        context={"error": error, "msg": msg, "csrf_token": csrf_token},
    )


@tenant_router.post("/tenant/login", response_class=HTMLResponse, dependencies=[Depends(verify_csrf_token)])
def tenant_login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_saas_db),
):
    """Processes tenant admin login with database-backed rate limiting."""
    client_ip = get_client_ip(request)
    clean_email = email.strip().lower()

    # 1. Rate limiting check across Vercel serverless instances
    locked, remaining = is_rate_limited(db, client_ip, clean_email)
    if locked:
        minutes = max(1, remaining // 60)
        return templates.TemplateResponse(
            request=request,
            name="tenant/login.html",
            context={
                "error": f"Too many failed login attempts. Please try again in {minutes} minute(s).",
                "email": email,
                "csrf_token": get_csrf_token(request),
            },
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    # 2. Authenticate
    user = db.scalar(select(TenantUser).where(TenantUser.email == clean_email))

    if not user or not verify_password(password, user.hashed_password):
        record_failed_login(db, client_ip, clean_email)
        return templates.TemplateResponse(
            request=request,
            name="tenant/login.html",
            context={
                "error": "Invalid email or password.",
                "email": email,
                "csrf_token": get_csrf_token(request),
            },
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    if not user.is_active:
        return templates.TemplateResponse(
            request=request,
            name="tenant/login.html",
            context={
                "error": "This user account is deactivated.",
                "email": email,
                "csrf_token": get_csrf_token(request),
            },
            status_code=status.HTTP_403_FORBIDDEN,
        )

    tenant = db.scalar(select(Tenant).where(Tenant.id == user.tenant_id)) if user.tenant_id else None
    if user.role != UserRole.superadmin:
        if not tenant:
            return templates.TemplateResponse(
                request=request,
                name="tenant/login.html",
                context={
                    "error": "No ISP tenant associated with this account.",
                    "email": email,
                    "csrf_token": get_csrf_token(request),
                },
                status_code=status.HTTP_403_FORBIDDEN,
            )
        if tenant.status == TenantStatus.suspended:
            return templates.TemplateResponse(
                request=request,
                name="tenant/login.html",
                context={
                    "error": "Your ISP account has been suspended. Please contact platform support.",
                    "email": email,
                    "csrf_token": get_csrf_token(request),
                },
                status_code=status.HTTP_403_FORBIDDEN,
            )

    # Reset failed attempts on success
    clear_failed_logins(db, client_ip, clean_email)

    # Establish session
    now_ts = int(datetime.now(timezone.utc).timestamp())
    request.session["user_id"] = user.id
    request.session["tenant_user_id"] = user.id
    request.session["session_version"] = user.session_version
    request.session["tenant_login_time"] = now_ts
    request.session["tenant_last_activity"] = now_ts
    if tenant:
        request.session["tenant_id"] = tenant.id

    return RedirectResponse(url="/tenant/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@tenant_router.get("/tenant/logout")
def tenant_logout(request: Request):
    """Clears tenant session and logs out."""
    request.session.clear()
    return RedirectResponse(url="/tenant/login?msg=logged_out", status_code=status.HTTP_303_SEE_OTHER)


# =====================================================================
# Dashboard
# =====================================================================

@tenant_router.get("/tenant/dashboard", response_class=HTMLResponse)
def tenant_dashboard(
    request: Request,
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Main tenant overview displaying database-backed metrics."""
    tenant_id = context.tenant.id
    msg, error = pop_flashes(request)
    csrf_token = get_csrf_token(request)

    total_customers = db.scalar(
        select(func.count(PPPoECustomer.id)).where(PPPoECustomer.tenant_id == tenant_id)
    ) or 0
    active_customers = db.scalar(
        select(func.count(PPPoECustomer.id)).where(
            PPPoECustomer.tenant_id == tenant_id,
            PPPoECustomer.status == CustomerStatus.active,
        )
    ) or 0
    expired_customers = db.scalar(
        select(func.count(PPPoECustomer.id)).where(
            PPPoECustomer.tenant_id == tenant_id,
            PPPoECustomer.status == CustomerStatus.expired,
        )
    ) or 0

    total_routers = db.scalar(
        select(func.count(Router.id)).where(Router.tenant_id == tenant_id)
    ) or 0
    online_routers = db.scalar(
        select(func.count(Router.id)).where(
            Router.tenant_id == tenant_id,
            Router.status == RouterStatus.online,
        )
    ) or 0
    offline_routers = db.scalar(
        select(func.count(Router.id)).where(
            Router.tenant_id == tenant_id,
            Router.status == RouterStatus.offline,
        )
    ) or 0

    now = datetime.now(timezone.utc)
    month_start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    monthly_rev_query = select(func.coalesce(func.sum(CustomerPayment.amount_kes), Decimal("0.00"))).where(
        CustomerPayment.tenant_id == tenant_id,
        CustomerPayment.status == "completed",
        CustomerPayment.created_at >= month_start,
    )
    monthly_revenue = db.scalar(monthly_rev_query) or Decimal("0.00")

    recent_payments = db.scalars(
        select(CustomerPayment)
        .where(CustomerPayment.tenant_id == tenant_id)
        .order_by(CustomerPayment.created_at.desc())
        .limit(5)
    ).all()

    recent_commands = db.scalars(
        select(RouterCommand)
        .where(RouterCommand.tenant_id == tenant_id)
        .order_by(RouterCommand.created_at.desc())
        .limit(5)
    ).all()

    sub = context.tenant.subscription
    max_routers = sub.max_routers if sub else 1

    return templates.TemplateResponse(
        request=request,
        name="tenant/dashboard.html",
        context={
            "context": context,
            "tenant": context.tenant,
            "user": context.user,
            "total_customers": total_customers,
            "active_customers": active_customers,
            "expired_customers": expired_customers,
            "total_routers": total_routers,
            "online_routers": online_routers,
            "offline_routers": offline_routers,
            "monthly_revenue": monthly_revenue,
            "recent_payments": recent_payments,
            "recent_commands": recent_commands,
            "subscription": sub,
            "max_routers": max_routers,
            "msg": msg,
            "error": error,
            "csrf_token": csrf_token,
        },
    )


# =====================================================================
# Router Management & Token Rotation
# =====================================================================

def _build_mikrotik_setup_script(sync_url: str, raw_token: str, router_name: str) -> str:
    """Generate safe, RAM-only RouterOS commands compatible with RouterOS 6.49+ and RouterOS 7.x.

    Zero files are written to NAND flash storage during sync operations.
    Initial removal is safely wrapped with on-error handlers.
    Strict TLS verification is enforced (check-certificate=yes-without-crl).
    Zero bypass secrets are distributed.
    """
    return build_mikrotik_terminal_commands(sync_url, raw_token, router_name)


@tenant_router.get("/tenant/routers", response_class=HTMLResponse)
def tenant_routers_list(
    request: Request,
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Lists all tenant routers with hardware telemetry and sync statuses."""
    msg, error = pop_flashes(request)
    csrf_token = get_csrf_token(request)

    routers = db.scalars(
        select(Router)
        .where(Router.tenant_id == context.tenant.id)
        .order_by(Router.created_at.desc())
    ).all()

    sub = context.tenant.subscription
    max_routers = sub.max_routers if sub else 1
    current_count = len(routers)

    return templates.TemplateResponse(
        request=request,
        name="tenant/routers.html",
        context={
            "context": context,
            "tenant": context.tenant,
            "routers": routers,
            "current_count": current_count,
            "max_routers": max_routers,
            "can_add": current_count < max_routers,
            "msg": msg,
            "error": error,
            "csrf_token": csrf_token,
        },
    )


@tenant_router.get("/tenant/routers/add", response_class=HTMLResponse)
def tenant_routers_add_page(
    request: Request,
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Add router page displaying plan limits and enrollment form."""
    msg, error = pop_flashes(request)
    csrf_token = get_csrf_token(request)

    sub = context.tenant.subscription
    max_allowed = sub.max_routers if sub else 1
    current_count = db.scalar(
        select(func.count(Router.id)).where(Router.tenant_id == context.tenant.id)
    ) or 0

    return templates.TemplateResponse(
        request=request,
        name="tenant/router_add.html",
        context={
            "context": context,
            "tenant": context.tenant,
            "current_count": current_count,
            "max_allowed": max_allowed,
            "limit_reached": current_count >= max_allowed,
            "created_router": None,
            "enrollment_token": None,
            "sync_script": None,
            "msg": msg,
            "error": error,
            "csrf_token": csrf_token,
        },
    )


@tenant_router.post("/tenant/routers/add", response_class=HTMLResponse, dependencies=[Depends(verify_csrf_token)])
def tenant_routers_add(
    request: Request,
    name: str = Form(...),
    location: str | None = Form(None),
    description: str | None = Form(None),
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Enforces plan limit, generates one-time enrollment token and safe RouterOS terminal script."""
    csrf_token = get_csrf_token(request)
    sub = context.tenant.subscription
    max_allowed = sub.max_routers if sub else 1

    try:
        clean_name = validate_plan_name(name)
        context.assert_can_add_router(db)
    except SubscriptionLimitExceededError as exc:
        current_count = db.scalar(
            select(func.count(Router.id)).where(Router.tenant_id == context.tenant.id)
        ) or 0
        return templates.TemplateResponse(
            request=request,
            name="tenant/router_add.html",
            context={
                "context": context,
                "tenant": context.tenant,
                "current_count": current_count,
                "max_allowed": max_allowed,
                "limit_reached": current_count >= max_allowed,
                "created_router": None,
                "enrollment_token": None,
                "sync_script": None,
                "error": str(exc),
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_403_FORBIDDEN,
        )
    except CommandInjectionError as exc:
        current_count = db.scalar(
            select(func.count(Router.id)).where(Router.tenant_id == context.tenant.id)
        ) or 0
        return templates.TemplateResponse(
            request=request,
            name="tenant/router_add.html",
            context={
                "context": context,
                "tenant": context.tenant,
                "current_count": current_count,
                "max_allowed": max_allowed,
                "limit_reached": current_count >= max_allowed,
                "created_router": None,
                "enrollment_token": None,
                "sync_script": None,
                "error": str(exc),
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    raw_token = generate_secure_token(32)
    token_hashed = hash_token(raw_token)

    new_router = Router(
        tenant_id=context.tenant.id,
        name=clean_name,
        token_hash=token_hashed,
        location=location.strip() if location else None,
        description=description.strip() if description else None,
        status=RouterStatus.provisioning,
    )
    db.add(new_router)
    db.commit()
    db.refresh(new_router)

    base_url = str(request.base_url).rstrip("/")
    sync_url = f"{base_url}/api/router/sync"
    mikrotik_script = _build_mikrotik_setup_script(sync_url, raw_token, new_router.name)

    current_count = db.scalar(
        select(func.count(Router.id)).where(Router.tenant_id == context.tenant.id)
    ) or 0

    return templates.TemplateResponse(
        request=request,
        name="tenant/router_add.html",
        context={
            "context": context,
            "tenant": context.tenant,
            "current_count": current_count,
            "max_allowed": max_allowed,
            "limit_reached": current_count >= max_allowed,
            "created_router": new_router,
            "enrollment_token": raw_token,
            "sync_script": mikrotik_script,
            "error": None,
            "csrf_token": csrf_token,
        },
    )


@tenant_router.post("/tenant/routers/{router_id}/rename", dependencies=[Depends(verify_csrf_token)])
def tenant_router_rename(
    request: Request,
    router_id: str,
    name: str = Form(...),
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Renames an existing router belonging to the authenticated tenant."""
    router = db.scalar(
        select(Router).where(Router.id == router_id, Router.tenant_id == context.tenant.id)
    )
    if not router:
        raise HTTPException(status_code=404, detail="Router not found.")

    try:
        clean_name = validate_plan_name(name)
    except CommandInjectionError as e:
        set_flash(request, error=str(e))
        return RedirectResponse(url="/tenant/routers", status_code=status.HTTP_303_SEE_OTHER)

    router.name = clean_name
    db.commit()
    set_flash(request, msg=f"Router renamed to '{clean_name}'.")
    return RedirectResponse(url="/tenant/routers", status_code=status.HTTP_303_SEE_OTHER)


@tenant_router.post("/tenant/routers/{router_id}/deactivate", dependencies=[Depends(verify_csrf_token)])
def tenant_router_deactivate(
    request: Request,
    router_id: str,
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Suspends or deactivates an existing router."""
    router = db.scalar(
        select(Router).where(Router.id == router_id, Router.tenant_id == context.tenant.id)
    )
    if not router:
        raise HTTPException(status_code=404, detail="Router not found.")

    router.status = RouterStatus.suspended
    db.commit()
    set_flash(request, msg=f"Router '{router.name}' has been suspended.")
    return RedirectResponse(url="/tenant/routers", status_code=status.HTTP_303_SEE_OTHER)


@tenant_router.post("/tenant/routers/{router_id}/rotate-token", dependencies=[Depends(verify_csrf_token)])
def tenant_router_rotate_token(
    request: Request,
    router_id: str,
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Rotates the sync token for a router, invalidating old credentials."""
    router = db.scalar(
        select(Router).where(Router.id == router_id, Router.tenant_id == context.tenant.id)
    )
    if not router:
        raise HTTPException(status_code=404, detail="Router not found.")

    raw_token = generate_secure_token(32)
    router.token_hash = hash_token(raw_token)
    db.commit()

    base_url = str(request.base_url).rstrip("/")
    sync_url = f"{base_url}/api/router/sync"
    new_script = _build_mikrotik_setup_script(sync_url, raw_token, router.name)

    msg_text = f"Token for '{router.name}' rotated successfully. Update your MikroTik script."
    set_flash(request, msg=msg_text)
    return templates.TemplateResponse(
        request=request,
        name="tenant/router_add.html",
        context={
            "context": context,
            "tenant": context.tenant,
            "current_count": 1,
            "max_allowed": 1,
            "limit_reached": False,
            "created_router": router,
            "enrollment_token": raw_token,
            "sync_script": new_script,
            "msg": msg_text,
            "error": None,
            "csrf_token": get_csrf_token(request),
        },
    )


@tenant_router.post("/tenant/routers/{router_id}/download-rsc", dependencies=[Depends(verify_csrf_token)])
def tenant_router_download_rsc(
    request: Request,
    router_id: str,
    token: str | None = Form(None),
    rotate: bool = Form(False),
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Securely generates and downloads a valid RouterOS .rsc setup file for the router.

    Security Guarantees:
    1. Requires authenticated tenant session (context.tenant.id).
    2. Verifies that the requested router belongs exclusively to the authenticated tenant (404 otherwise).
    3. Enforces CSRF token verification on the state-changing POST operation.
    4. Never exposes or accepts router authentication tokens in URL query parameters.
    5. If a matching unrotated token is supplied in the POST body, it is embedded into the script.
    6. If no token is provided or rotation is requested, a fresh cryptographically secure 32-byte token
       is generated, hashed, persisted to the database, and embedded directly into the downloadable .rsc attachment.
       Previously issued tokens are permanently invalidated.
    7. Returns the file directly as an attachment ('Content-Disposition: attachment; filename="cowen_{safe_name}.rsc"').
    8. Sets strict no-cache headers to prevent proxy or browser disk caching.
    9. Zero logging of raw tokens or token hashes.
    """
    router = db.scalar(
        select(Router).where(
            Router.id == router_id,
            Router.tenant_id == context.tenant.id,
        )
    )
    if not router:
        raise HTTPException(status_code=404, detail="Router not found.")

    raw_token: str | None = None

    # If an active token was provided in the POST body, check if it matches current hash
    if token and token.strip() and not rotate:
        candidate = token.strip()
        if hash_token(candidate) == router.token_hash:
            raw_token = candidate

    # If no valid token was provided in body or rotation was requested, securely rotate and persist
    if not raw_token:
        raw_token = generate_secure_token(32)
        router.token_hash = hash_token(raw_token)
        db.commit()

    base_url = str(request.base_url).rstrip("/")
    sync_url = f"{base_url}/api/router/sync"
    rsc_content = build_mikrotik_rsc_file(sync_url, raw_token, router.name)
    safe_filename = re.sub(r"[^a-zA-Z0-9_\-]", "_", router.name)

    return Response(
        content=rsc_content,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="cowen_{safe_filename}.rsc"',
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "Pragma": "no-cache",
        },
    )


@tenant_router.get("/tenant/routers/isrgrootx1.crt")
def tenant_router_download_isrg_root_crt(request: Request):
    """Downloads the verified official ISRG Root X1 CA certificate file for WinBox upload."""
    from saas.security.sanitizer import ISRG_ROOT_X1_PEM
    raw_pem = ISRG_ROOT_X1_PEM.replace("\\r\\n", "\r\n")
    return Response(
        content=raw_pem,
        media_type="application/x-x509-ca-cert",
        headers={
            "Content-Disposition": 'attachment; filename="isrgrootx1.crt"',
            "Cache-Control": "public, max-age=86400",
        },
    )




# =====================================================================
# PPPoE Management
# =====================================================================

@tenant_router.get("/tenant/pppoe", response_class=HTMLResponse)
def tenant_pppoe_page(
    request: Request,
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Lists speed tiers and subscriber records."""
    tenant_id = context.tenant.id
    msg, error = pop_flashes(request)
    csrf_token = get_csrf_token(request)

    plans = db.scalars(
        select(PPPoEPlan)
        .where(PPPoEPlan.tenant_id == tenant_id)
        .order_by(PPPoEPlan.price_kes.asc())
    ).all()

    subscribers = db.scalars(
        select(PPPoECustomer)
        .where(PPPoECustomer.tenant_id == tenant_id)
        .order_by(PPPoECustomer.created_at.desc())
    ).all()

    routers = db.scalars(
        select(Router)
        .where(Router.tenant_id == tenant_id, Router.status != RouterStatus.suspended)
        .order_by(Router.name.asc())
    ).all()

    return templates.TemplateResponse(
        request=request,
        name="tenant/pppoe.html",
        context={
            "context": context,
            "tenant": context.tenant,
            "plans": plans,
            "subscribers": subscribers,
            "routers": routers,
            "msg": msg,
            "error": error,
            "csrf_token": csrf_token,
        },
    )


@tenant_router.post("/tenant/pppoe/plans/add", dependencies=[Depends(verify_csrf_token)])
def tenant_pppoe_plan_add(
    request: Request,
    name: str = Form(...),
    rate_limit: str = Form(...),
    price_kes: float = Form(...),
    duration_days: int = Form(30),
    marketing_speed: str | None = Form(None),
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Creates a bandwidth speed plan with strict parameter validation."""
    try:
        clean_name = validate_plan_name(name)
        clean_rate = validate_rate_limit(rate_limit)
    except CommandInjectionError as exc:
        set_flash(request, error=str(exc))
        return RedirectResponse(url="/tenant/pppoe", status_code=status.HTTP_303_SEE_OTHER)

    plan = PPPoEPlan(
        tenant_id=context.tenant.id,
        name=clean_name,
        rate_limit=clean_rate,
        price_kes=Decimal(str(price_kes)),
        duration_days=duration_days,
        marketing_speed=marketing_speed.strip() if marketing_speed else None,
        is_active=True,
    )
    db.add(plan)

    # Proactively queue PPP profile creation to all active tenant routers
    routers = db.scalars(
        select(Router).where(
            Router.tenant_id == context.tenant.id,
            Router.status != RouterStatus.suspended,
        )
    ).all()
    prof_cmd = build_pppoe_profile_command(clean_name, clean_rate)
    for r in routers:
        cmd = RouterCommand(
            tenant_id=context.tenant.id,
            router_id=r.id,
            description=f"Provision PPP profile: {clean_name}",
            script=prof_cmd,
            status=RouterCommandStatus.pending,
        )
        db.add(cmd)

    db.commit()
    set_flash(request, msg=f"Plan '{clean_name}' created successfully.")
    return RedirectResponse(url="/tenant/pppoe", status_code=status.HTTP_303_SEE_OTHER)


@tenant_router.post("/tenant/pppoe/subscribers/add", dependencies=[Depends(verify_csrf_token)])
def tenant_pppoe_subscriber_add(
    request: Request,
    router_id: str = Form(...),
    plan_id: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(...),
    phone_number: str | None = Form(None),
    email: str | None = Form(None),
    connection_type: str = Form("pppoe"),
    static_ip: str | None = Form(None),
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Creates a new PPPoE subscriber and queues safe, escaped router provisioning commands."""
    router = db.scalar(
        select(Router).where(Router.id == router_id, Router.tenant_id == context.tenant.id)
    )
    if not router or router.status == RouterStatus.suspended:
        raise HTTPException(status_code=400, detail="Invalid router selection or router is suspended.")

    plan = db.scalar(
        select(PPPoEPlan).where(PPPoEPlan.id == plan_id, PPPoEPlan.tenant_id == context.tenant.id)
    )
    if not plan:
        raise HTTPException(status_code=400, detail="Invalid plan selection.")

    # Strict input validation
    try:
        clean_username = validate_pppoe_username(username)
        clean_password = validate_password(password)
        clean_comment = full_name.strip()
    except CommandInjectionError as exc:
        set_flash(request, error=str(exc))
        return RedirectResponse(url="/tenant/pppoe", status_code=status.HTTP_303_SEE_OTHER)

    existing = db.scalar(
        select(PPPoECustomer).where(
            PPPoECustomer.tenant_id == context.tenant.id,
            PPPoECustomer.username == clean_username,
        )
    )
    if existing:
        set_flash(request, error=f"Username '{clean_username}' already exists for another subscriber.")
        return RedirectResponse(url="/tenant/pppoe", status_code=status.HTTP_303_SEE_OTHER)

    customer = PPPoECustomer(
        tenant_id=context.tenant.id,
        router_id=router.id,
        plan_id=plan.id,
        username=clean_username,
        password=clean_password,
        full_name=clean_comment,
        phone_number=phone_number.strip() if phone_number else None,
        email=email.strip() if email else None,
        connection_type=ConnectionType(connection_type),
        static_ip=static_ip.strip() if static_ip else None,
        status=CustomerStatus.active,
    )
    db.add(customer)

    # Generate safe, injection-proof, idempotent RouterOS command
    profile_script = build_pppoe_profile_command(
        name=plan.name,
        rate_limit=plan.rate_limit,
    )
    secret_script = build_pppoe_secret_command(
        username=clean_username,
        password=clean_password,
        profile=plan.name,
        service="pppoe",
        comment=clean_comment,
    )
    cmd_script = f"{profile_script}; {secret_script}"
    command = RouterCommand(
        tenant_id=context.tenant.id,
        router_id=router.id,
        description=f"Provision PPPoE user: {clean_username} ({plan.name})",
        script=cmd_script,
        status=RouterCommandStatus.pending,
    )
    db.add(command)

    db.commit()
    set_flash(request, msg=f"Subscriber '{clean_username}' created and queued for router sync.")
    return RedirectResponse(url="/tenant/pppoe", status_code=status.HTTP_303_SEE_OTHER)


@tenant_router.post("/tenant/pppoe/subscribers/{subscriber_id}/toggle-status", dependencies=[Depends(verify_csrf_token)])
def tenant_pppoe_subscriber_toggle_status(
    request: Request,
    subscriber_id: str,
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Toggles subscriber between active and suspended state and queues router command to enable/disable and kick sessions."""
    sub = db.scalar(
        select(PPPoECustomer).where(
            PPPoECustomer.id == subscriber_id,
            PPPoECustomer.tenant_id == context.tenant.id,
        )
    )
    if not sub:
        raise HTTPException(status_code=404, detail="Subscriber not found.")

    if sub.status == CustomerStatus.active:
        sub.status = CustomerStatus.suspended
        new_state_label = "suspended"
        script = build_pppoe_disable_command(sub.username)
        desc = f"Suspend PPPoE subscriber: {sub.username}"
    else:
        sub.status = CustomerStatus.active
        new_state_label = "activated"
        script = build_pppoe_enable_command(sub.username)
        desc = f"Activate PPPoE subscriber: {sub.username}"

    if sub.router_id:
        cmd = RouterCommand(
            tenant_id=context.tenant.id,
            router_id=sub.router_id,
            description=desc,
            script=script,
            status=RouterCommandStatus.pending,
        )
        db.add(cmd)

    db.commit()
    set_flash(request, msg=f"Subscriber '{sub.username}' {new_state_label} and sync command queued.")
    return RedirectResponse(url="/tenant/pppoe", status_code=status.HTTP_303_SEE_OTHER)


@tenant_router.post("/tenant/pppoe/subscribers/{subscriber_id}/delete", dependencies=[Depends(verify_csrf_token)])
def tenant_pppoe_subscriber_delete(
    request: Request,
    subscriber_id: str,
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Deletes subscriber and queues router removal command."""
    sub = db.scalar(
        select(PPPoECustomer).where(
            PPPoECustomer.id == subscriber_id,
            PPPoECustomer.tenant_id == context.tenant.id,
        )
    )
    if not sub:
        raise HTTPException(status_code=404, detail="Subscriber not found.")

    username = sub.username
    router_id = sub.router_id

    if router_id:
        cmd = RouterCommand(
            tenant_id=context.tenant.id,
            router_id=router_id,
            description=f"Remove PPPoE secret: {username}",
            script=build_pppoe_delete_command(username),
            status=RouterCommandStatus.pending,
        )
        db.add(cmd)

    db.delete(sub)
    db.commit()
    set_flash(request, msg=f"Subscriber '{username}' deleted and removed from router.")
    return RedirectResponse(url="/tenant/pppoe", status_code=status.HTTP_303_SEE_OTHER)


# =====================================================================
# Hotspot Management & Voucher Generation (CRIT-02 Fixed)
# =====================================================================

@tenant_router.get("/tenant/hotspot", response_class=HTMLResponse)
def tenant_hotspot_page(
    request: Request,
    batch_filter: str | None = None,
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Hotspot packages, voucher batch creation, and captive portal theme editor."""
    tenant_id = context.tenant.id
    msg, error = pop_flashes(request)
    csrf_token = get_csrf_token(request)

    packages = db.scalars(
        select(HotspotPackage)
        .where(HotspotPackage.tenant_id == tenant_id)
        .order_by(HotspotPackage.price_kes.asc())
    ).all()

    voucher_query = select(HotspotVoucher).where(HotspotVoucher.tenant_id == tenant_id)
    if batch_filter:
        voucher_query = voucher_query.where(HotspotVoucher.batch_id == batch_filter)
    vouchers = db.scalars(voucher_query.order_by(HotspotVoucher.created_at.desc()).limit(100)).all()

    routers = db.scalars(
        select(Router)
        .where(Router.tenant_id == tenant_id, Router.status != RouterStatus.suspended)
        .order_by(Router.name.asc())
    ).all()

    portal = db.scalar(
        select(HotspotPortalDesign).where(HotspotPortalDesign.tenant_id == tenant_id)
    )
    if not portal:
        portal = HotspotPortalDesign(
            tenant_id=tenant_id,
            brand_name=context.tenant.name,
            headline="Welcome to High-Speed WiFi",
            primary_color="#dfb758",
            secondary_color="#090a0f",
            accent_color="#b8913e",
        )
        db.add(portal)
        db.commit()
        db.refresh(portal)

    return templates.TemplateResponse(
        request=request,
        name="tenant/hotspot.html",
        context={
            "context": context,
            "tenant": context.tenant,
            "packages": packages,
            "vouchers": vouchers,
            "routers": routers,
            "portal": portal,
            "batch_filter": batch_filter,
            "msg": msg,
            "error": error,
            "csrf_token": csrf_token,
        },
    )


@tenant_router.post("/tenant/hotspot/packages/add", dependencies=[Depends(verify_csrf_token)])
def tenant_hotspot_package_add(
    request: Request,
    name: str = Form(...),
    price_kes: float = Form(...),
    duration_minutes: int = Form(...),
    rate_limit: str = Form("5M/10M"),
    data_limit_mb: int | None = Form(None),
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Creates a Hotspot pricing package with parameter validation."""
    try:
        clean_name = validate_package_name(name)
        clean_rate = validate_rate_limit(rate_limit)
    except CommandInjectionError as exc:
        set_flash(request, error=str(exc))
        return RedirectResponse(url="/tenant/hotspot", status_code=status.HTTP_303_SEE_OTHER)

    pkg = HotspotPackage(
        tenant_id=context.tenant.id,
        name=clean_name,
        price_kes=Decimal(str(price_kes)),
        duration_minutes=duration_minutes,
        rate_limit=clean_rate,
        data_limit_mb=data_limit_mb,
        is_active=True,
    )
    db.add(pkg)

    # Proactively queue safe Hotspot profile creation to all active tenant routers
    routers = db.scalars(
        select(Router).where(
            Router.tenant_id == context.tenant.id,
            Router.status != RouterStatus.suspended,
        )
    ).all()
    prof_cmd = build_hotspot_profile_command(clean_name, clean_rate)
    for r in routers:
        cmd = RouterCommand(
            tenant_id=context.tenant.id,
            router_id=r.id,
            description=f"Provision Hotspot profile: {clean_name}",
            script=prof_cmd,
            status=RouterCommandStatus.pending,
        )
        db.add(cmd)

    db.commit()
    set_flash(request, msg=f"Package '{clean_name}' created successfully.")
    return RedirectResponse(url="/tenant/hotspot", status_code=status.HTTP_303_SEE_OTHER)


@tenant_router.post("/tenant/hotspot/vouchers/generate", dependencies=[Depends(verify_csrf_token)])
def tenant_hotspot_vouchers_generate(
    request: Request,
    package_id: str = Form(...),
    quantity: int = Form(...),
    router_id: str | None = Form(None),
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Generates a batch of unique Hotspot voucher codes with strict router ownership validation."""
    pkg = db.scalar(
        select(HotspotPackage).where(
            HotspotPackage.id == package_id,
            HotspotPackage.tenant_id == context.tenant.id,
        )
    )
    if not pkg:
        raise HTTPException(status_code=400, detail="Invalid package selection.")

    # CRIT-02 FIX: Strict router ownership validation
    target_router = None
    if router_id and router_id.strip():
        target_router = db.scalar(
            select(Router).where(
                Router.id == router_id.strip(),
                Router.tenant_id == context.tenant.id,
            )
        )
        if not target_router or target_router.status == RouterStatus.suspended:
            raise HTTPException(
                status_code=400,
                detail="Invalid router selection: router does not belong to your account or is suspended.",
            )

    qty = max(1, min(quantity, 200))
    batch_id = uuid.uuid4().hex[:10].upper()

    commands_to_queue = []
    for _ in range(qty):
        charset = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
        code = "".join(secrets.choice(charset) for _ in range(6))

        voucher = HotspotVoucher(
            tenant_id=context.tenant.id,
            package_id=pkg.id,
            router_id=target_router.id if target_router else None,
            code=code,
            batch_id=batch_id,
            status=VoucherStatus.unused,
        )
        db.add(voucher)

        if target_router:
            cmd = build_hotspot_user_command(
                code=code,
                password=code,
                profile=pkg.name,
                comment=f"Batch {batch_id}",
            )
            commands_to_queue.append(cmd)

    if target_router and commands_to_queue:
        profile_cmd = build_hotspot_profile_command(pkg.name, pkg.rate_limit)
        chunk_size = 5
        total_chunks = (len(commands_to_queue) + chunk_size - 1) // chunk_size
        for chunk_idx, i in enumerate(range(0, len(commands_to_queue), chunk_size), 1):
            chunk = commands_to_queue[i : i + chunk_size]
            chunk_script = f"{profile_cmd};\n" + ";\n".join(chunk)
            cmd_record = RouterCommand(
                tenant_id=context.tenant.id,
                router_id=target_router.id,
                description=f"Batch {batch_id} (chunk {chunk_idx}/{total_chunks}): Add {len(chunk)} hotspot vouchers",
                script=chunk_script,
                status=RouterCommandStatus.pending,
            )
            db.add(cmd_record)

    db.commit()
    set_flash(request, msg=f"Successfully generated {qty} vouchers (Batch {batch_id}).")
    return RedirectResponse(
        url=f"/tenant/hotspot?batch_filter={batch_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@tenant_router.post("/tenant/hotspot/portal/save", dependencies=[Depends(verify_csrf_token)])
def tenant_hotspot_portal_save(
    request: Request,
    brand_name: str = Form(...),
    headline: str = Form("Welcome to High-Speed WiFi"),
    primary_color: str = Form("#dfb758"),
    secondary_color: str = Form("#090a0f"),
    accent_color: str = Form("#b8913e"),
    logo_url: str | None = Form(None),
    banner_html: str | None = Form(None),
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Saves captive portal branding customizations."""
    portal = db.scalar(
        select(HotspotPortalDesign).where(HotspotPortalDesign.tenant_id == context.tenant.id)
    )
    if not portal:
        portal = HotspotPortalDesign(tenant_id=context.tenant.id)
        db.add(portal)

    portal.brand_name = brand_name.strip()
    portal.headline = headline.strip()
    portal.primary_color = primary_color.strip()
    portal.secondary_color = secondary_color.strip()
    portal.accent_color = accent_color.strip()
    portal.logo_url = logo_url.strip() if logo_url else None
    portal.banner_html = banner_html.strip() if banner_html else None
    portal.version += 1

    db.commit()
    set_flash(request, msg="Captive portal branding updated successfully.")
    return RedirectResponse(url="/tenant/hotspot", status_code=status.HTTP_303_SEE_OTHER)


# =====================================================================
# Payments & Gateway Configuration
# =====================================================================

@tenant_router.get("/tenant/payments", response_class=HTMLResponse)
def tenant_payments_page(
    request: Request,
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """M-Pesa and Paystack credentials management, plus customer payments ledger."""
    tenant_id = context.tenant.id
    msg, error = pop_flashes(request)
    csrf_token = get_csrf_token(request)

    config = db.scalar(
        select(TenantPaymentConfig).where(TenantPaymentConfig.tenant_id == tenant_id)
    )

    payments = db.scalars(
        select(CustomerPayment)
        .where(CustomerPayment.tenant_id == tenant_id)
        .order_by(CustomerPayment.created_at.desc())
        .limit(100)
    ).all()

    mpesa_creds = config.get_mpesa_credentials() if config else {}
    has_mpesa = bool(config and config.mpesa_enabled and mpesa_creds.get("consumer_key"))
    has_paystack = bool(config and config.paystack_enabled and config.get_paystack_secret())

    return templates.TemplateResponse(
        request=request,
        name="tenant/payments.html",
        context={
            "context": context,
            "tenant": context.tenant,
            "config": config,
            "payments": payments,
            "has_mpesa": has_mpesa,
            "has_paystack": has_paystack,
            "msg": msg,
            "error": error,
            "csrf_token": csrf_token,
        },
    )


@tenant_router.post("/tenant/payments/mpesa", dependencies=[Depends(verify_csrf_token)])
def tenant_payments_mpesa_save(
    request: Request,
    mpesa_type: str = Form("paybill"),
    shortcode: str = Form(...),
    consumer_key: str = Form(...),
    consumer_secret: str = Form(...),
    passkey: str = Form(...),
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Encrypts and stores tenant M-Pesa Daraja credentials."""
    config = db.scalar(
        select(TenantPaymentConfig).where(TenantPaymentConfig.tenant_id == context.tenant.id)
    )
    if not config:
        config = TenantPaymentConfig(tenant_id=context.tenant.id)
        db.add(config)

    config.mpesa_enabled = True
    config.mpesa_type = mpesa_type.strip()
    config.mpesa_shortcode = shortcode.strip()
    config.set_mpesa_credentials(
        consumer_key=consumer_key.strip(),
        consumer_secret=consumer_secret.strip(),
        passkey=passkey.strip(),
    )
    db.commit()

    set_flash(request, msg="M-Pesa Daraja credentials encrypted and saved.")
    return RedirectResponse(url="/tenant/payments", status_code=status.HTTP_303_SEE_OTHER)


@tenant_router.post("/tenant/payments/paystack", dependencies=[Depends(verify_csrf_token)])
def tenant_payments_paystack_save(
    request: Request,
    public_key: str = Form(...),
    secret_key: str = Form(...),
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Encrypts and stores tenant Paystack credentials."""
    config = db.scalar(
        select(TenantPaymentConfig).where(TenantPaymentConfig.tenant_id == context.tenant.id)
    )
    if not config:
        config = TenantPaymentConfig(tenant_id=context.tenant.id)
        db.add(config)

    config.paystack_enabled = True
    config.paystack_public_key = public_key.strip()
    config.set_paystack_secret(secret_key.strip())
    db.commit()

    set_flash(request, msg="Paystack credentials encrypted and saved.")
    return RedirectResponse(url="/tenant/payments", status_code=status.HTTP_303_SEE_OTHER)


# =====================================================================
# Financial Reports
# =====================================================================

@tenant_router.get("/tenant/reports", response_class=HTMLResponse)
def tenant_reports_page(
    request: Request,
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Financial reports strictly restricted to customer payments for this ISP."""
    tenant_id = context.tenant.id
    msg, error = pop_flashes(request)
    csrf_token = get_csrf_token(request)

    all_time_rev = db.scalar(
        select(func.coalesce(func.sum(CustomerPayment.amount_kes), Decimal("0.00"))).where(
            CustomerPayment.tenant_id == tenant_id,
            CustomerPayment.status == "completed",
        )
    ) or Decimal("0.00")

    now = datetime.now(timezone.utc)
    month_start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    this_month_rev = db.scalar(
        select(func.coalesce(func.sum(CustomerPayment.amount_kes), Decimal("0.00"))).where(
            CustomerPayment.tenant_id == tenant_id,
            CustomerPayment.status == "completed",
            CustomerPayment.created_at >= month_start,
        )
    ) or Decimal("0.00")

    gateway_rows = db.execute(
        select(
            CustomerPayment.gateway,
            func.count(CustomerPayment.id),
            func.coalesce(func.sum(CustomerPayment.amount_kes), Decimal("0.00")),
        )
        .where(CustomerPayment.tenant_id == tenant_id, CustomerPayment.status == "completed")
        .group_by(CustomerPayment.gateway)
    ).all()
    gateway_breakdown = [
        {"gateway": row[0], "count": row[1], "total": row[2]} for row in gateway_rows
    ]

    pppoe_total = db.scalar(
        select(func.coalesce(func.sum(CustomerPayment.amount_kes), Decimal("0.00"))).where(
            CustomerPayment.tenant_id == tenant_id,
            CustomerPayment.customer_id.is_not(None),
            CustomerPayment.status == "completed",
        )
    ) or Decimal("0.00")

    hotspot_total = db.scalar(
        select(func.coalesce(func.sum(CustomerPayment.amount_kes), Decimal("0.00"))).where(
            CustomerPayment.tenant_id == tenant_id,
            CustomerPayment.voucher_id.is_not(None),
            CustomerPayment.status == "completed",
        )
    ) or Decimal("0.00")

    recent_transactions = db.scalars(
        select(CustomerPayment)
        .where(CustomerPayment.tenant_id == tenant_id)
        .order_by(CustomerPayment.created_at.desc())
        .limit(20)
    ).all()

    return templates.TemplateResponse(
        request=request,
        name="tenant/reports.html",
        context={
            "context": context,
            "tenant": context.tenant,
            "all_time_revenue": all_time_rev,
            "this_month_revenue": this_month_rev,
            "gateway_breakdown": gateway_breakdown,
            "pppoe_total": pppoe_total,
            "hotspot_total": hotspot_total,
            "recent_transactions": recent_transactions,
            "msg": msg,
            "error": error,
            "csrf_token": csrf_token,
        },
    )


# =====================================================================
# Settings & White-Label Branding
# =====================================================================

@tenant_router.get("/tenant/settings", response_class=HTMLResponse)
def tenant_settings_page(
    request: Request,
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Company profile, custom branding, and administrator security."""
    msg, error = pop_flashes(request)
    csrf_token = get_csrf_token(request)

    branding = context.tenant.branding
    if not branding:
        branding = TenantBranding(tenant_id=context.tenant.id)
        db.add(branding)
        db.commit()
        db.refresh(branding)

    return templates.TemplateResponse(
        request=request,
        name="tenant/settings.html",
        context={
            "context": context,
            "tenant": context.tenant,
            "user": context.user,
            "branding": branding,
            "subscription": context.tenant.subscription,
            "msg": msg,
            "error": error,
            "csrf_token": csrf_token,
        },
    )


@tenant_router.post("/tenant/settings/company", dependencies=[Depends(verify_csrf_token)])
def tenant_settings_company_save(
    request: Request,
    name: str = Form(...),
    contact_email: str = Form(...),
    contact_phone: str = Form(...),
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Updates company profile information."""
    context.tenant.name = name.strip()
    context.tenant.contact_email = contact_email.strip()
    context.tenant.contact_phone = contact_phone.strip()
    db.commit()
    set_flash(request, msg="Company details updated successfully.")
    return RedirectResponse(url="/tenant/settings", status_code=status.HTTP_303_SEE_OTHER)


@tenant_router.post("/tenant/settings/branding", dependencies=[Depends(verify_csrf_token)])
def tenant_settings_branding_save(
    request: Request,
    company_title: str = Form("ISP Billing"),
    logo_url: str | None = Form(None),
    primary_color: str = Form("#dfb758"),
    secondary_color: str = Form("#090a0f"),
    accent_color: str = Form("#b8913e"),
    support_phone: str | None = Form(None),
    support_email: str | None = Form(None),
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Updates white-label branding styles and contact information."""
    branding = context.tenant.branding
    if not branding:
        branding = TenantBranding(tenant_id=context.tenant.id)
        db.add(branding)

    branding.company_title = company_title.strip()
    branding.logo_url = logo_url.strip() if logo_url else None
    branding.primary_color = primary_color.strip()
    branding.secondary_color = secondary_color.strip()
    branding.accent_color = accent_color.strip()
    branding.support_phone = support_phone.strip() if support_phone else None
    branding.support_email = support_email.strip() if support_email else None

    db.commit()
    set_flash(request, msg="White-label branding updated.")
    return RedirectResponse(url="/tenant/settings", status_code=status.HTTP_303_SEE_OTHER)


@tenant_router.post("/tenant/settings/password", dependencies=[Depends(verify_csrf_token)])
def tenant_settings_password_save(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Updates administrator password with current password verification."""
    if not verify_password(current_password, context.user.hashed_password):
        set_flash(request, error="Incorrect current password.")
        return RedirectResponse(url="/tenant/settings", status_code=status.HTTP_303_SEE_OTHER)

    if new_password != confirm_password:
        set_flash(request, error="New passwords do not match.")
        return RedirectResponse(url="/tenant/settings", status_code=status.HTTP_303_SEE_OTHER)

    if len(new_password) < 8:
        set_flash(request, error="Password must be at least 8 characters.")
        return RedirectResponse(url="/tenant/settings", status_code=status.HTTP_303_SEE_OTHER)

    context.user.hashed_password = hash_password(new_password)
    context.user.session_version += 1
    db.commit()

    # Update active browser session version so current session remains authenticated
    # while all other concurrent devices and stolen sessions are immediately invalidated
    if "session" in request.scope:
        request.session["session_version"] = context.user.session_version

    set_flash(request, msg="Password updated successfully. Other active sessions have been revoked.")
    return RedirectResponse(url="/tenant/settings", status_code=status.HTTP_303_SEE_OTHER)


# =====================================================================
# Router Outbound Synchronization API (RAM-only execution)
# =====================================================================

def render_router_batch(batch: list[RouterCommand], ack_url: str, raw_token: str) -> str:
    """Renders a batch of RouterOS commands with magic verification header, per-command error handling and ack callback."""
    if not batch:
        return ""

    lines = ["# COwen-Batch-OK", ':local ok ""', ':local failed ""']
    for cmd in batch:
        # Wrap each command safely so a failure in one command does not halt the others
        clean_script = cmd.script.strip().rstrip(";")
        lines.append(
            f":do {{{clean_script}; :set ok ($ok . \"{cmd.id},\")}} "
            f"on-error={{:set failed ($failed . \"{cmd.id},\"); :log warning \"COwen_Sync: command {cmd.id} failed\"}}"
        )

    q_ack_url = quote_routeros(ack_url)
    clean_token = raw_token.strip().replace('"', '').replace('\\', '').replace('$', '')
    header_str = f"Content-Type: application/x-www-form-urlencoded,X-Router-Token: {clean_token}"
    q_ack_header = quote_routeros(header_str)

    lines.append(
        f":local ackData (\"ok=\" . $ok . \"&failed=\" . $failed);\n"
        f":do {{/tool fetch url={q_ack_url} http-method=post "
        f"http-header-field={q_ack_header} "
        f"http-data=$ackData check-certificate=yes-without-crl output=none;\n"
        f":log info \"COwen_Sync: batch commands executed and acknowledged\";}} "
        f"on-error={{:log warning \"COwen_Sync: could not report results\"}}"
    )
    return "\n".join(lines) + "\n"


@tenant_router.post("/api/router/sync")
async def router_sync_endpoint(
    request: Request,
    x_router_token: str | None = Header(None),
    db: Session = Depends(get_saas_db),
):
    """Outbound HTTPS Polling API for MikroTik routers.

    Receives telemetry and returns executable RouterOS script text in RAM.
    """
    if not x_router_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Router-Token header.",
        )

    token_hash = hash_token(x_router_token.strip())
    router = db.scalar(select(Router).where(Router.token_hash == token_hash))

    if not router:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid router enrollment token.",
        )

    if router.status == RouterStatus.suspended:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Router is deactivated or suspended.",
        )

    # Parse telemetry payload (supports JSON or form-encoded from /tool fetch)
    body: dict[str, Any] = {}
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
        except Exception:
            body = {}
    else:
        try:
            form = await request.form()
            body = dict(form)
        except Exception:
            body = {}

    router.last_seen_at = datetime.now(timezone.utc)
    router.status = RouterStatus.online
    if body.get("version"):
        router.version = str(body["version"])[:64]
    if body.get("board"):
        router.board = str(body["board"])[:64]
    if body.get("uptime"):
        router.uptime = str(body["uptime"])[:32]
    if body.get("cpu_load") is not None or body.get("cpu") is not None:
        raw_cpu = body.get("cpu_load", body.get("cpu"))
        try:
            router.cpu_load = int(raw_cpu)
        except (ValueError, TypeError):
            pass

    client_host = request.client.host if request.client else None
    if client_host:
        router.ip_address = client_host

    now_ts = datetime.now(timezone.utc)
    retry_timeout_seconds = 120
    max_attempts = 3

    # Mark timed-out sent commands that exceeded max_attempts as failed
    timed_out_commands = db.scalars(
        select(RouterCommand).where(
            RouterCommand.router_id == router.id,
            RouterCommand.tenant_id == router.tenant_id,
            RouterCommand.status == RouterCommandStatus.sent,
            RouterCommand.attempts >= max_attempts,
            RouterCommand.sent_at <= now_ts - timedelta(seconds=retry_timeout_seconds),
        )
    ).all()
    for f_cmd in timed_out_commands:
        f_cmd.status = RouterCommandStatus.failed
        f_cmd.finished_at = now_ts

    # Fetch queued pending commands OR retryable sent commands
    candidate_commands = db.scalars(
        select(RouterCommand)
        .where(
            RouterCommand.router_id == router.id,
            RouterCommand.tenant_id == router.tenant_id,
            or_(
                RouterCommand.status == RouterCommandStatus.pending,
                and_(
                    RouterCommand.status == RouterCommandStatus.sent,
                    RouterCommand.attempts < max_attempts,
                    RouterCommand.sent_at <= now_ts - timedelta(seconds=retry_timeout_seconds),
                ),
            ),
        )
        .order_by(RouterCommand.created_at.asc())
        .limit(20)
    ).all()

    # Determine batch size limit based on RouterOS version
    is_ros7 = (router.version or "").startswith("7")
    limit_bytes = BATCH_BYTES_ROS7 if is_ros7 else BATCH_BYTES_ROS6

    batch: list[RouterCommand] = []
    total_size = 0
    for cmd in candidate_commands:
        cost = len(cmd.script) + 120
        if batch and (total_size + cost > limit_bytes):
            break
        cmd.status = RouterCommandStatus.sent
        cmd.sent_at = now_ts
        cmd.attempts += 1
        batch.append(cmd)
        total_size += cost

    db.commit()

    # Return format negotiation:
    # Programmatic API clients requesting JSON receive structured JSON
    # MikroTik routers receive plain text RouterOS script executed directly in RAM via :parse
    accept_header = request.headers.get("accept", "")
    if "application/json" in accept_header:
        return {
            "status": "ok",
            "router_id": router.id,
            "router_name": router.name,
            "server_time": now_ts.isoformat(),
            "commands": [
                {"id": c.id, "description": c.description, "script": c.script} for c in batch
            ],
        }

    base_url = str(request.base_url).rstrip("/")
    ack_url = f"{base_url}/api/router/ack"
    script_text = render_router_batch(batch, ack_url, x_router_token.strip())
    return PlainTextResponse(content=script_text, media_type="text/plain")


@tenant_router.post("/api/router/ack")
async def router_ack_endpoint(
    request: Request,
    x_router_token: str | None = Header(None),
    db: Session = Depends(get_saas_db),
):
    """Receives acknowledgement of executed command batches."""
    if not x_router_token:
        raise HTTPException(status_code=401, detail="Missing X-Router-Token header.")

    token_hash = hash_token(x_router_token.strip())
    router = db.scalar(select(Router).where(Router.token_hash == token_hash))
    if not router:
        raise HTTPException(status_code=401, detail="Invalid router token.")

    # Parse ok and failed command IDs
    form = await request.form()
    ok_str = str(form.get("ok", ""))
    failed_str = str(form.get("failed", ""))

    now_ts = datetime.now(timezone.utc)
    ok_ids = [part.strip() for part in ok_str.split(",") if part.strip()]
    failed_ids = [part.strip() for part in failed_str.split(",") if part.strip()]

    if ok_ids:
        cmds_ok = db.scalars(
            select(RouterCommand).where(
                RouterCommand.id.in_(ok_ids),
                RouterCommand.router_id == router.id,
                RouterCommand.tenant_id == router.tenant_id,
            )
        ).all()
        for cmd in cmds_ok:
            cmd.status = RouterCommandStatus.done
            cmd.finished_at = now_ts

    if failed_ids:
        cmds_failed = db.scalars(
            select(RouterCommand).where(
                RouterCommand.id.in_(failed_ids),
                RouterCommand.router_id == router.id,
                RouterCommand.tenant_id == router.tenant_id,
            )
        ).all()
        for cmd in cmds_failed:
            cmd.status = RouterCommandStatus.failed
            cmd.finished_at = now_ts

    db.commit()
    return {"status": "recorded", "acknowledged_ok": len(ok_ids), "acknowledged_failed": len(failed_ids)}


@tenant_router.post("/api/router/command-result")
async def router_command_result_endpoint(
    request: Request,
    x_router_token: str | None = Header(None),
    db: Session = Depends(get_saas_db),
):
    """Reports back the execution output/result of a single router command."""
    if not x_router_token:
        raise HTTPException(status_code=401, detail="Missing X-Router-Token header.")

    token_hash = hash_token(x_router_token.strip())
    router = db.scalar(select(Router).where(Router.token_hash == token_hash))
    if not router:
        raise HTTPException(status_code=401, detail="Invalid router token.")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body.")

    cmd_id = body.get("command_id")
    cmd_status = body.get("status")

    if not cmd_id or not cmd_status:
        raise HTTPException(status_code=400, detail="Missing command_id or status.")

    cmd = db.scalar(
        select(RouterCommand).where(RouterCommand.id == cmd_id, RouterCommand.router_id == router.id)
    )
    if not cmd:
        raise HTTPException(status_code=404, detail="Command not found.")

    cmd.status = RouterCommandStatus.done if cmd_status == "done" else RouterCommandStatus.failed
    cmd.finished_at = datetime.now(timezone.utc)
    db.commit()


@tenant_router.post("/tenant/routers/commands/{command_id}/retry", dependencies=[Depends(verify_csrf_token)])
def tenant_router_command_retry(
    command_id: str,
    request: Request,
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Retries a failed router command by resetting it to pending status."""
    cmd = db.scalar(
        select(RouterCommand).where(
            RouterCommand.id == command_id,
            RouterCommand.tenant_id == context.tenant.id,
        )
    )
    if not cmd:
        raise HTTPException(status_code=404, detail="Command not found.")

    cmd.status = RouterCommandStatus.pending
    cmd.attempts = 0
    cmd.sent_at = None
    cmd.finished_at = None
    db.commit()

    set_flash(request, msg=f"Command '{cmd.description}' re-queued for synchronization.")
    return RedirectResponse(url="/tenant/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    return {"status": "recorded", "command_id": cmd.id, "command_status": cmd.status.value}
