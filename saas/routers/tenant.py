"""Tenant Admin Portal routes, management views, and MikroTik router sync APIs."""
from __future__ import annotations

import logging
import secrets
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_, select
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

logger = logging.getLogger("saas.tenant")

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

tenant_router = APIRouter(tags=["tenant"])


# =====================================================================
# Dependency: Tenant Authentication & Context Enforcement
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

    # Resolve tenant
    tenant: Tenant | None = None
    if user.tenant_id:
        tenant = db.scalar(select(Tenant).where(Tenant.id == user.tenant_id))
    elif user.role == UserRole.superadmin:
        # Superadmin accessing tenant portal can target first active tenant or by session
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
        # Web browser redirect to login
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/tenant/login"},
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
# Authentication Routes
# =====================================================================

@tenant_router.get("/tenant/login", response_class=HTMLResponse)
def tenant_login_page(request: Request, error: str | None = None, msg: str | None = None, db: Session = Depends(get_saas_db)):
    """Tenant admin login page."""
    # Check if already authenticated
    context = get_tenant_context_optional(request, db)
    if context:
        return RedirectResponse(url="/tenant/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    return templates.TemplateResponse(
        request=request,
        name="tenant/login.html",
        context={"error": error, "msg": msg},
    )


@tenant_router.post("/tenant/login", response_class=HTMLResponse)
def tenant_login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_saas_db),
):
    """Processes tenant admin login."""
    clean_email = email.strip().lower()
    user = db.scalar(select(TenantUser).where(TenantUser.email == clean_email))

    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(
            request=request,
            name="tenant/login.html",
            context={"error": "Invalid email or password.", "email": email},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    if not user.is_active:
        return templates.TemplateResponse(
            request=request,
            name="tenant/login.html",
            context={"error": "This user account is deactivated.", "email": email},
            status_code=status.HTTP_403_FORBIDDEN,
        )

    # Check tenant account status
    tenant = db.scalar(select(Tenant).where(Tenant.id == user.tenant_id)) if user.tenant_id else None
    if user.role != UserRole.superadmin:
        if not tenant:
            return templates.TemplateResponse(
                request=request,
                name="tenant/login.html",
                context={"error": "No ISP tenant associated with this account.", "email": email},
                status_code=status.HTTP_403_FORBIDDEN,
            )
        if tenant.status == TenantStatus.suspended:
            return templates.TemplateResponse(
                request=request,
                name="tenant/login.html",
                context={"error": "Your ISP account has been suspended. Please contact platform support.", "email": email},
                status_code=status.HTTP_403_FORBIDDEN,
            )

    # Establish session
    request.session["user_id"] = user.id
    request.session["tenant_user_id"] = user.id
    if tenant:
        request.session["tenant_id"] = tenant.id

    return RedirectResponse(url="/tenant/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@tenant_router.get("/tenant/logout")
def tenant_logout(request: Request):
    """Clears tenant session and logs out."""
    request.session.pop("user_id", None)
    request.session.pop("tenant_user_id", None)
    request.session.pop("tenant_id", None)
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
    """
    Main tenant overview.
    Queries database metrics: subscribers, routers, revenue, recent payments, recent activity.
    Never fabricates metrics. Empty states handled cleanly.
    """
    tenant_id = context.tenant.id

    # 1. Subscribers Metrics
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

    # 2. Routers Metrics
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

    # 3. Monthly Revenue from Customer Payments
    now = datetime.now(timezone.utc)
    month_start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    monthly_rev_query = select(func.coalesce(func.sum(CustomerPayment.amount_kes), Decimal("0.00"))).where(
        CustomerPayment.tenant_id == tenant_id,
        CustomerPayment.status == "completed",
        CustomerPayment.created_at >= month_start,
    )
    monthly_revenue = db.scalar(monthly_rev_query) or Decimal("0.00")

    # 4. Recent Payments (Last 5)
    recent_payments = db.scalars(
        select(CustomerPayment)
        .where(CustomerPayment.tenant_id == tenant_id)
        .order_by(CustomerPayment.created_at.desc())
        .limit(5)
    ).all()

    # 5. Recent Commands / Activity (Last 5)
    recent_commands = db.scalars(
        select(RouterCommand)
        .where(RouterCommand.tenant_id == tenant_id)
        .order_by(RouterCommand.created_at.desc())
        .limit(5)
    ).all()

    # 6. Subscription Info
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
        },
    )


# =====================================================================
# Router Management
# =====================================================================

@tenant_router.get("/tenant/routers", response_class=HTMLResponse)
def tenant_routers_list(
    request: Request,
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Lists all tenant routers with hardware telemetry and sync statuses."""
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
        },
    )


@tenant_router.get("/tenant/routers/add", response_class=HTMLResponse)
def tenant_routers_add_page(
    request: Request,
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Add router page displaying plan limits and enrollment form."""
    sub = context.tenant.subscription
    max_allowed = sub.max_routers if sub else 1
    current_count = db.scalar(
        select(func.count(Router.id)).where(Router.tenant_id == context.tenant.id)
    ) or 0

    limit_reached = current_count >= max_allowed

    return templates.TemplateResponse(
        request=request,
        name="tenant/router_add.html",
        context={
            "context": context,
            "tenant": context.tenant,
            "current_count": current_count,
            "max_allowed": max_allowed,
            "limit_reached": limit_reached,
            "enrollment_token": None,
            "sync_script": None,
            "error": None,
        },
    )


@tenant_router.post("/tenant/routers/add", response_class=HTMLResponse)
def tenant_routers_add(
    request: Request,
    name: str = Form(...),
    location: str | None = Form(None),
    description: str | None = Form(None),
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Enforces plan limit, generates one-time enrollment token and MikroTik terminal script."""
    try:
        context.assert_can_add_router(db)
    except SubscriptionLimitExceededError as exc:
        return templates.TemplateResponse(
            request=request,
            name="tenant/router_add.html",
            context={
                "context": context,
                "tenant": context.tenant,
                "current_count": exc.current_count,
                "max_allowed": exc.max_limit,
                "limit_reached": True,
                "enrollment_token": None,
                "sync_script": None,
                "error": str(exc),
            },
            status_code=status.HTTP_403_FORBIDDEN,
        )

    # Generate one-time cryptographically secure random token
    raw_token = generate_secure_token(32)
    token_hashed = hash_token(raw_token)

    new_router = Router(
        tenant_id=context.tenant.id,
        name=name.strip(),
        token_hash=token_hashed,
        location=location.strip() if location else None,
        description=description.strip() if description else None,
        status=RouterStatus.provisioning,
    )
    db.add(new_router)
    db.commit()
    db.refresh(new_router)

    # Base sync URL for outbound HTTPS polling
    # Uses request.base_url to work seamlessly in local dev, preview, and production
    base_url = str(request.base_url).rstrip("/")
    sync_url = f"{base_url}/api/router/sync"

    # Outbound MikroTik RouterOS Fetch script (Works behind CGNAT, Starlink, dynamic IPs)
    script_template = (
        '# MikroTik RouterOS Outbound HTTPS Synchronization Script\n'
        '# Device: {router_name} (Tenant: {tenant_name})\n'
        '/system scheduler remove [find name="COwen_Sync"]\n'
        '/system script remove [find name="COwen_Sync_Script"]\n\n'
        '/system script add name="COwen_Sync_Script" source="\\\n'
        '  :local ver [/system resource get version];\\\n'
        '  :local upt [/system resource get uptime];\\\n'
        '  :local cpu [/system resource get cpu-load];\\\n'
        '  :local brd [/system resource get board-name];\\\n'
        '  /tool fetch url=\\"{sync_url}\\" http-method=post \\\n'
        '    http-header-field=\\"Content-Type: application/json,X-Router-Token: {raw_token}\\" \\\n'
        '    http-data=\\"{{\\\\\\"version\\\\\\":\\\\\\"$ver\\\\\\",\\\\\\"uptime\\\\\\":\\\\\\"$upt\\\\\\\",\\\\\\"cpu_load\\\\\\":$cpu,\\\\\\"board\\\\\\":\\\\\\"$brd\\\\\\"}}\\" \\\n'
        '    mode=https dst-path=\\"cowen_sync.json\\" output=none;\\\n'
        '"\n\n'
        '/system scheduler add name="COwen_Sync" interval=60s on-event="COwen_Sync_Script" start-time=startup\n'
        '# Run once immediately:\n'
        '/system script run COwen_Sync_Script\n'
    )
    mikrotik_script = script_template.format(
        router_name=new_router.name,
        tenant_name=context.tenant.name,
        sync_url=sync_url,
        raw_token=raw_token,
    )

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
            "created_router": new_router,
            "enrollment_token": raw_token,
            "sync_script": mikrotik_script,
            "error": None,
        },
    )


@tenant_router.post("/tenant/routers/{router_id}/rename")
def tenant_router_rename(
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

    router.name = name.strip()
    db.commit()
    return RedirectResponse(url="/tenant/routers?msg=renamed", status_code=status.HTTP_303_SEE_OTHER)


@tenant_router.post("/tenant/routers/{router_id}/deactivate")
def tenant_router_deactivate(
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
    return RedirectResponse(url="/tenant/routers?msg=deactivated", status_code=status.HTTP_303_SEE_OTHER)


# =====================================================================
# PPPoE Management
# =====================================================================

@tenant_router.get("/tenant/pppoe", response_class=HTMLResponse)
def tenant_pppoe_page(
    request: Request,
    msg: str | None = None,
    error: str | None = None,
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Lists speed tiers and subscriber records."""
    tenant_id = context.tenant.id

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
        },
    )


@tenant_router.post("/tenant/pppoe/plans/add")
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
    """Creates a bandwidth speed plan."""
    plan = PPPoEPlan(
        tenant_id=context.tenant.id,
        name=name.strip(),
        rate_limit=rate_limit.strip(),
        price_kes=Decimal(str(price_kes)),
        duration_days=duration_days,
        marketing_speed=marketing_speed.strip() if marketing_speed else None,
        is_active=True,
    )
    db.add(plan)
    db.commit()
    return RedirectResponse(url="/tenant/pppoe?msg=plan_created", status_code=status.HTTP_303_SEE_OTHER)


@tenant_router.post("/tenant/pppoe/subscribers/add")
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
    """Creates a new PPPoE subscriber and queues a router command for provisioning."""
    # Verify router belongs to tenant
    router = db.scalar(
        select(Router).where(Router.id == router_id, Router.tenant_id == context.tenant.id)
    )
    if not router:
        raise HTTPException(status_code=400, detail="Invalid router selection.")

    # Verify plan belongs to tenant
    plan = db.scalar(
        select(PPPoEPlan).where(PPPoEPlan.id == plan_id, PPPoEPlan.tenant_id == context.tenant.id)
    )
    if not plan:
        raise HTTPException(status_code=400, detail="Invalid plan selection.")

    # Check for username collision in this tenant
    existing = db.scalar(
        select(PPPoECustomer).where(
            PPPoECustomer.tenant_id == context.tenant.id,
            PPPoECustomer.username == username.strip(),
        )
    )
    if existing:
        return RedirectResponse(
            url="/tenant/pppoe?error=Username+already+exists+for+another+subscriber",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    customer = PPPoECustomer(
        tenant_id=context.tenant.id,
        router_id=router.id,
        plan_id=plan.id,
        username=username.strip(),
        password=password.strip(),
        full_name=full_name.strip(),
        phone_number=phone_number.strip() if phone_number else None,
        email=email.strip() if email else None,
        connection_type=ConnectionType(connection_type),
        static_ip=static_ip.strip() if static_ip else None,
        status=CustomerStatus.active,
    )
    db.add(customer)

    # Queue automated MikroTik RouterOS command
    cmd_script = f'/ppp secret add name="{customer.username}" password="{customer.password}" profile="{plan.name}" service=pppoe comment="{customer.full_name}"'
    command = RouterCommand(
        tenant_id=context.tenant.id,
        router_id=router.id,
        description=f"Provision PPPoE user: {customer.username}",
        script=cmd_script,
        status=RouterCommandStatus.pending,
    )
    db.add(command)

    db.commit()
    return RedirectResponse(url="/tenant/pppoe?msg=subscriber_added", status_code=status.HTTP_303_SEE_OTHER)


# =====================================================================
# Hotspot Management & Voucher Generation
# =====================================================================

@tenant_router.get("/tenant/hotspot", response_class=HTMLResponse)
def tenant_hotspot_page(
    request: Request,
    msg: str | None = None,
    error: str | None = None,
    batch_filter: str | None = None,
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Hotspot packages, voucher batch creation, and captive portal theme editor."""
    tenant_id = context.tenant.id

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

    # Portal design configuration
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
        },
    )


@tenant_router.post("/tenant/hotspot/packages/add")
def tenant_hotspot_package_add(
    name: str = Form(...),
    price_kes: float = Form(...),
    duration_minutes: int = Form(...),
    rate_limit: str = Form("5M/10M"),
    data_limit_mb: int | None = Form(None),
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Creates a Hotspot pricing package."""
    pkg = HotspotPackage(
        tenant_id=context.tenant.id,
        name=name.strip(),
        price_kes=Decimal(str(price_kes)),
        duration_minutes=duration_minutes,
        rate_limit=rate_limit.strip(),
        data_limit_mb=data_limit_mb,
        is_active=True,
    )
    db.add(pkg)
    db.commit()
    return RedirectResponse(url="/tenant/hotspot?msg=package_created", status_code=status.HTTP_303_SEE_OTHER)


@tenant_router.post("/tenant/hotspot/vouchers/generate")
def tenant_hotspot_vouchers_generate(
    package_id: str = Form(...),
    quantity: int = Form(...),
    router_id: str | None = Form(None),
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Generates a batch of unique Hotspot voucher codes."""
    pkg = db.scalar(
        select(HotspotPackage).where(
            HotspotPackage.id == package_id,
            HotspotPackage.tenant_id == context.tenant.id,
        )
    )
    if not pkg:
        raise HTTPException(status_code=400, detail="Invalid package selection.")

    qty = max(1, min(quantity, 200))  # Capped at 200 per batch for performance
    batch_id = uuid.uuid4().hex[:10].upper()

    commands_to_queue = []
    for _ in range(qty):
        # 6-character clean alphanumeric code (avoiding 0/O, 1/I confusion)
        charset = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
        code = "".join(secrets.choice(charset) for _ in range(6))

        voucher = HotspotVoucher(
            tenant_id=context.tenant.id,
            package_id=pkg.id,
            router_id=router_id if router_id else None,
            code=code,
            batch_id=batch_id,
            status=VoucherStatus.unused,
        )
        db.add(voucher)

        if router_id:
            # Queue command to push voucher user to MikroTik Hotspot
            cmd = f'/ip hotspot user add name="{code}" password="{code}" profile="{pkg.name}" comment="Batch {batch_id}"'
            commands_to_queue.append(cmd)

    if router_id and commands_to_queue:
        # Group commands into single router command
        batched_script = "\n".join(commands_to_queue)
        command = RouterCommand(
            tenant_id=context.tenant.id,
            router_id=router_id,
            description=f"Batch {batch_id}: Add {qty} hotspot vouchers",
            script=batched_script,
            status=RouterCommandStatus.pending,
        )
        db.add(command)

    db.commit()
    return RedirectResponse(
        url=f"/tenant/hotspot?batch_filter={batch_id}&msg=Generated+{qty}+vouchers",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@tenant_router.post("/tenant/hotspot/portal/save")
def tenant_hotspot_portal_save(
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
    return RedirectResponse(url="/tenant/hotspot?msg=portal_updated", status_code=status.HTTP_303_SEE_OTHER)


# =====================================================================
# Payments & Gateway Configuration
# =====================================================================

@tenant_router.get("/tenant/payments", response_class=HTMLResponse)
def tenant_payments_page(
    request: Request,
    msg: str | None = None,
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """M-Pesa and Paystack credentials management, plus customer payments ledger."""
    tenant_id = context.tenant.id

    config = db.scalar(
        select(TenantPaymentConfig).where(TenantPaymentConfig.tenant_id == tenant_id)
    )

    payments = db.scalars(
        select(CustomerPayment)
        .where(CustomerPayment.tenant_id == tenant_id)
        .order_by(CustomerPayment.created_at.desc())
        .limit(100)
    ).all()

    # Masked representation of keys for UI safety
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
        },
    )


@tenant_router.post("/tenant/payments/mpesa")
def tenant_payments_mpesa_save(
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

    return RedirectResponse(url="/tenant/payments?msg=mpesa_saved", status_code=status.HTTP_303_SEE_OTHER)


@tenant_router.post("/tenant/payments/paystack")
def tenant_payments_paystack_save(
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

    return RedirectResponse(url="/tenant/payments?msg=paystack_saved", status_code=status.HTTP_303_SEE_OTHER)


# =====================================================================
# Financial Reports (Customer ISP Revenue Only)
# =====================================================================

@tenant_router.get("/tenant/reports", response_class=HTMLResponse)
def tenant_reports_page(
    request: Request,
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """
    Financial reports strictly restricted to customer payments for this ISP.
    Platform-wide subscription revenue is strictly excluded.
    """
    tenant_id = context.tenant.id

    # 1. Total All-time Customer Revenue
    all_time_rev = db.scalar(
        select(func.coalesce(func.sum(CustomerPayment.amount_kes), Decimal("0.00"))).where(
            CustomerPayment.tenant_id == tenant_id,
            CustomerPayment.status == "completed",
        )
    ) or Decimal("0.00")

    # 2. This Month Revenue
    now = datetime.now(timezone.utc)
    month_start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    this_month_rev = db.scalar(
        select(func.coalesce(func.sum(CustomerPayment.amount_kes), Decimal("0.00"))).where(
            CustomerPayment.tenant_id == tenant_id,
            CustomerPayment.status == "completed",
            CustomerPayment.created_at >= month_start,
        )
    ) or Decimal("0.00")

    # 3. Breakdown by Payment Gateway
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

    # 4. Service Breakdown (PPPoE vs Hotspot)
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

    # 5. Recent 20 Transactions
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
        },
    )


# =====================================================================
# Settings & White-Label Branding
# =====================================================================

@tenant_router.get("/tenant/settings", response_class=HTMLResponse)
def tenant_settings_page(
    request: Request,
    msg: str | None = None,
    error: str | None = None,
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Company profile, custom branding, and administrator security."""
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
        },
    )


@tenant_router.post("/tenant/settings/company")
def tenant_settings_company_save(
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
    return RedirectResponse(url="/tenant/settings?msg=company_updated", status_code=status.HTTP_303_SEE_OTHER)


@tenant_router.post("/tenant/settings/branding")
def tenant_settings_branding_save(
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
    return RedirectResponse(url="/tenant/settings?msg=branding_updated", status_code=status.HTTP_303_SEE_OTHER)


@tenant_router.post("/tenant/settings/password")
def tenant_settings_password_save(
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    context: TenantContext = Depends(require_tenant_context),
    db: Session = Depends(get_saas_db),
):
    """Updates administrator password with current password verification."""
    if not verify_password(current_password, context.user.hashed_password):
        return RedirectResponse(
            url="/tenant/settings?error=Incorrect+current+password",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    if new_password != confirm_password:
        return RedirectResponse(
            url="/tenant/settings?error=New+passwords+do+not+match",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    if len(new_password) < 8:
        return RedirectResponse(
            url="/tenant/settings?error=Password+must+be+at+least+8+characters",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    context.user.hashed_password = hash_password(new_password)
    context.user.session_version += 1
    db.commit()

    return RedirectResponse(url="/tenant/settings?msg=password_updated", status_code=status.HTTP_303_SEE_OTHER)


# =====================================================================
# Router Outbound HTTPS Polling & Command Execution API
# =====================================================================

@tenant_router.post("/api/router/sync")
async def router_sync_endpoint(
    request: Request,
    x_router_token: str | None = Header(None),
    db: Session = Depends(get_saas_db),
):
    """
    Outbound HTTPS Polling API for MikroTik routers.
    Allows routers behind CGNAT, Starlink, or private IPs to report status and retrieve commands.
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

    # Parse telemetry JSON payload if provided
    try:
        body = await request.json()
    except Exception:
        body = {}

    # Update router telemetry
    router.last_seen_at = datetime.now(timezone.utc)
    router.status = RouterStatus.online
    if body.get("version"):
        router.version = str(body["version"])[:64]
    if body.get("board"):
        router.board = str(body["board"])[:64]
    if body.get("uptime"):
        router.uptime = str(body["uptime"])[:32]
    if body.get("cpu_load") is not None:
        try:
            router.cpu_load = int(body["cpu_load"])
        except (ValueError, TypeError):
            pass

    # Extract remote IP
    client_host = request.client.host if request.client else None
    if client_host:
        router.ip_address = client_host

    # Fetch queued pending commands for this router
    pending_commands = db.scalars(
        select(RouterCommand)
        .where(
            RouterCommand.router_id == router.id,
            RouterCommand.status == RouterCommandStatus.pending,
        )
        .order_by(RouterCommand.created_at.asc())
        .limit(10)
    ).all()

    commands_payload = []
    now_ts = datetime.now(timezone.utc)
    for cmd in pending_commands:
        cmd.status = RouterCommandStatus.sent
        cmd.sent_at = now_ts
        cmd.attempts += 1
        commands_payload.append({
            "id": cmd.id,
            "description": cmd.description,
            "script": cmd.script,
        })

    db.commit()

    return {
        "status": "ok",
        "router_id": router.id,
        "router_name": router.name,
        "server_time": now_ts.isoformat(),
        "commands": commands_payload,
    }


@tenant_router.post("/api/router/command-result")
async def router_command_result_endpoint(
    request: Request,
    x_router_token: str | None = Header(None),
    db: Session = Depends(get_saas_db),
):
    """Reports back the execution output/result of a router command."""
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
    cmd_status = body.get("status")  # "done" or "failed"

    if not cmd_id or not cmd_status:
        raise HTTPException(status_code=400, detail="Missing command_id or status.")

    cmd = db.scalar(
        select(RouterCommand).where(RouterCommand.id == cmd_id, RouterCommand.router_id == router.id)
    )
    if not cmd:
        raise HTTPException(status_code=404, detail="Command not found.")

    if cmd_status == "done":
        cmd.status = RouterCommandStatus.done
    else:
        cmd.status = RouterCommandStatus.failed

    cmd.finished_at = datetime.now(timezone.utc)
    db.commit()

    return {"status": "recorded", "command_id": cmd.id, "command_status": cmd.status.value}
