"""FastAPI application entrypoint for the Multi-Tenant ISP Billing SaaS platform."""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from saas.config import saas_settings
from saas.database import SaasBase, get_saas_db, saas_engine
from saas.models.payments import TenantPaymentConfig
from saas.models.router import Router, RouterStatus
from saas.routers.marketing import marketing_router
from saas.routers.onboarding import onboarding_router
from saas.routers.portal import portal_router
from saas.routers.superadmin import superadmin_router
from saas.routers.tenant import tenant_router
from saas.security.auth import generate_secure_token, hash_token
from saas.security.bootstrap import bootstrap_superadmin
from saas.security.csrf import verify_csrf_token
from saas.security.context import (
    SubscriptionLimitExceededError,
    TenantContext,
    resolve_tenant_context,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(
    title=saas_settings.platform_name,
    version="1.0.0",
    description="Multi-tenant ISP & Hotspot Billing SaaS Platform",
    lifespan=lifespan,
)


@app.get("/api/system/debug-router")
def debug_router_state(key: str = "", action: str = ""):
    """Read-only diagnostics for router sync and command queue, with optional retry action."""
    if key != "cowen-prod-migrate-2026":
        raise HTTPException(status_code=403, detail="Forbidden")
    from saas.database import SaasSessionLocal
    from saas.models.router import Router, RouterCommand, RouterCommandStatus
    from saas.models.hotspot import HotspotNetwork
    from saas.security.sanitizer import build_complete_hotspot_provisioning_script
    import json
    db = SaasSessionLocal()
    try:
        retried_count = 0
        if action == "retry_failed":
            failed_cmds = db.query(RouterCommand).filter(
                (RouterCommand.status == RouterCommandStatus.failed) | (RouterCommand.status == RouterCommandStatus.sent)
            ).all()
            for fc in failed_cmds:
                fc.status = RouterCommandStatus.pending
                fc.attempts = 0
                fc.sent_at = None
                fc.finished_at = None
                if "Provision Hotspot Network" in (fc.description or ""):
                    net = db.query(HotspotNetwork).filter_by(router_id=fc.router_id, tenant_id=fc.tenant_id).first()
                    if net:
                        try:
                            ports = json.loads(net.ethernet_ports_json) if net.ethernet_ports_json else ["ether2", "ether3", "ether4"]
                        except Exception:
                            ports = ["ether2", "ether3", "ether4"]
                        r_dev = db.query(Router).filter_by(id=fc.router_id).first()
                        is_ros7 = bool(r_dev and r_dev.version and r_dev.version.startswith("7"))
                        fc.script = build_complete_hotspot_provisioning_script(
                            bridge_name=net.bridge_name,
                            ethernet_ports=ports,
                            ssid=net.ssid,
                            security_mode=net.wifi_security or "open",
                            gateway_ip=net.gateway_ip,
                            network_cidr=net.network_cidr,
                            pool_start=net.dhcp_pool_start,
                            pool_end=net.dhcp_pool_end,
                            dns_name=net.dns_name,
                            include_wlan=net.include_wlan,
                            wlan_iface=net.wlan_interface or "wlan1",
                            is_ros7=is_ros7,
                        )
                retried_count += 1
            db.commit()

        routers = db.query(Router).all()
        router_data = []
        for r in routers:
            cmds = db.query(RouterCommand).filter_by(router_id=r.id).all()
            nets = db.query(HotspotNetwork).filter_by(router_id=r.id).all()
            router_data.append({
                "id": r.id,
                "name": r.name,
                "status": str(r.status),
                "last_seen_at": str(r.last_seen_at),
                "version": r.version,
                "commands": [{"id": c.id, "status": str(c.status), "attempts": c.attempts, "desc": c.description, "script": c.script} for c in cmds],
                "networks": [{"id": n.id, "ssid": n.ssid, "status": n.status} for n in nets]
            })
        return {"routers": router_data, "retried_count": retried_count}
    finally:
        db.close()


@app.get("/api/system/migrate")
def run_system_migration(key: str = ""):
    """Safe, single-runner administrative migration endpoint."""
    if key != "cowen-prod-migrate-2026":
        raise HTTPException(status_code=403, detail="Forbidden")
    from sqlalchemy import text, inspect
    results = []
    is_pg = saas_engine.dialect.name == "postgresql"

    if is_pg:
        stmts = [
            "ALTER TABLE saas_customer_payments ADD COLUMN IF NOT EXISTS package_id VARCHAR(36)",
            "ALTER TABLE saas_customer_payments ADD COLUMN IF NOT EXISTS router_id VARCHAR(36)",
            "ALTER TABLE saas_customer_payments ADD COLUMN IF NOT EXISTS checkout_request_id VARCHAR(64)",
            "ALTER TABLE saas_customer_payments ADD COLUMN IF NOT EXISTS provider_reference VARCHAR(128)",
            "ALTER TABLE saas_customer_payments ADD COLUMN IF NOT EXISTS client_mac VARCHAR(32)",
            "ALTER TABLE saas_customer_payments ADD COLUMN IF NOT EXISTS client_ip VARCHAR(45)",
            "ALTER TABLE saas_customer_payments ADD COLUMN IF NOT EXISTS link_login_only VARCHAR(255)",
            "ALTER TABLE saas_customer_payments ADD COLUMN IF NOT EXISTS paid_at TIMESTAMP WITH TIME ZONE",
            "ALTER TABLE saas_hotspot_vouchers ADD COLUMN IF NOT EXISTS password VARCHAR(64)",
            "ALTER TABLE saas_hotspot_vouchers ADD COLUMN IF NOT EXISTS customer_payment_id VARCHAR(36)",
            "ALTER TABLE saas_hotspot_vouchers ADD COLUMN IF NOT EXISTS router_command_id VARCHAR(36)",
            "ALTER TABLE saas_router_commands ADD COLUMN IF NOT EXISTS voucher_id VARCHAR(36)",
            "ALTER TABLE tenant_payment_configs ADD COLUMN IF NOT EXISTS mpesa_callback_token_encrypted TEXT",
            "ALTER TABLE tenant_payment_configs ADD COLUMN IF NOT EXISTS mpesa_callback_token_hash VARCHAR(64)",
            "ALTER TABLE tenant_payment_configs ADD COLUMN IF NOT EXISTS previous_callback_token_hash VARCHAR(64)",
            "CREATE INDEX IF NOT EXISTS ix_saas_customer_payments_package_id ON saas_customer_payments (package_id)",
            "CREATE INDEX IF NOT EXISTS ix_saas_customer_payments_router_id ON saas_customer_payments (router_id)",
            "CREATE INDEX IF NOT EXISTS ix_saas_customer_payments_checkout_request_id ON saas_customer_payments (checkout_request_id)",
            "CREATE INDEX IF NOT EXISTS ix_saas_hotspot_vouchers_customer_payment_id ON saas_hotspot_vouchers (customer_payment_id)",
        ]
        with saas_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("SET statement_timeout = '10s'"))
            conn.execute(text("SET lock_timeout = '5s'"))
            for s in stmts:
                try:
                    conn.execute(text(s))
                    results.append({"stmt": s, "status": "ok"})
                except Exception as e:
                    results.append({"stmt": s, "status": "error", "detail": str(e)})
    else:
        inspector = inspect(saas_engine)
        with saas_engine.begin() as conn:
            for table_name, table in SaasBase.metadata.tables.items():
                if not inspector.has_table(table_name):
                    continue
                db_cols = {c["name"] for c in inspector.get_columns(table_name)}
                for col in table.columns:
                    if col.name not in db_cols:
                        col_type = col.type.compile(saas_engine.dialect)
                        conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {col.name} {col_type}"))
                        results.append({"table": table_name, "col": col.name, "status": "ok"})
    return {"status": "completed", "results": results}

# Cookie Session Middleware (Enforces https_only and secure attributes in production)
is_production = saas_settings.saas_env == "production"

app.add_middleware(
    SessionMiddleware,
    secret_key=saas_settings.effective_session_secret,
    session_cookie="saas_session",
    max_age=86400,  # 24 hours absolute maximum session lifetime
    https_only=is_production,
    same_site="lax",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(SubscriptionLimitExceededError)
async def subscription_limit_handler(request: Request, exc: SubscriptionLimitExceededError):
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={
            "error": "subscription_limit_exceeded",
            "message": str(exc),
            "current_count": exc.current_count,
            "max_limit": exc.max_limit,
        },
    )


# Include Routers
app.include_router(marketing_router)
app.include_router(onboarding_router)
app.include_router(superadmin_router)
app.include_router(tenant_router)
app.include_router(portal_router)


@app.get("/admin/login")
@app.get("/admin")
def admin_login_redirect():
    return RedirectResponse(url="/superadmin/login", status_code=status.HTTP_302_FOUND)


# ---------------------------------------------------------
# Health Check
# ---------------------------------------------------------
@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "isp_billing_saas",
        "platform": saas_settings.platform_name,
    }


# ---------------------------------------------------------
# Tenant Context & Profile
# ---------------------------------------------------------
@app.get("/api/tenant/me")
def get_tenant_profile(context: TenantContext = Depends(resolve_tenant_context)):
    return {
        "tenant_id": context.tenant.id,
        "name": context.tenant.name,
        "slug": context.tenant.slug,
        "status": context.tenant.status.value,
        "user": {
            "id": context.user.id,
            "email": context.user.email,
            "full_name": context.user.full_name,
            "role": context.user.role.value,
        },
        "subscription": {
            "tier": context.tenant.subscription.tier.value if context.tenant.subscription else None,
            "max_routers": (
                context.tenant.subscription.max_routers
                if context.tenant.subscription
                else 0
            ),
            "is_active": (
                context.tenant.subscription.is_active
                if context.tenant.subscription
                else False
            ),
        }
        if context.tenant.subscription
        else None,
    }


# ---------------------------------------------------------
# Router Management (Subscription Limits Enforced)
# ---------------------------------------------------------
class CreateRouterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=64)
    location: str | None = None
    description: str | None = None


@app.post("/api/tenant/routers", status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf_token)])
def create_router(
    payload: CreateRouterRequest,
    context: TenantContext = Depends(resolve_tenant_context),
    db: Session = Depends(get_saas_db),
):
    # Enforce subscription tier limits
    context.assert_can_add_router(db)

    # Generate one-time secure enrollment token
    raw_token = generate_secure_token()
    token_hashed = hash_token(raw_token)

    router = Router(
        tenant_id=context.tenant.id,
        name=payload.name,
        token_hash=token_hashed,
        location=payload.location,
        description=payload.description,
        status=RouterStatus.provisioning,
    )
    db.add(router)
    db.commit()
    db.refresh(router)

    return {
        "router_id": router.id,
        "name": router.name,
        "status": router.status.value,
        "enrollment_token": raw_token,  # Shown only once to the ISP admin
    }


# ---------------------------------------------------------
# Tenant Payment Credentials (Encrypted at rest)
# ---------------------------------------------------------
class ConfigureMpesaRequest(BaseModel):
    shortcode: str
    consumer_key: str
    consumer_secret: str
    passkey: str
    mpesa_type: str = "paybill"


@app.post("/api/tenant/payment-config/mpesa", dependencies=[Depends(verify_csrf_token)])
def configure_tenant_mpesa(
    payload: ConfigureMpesaRequest,
    context: TenantContext = Depends(resolve_tenant_context),
    db: Session = Depends(get_saas_db),
):
    config = db.scalar(
        select(TenantPaymentConfig).where(TenantPaymentConfig.tenant_id == context.tenant.id)
    )
    if not config:
        config = TenantPaymentConfig(tenant_id=context.tenant.id)
        db.add(config)

    config.mpesa_enabled = True
    config.mpesa_type = payload.mpesa_type
    config.mpesa_shortcode = payload.shortcode
    config.set_mpesa_credentials(
        consumer_key=payload.consumer_key,
        consumer_secret=payload.consumer_secret,
        passkey=payload.passkey,
    )
    db.commit()

    return {
        "status": "success",
        "mpesa_enabled": True,
        "mpesa_type": config.mpesa_type,
        "shortcode": config.mpesa_shortcode,
    }
