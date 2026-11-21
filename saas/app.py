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
    # Ensure database schema exists on startup
    SaasBase.metadata.create_all(bind=saas_engine)
    yield


app = FastAPI(
    title=saas_settings.platform_name,
    version="1.0.0",
    description="Multi-tenant ISP & Hotspot Billing SaaS Platform",
    lifespan=lifespan,
)

# Cookie Session Middleware (Enforces https_only and secure attributes in production)
is_production = saas_settings.saas_env == "production"

app.add_middleware(
    SessionMiddleware,
    secret_key=saas_settings.effective_session_secret,
    session_cookie="saas_session",
    max_age=86400 * 7,  # 7 days
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
