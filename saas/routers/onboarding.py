"""Checkout, Paystack Webhook, and Administrator Invitation routes."""
from __future__ import annotations

import json
import logging
import re
import secrets
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from saas.config import saas_settings
from saas.database import get_saas_db
from saas.models.payments import PendingSubscriptionCheckout, SubscriptionTransaction
from saas.models.tenant import (
    SubscriptionTier,
    Tenant,
    TenantInvitation,
    TenantUser,
    UserRole,
)
from saas.security.auth import hash_password, hash_token
from saas.services import paystack
from saas.services.paystack import PaystackPlatformError
from saas.services.provisioning import ProvisioningError, process_payment_and_provision

logger = logging.getLogger("saas.onboarding")

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

onboarding_router = APIRouter(tags=["onboarding"])

_SLUG_REGEX = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


# ---------------------------------------------------------
# 1. Checkout Initiation
# ---------------------------------------------------------
@onboarding_router.get("/checkout", response_class=HTMLResponse)
def checkout_page(request: Request, plan: str = "starter"):
    """Displays checkout form with selected subscription package."""
    try:
        tier = SubscriptionTier(plan.lower())
    except ValueError:
        tier = SubscriptionTier.starter

    return templates.TemplateResponse(
        request=request,
        name="checkout.html",
        context={
            "tier": tier,
            "error": None,
            "form_data": {},
        },
    )


@onboarding_router.post("/checkout/initiate")
async def initiate_checkout(
    request: Request,
    plan: str = Form(...),
    company_name: str = Form(...),
    company_slug: str = Form(...),
    company_email: str = Form(...),
    company_phone: str = Form(...),
    admin_name: str = Form(...),
    admin_email: str = Form(...),
    db: Session = Depends(get_saas_db),
):
    """
    Validates company onboarding details, stores PendingSubscriptionCheckout,
    initializes Paystack transaction, and redirects to Paystack checkout.
    """
    company_name = company_name.strip()
    company_slug = company_slug.strip().lower()
    company_email = company_email.strip().lower()
    company_phone = company_phone.strip()
    admin_name = admin_name.strip()
    admin_email = admin_email.strip().lower()

    form_data = {
        "company_name": company_name,
        "company_slug": company_slug,
        "company_email": company_email,
        "company_phone": company_phone,
        "admin_name": admin_name,
        "admin_email": admin_email,
    }

    try:
        tier = SubscriptionTier(plan.lower())
    except ValueError:
        tier = SubscriptionTier.starter

    # Validations
    if len(company_name) < 2:
        return templates.TemplateResponse(
            request=request,
            name="checkout.html",
            context={"tier": tier, "error": "Company name must be at least 2 characters.", "form_data": form_data},
            status_code=400,
        )

    if not _SLUG_REGEX.match(company_slug):
        return templates.TemplateResponse(
            request=request,
            name="checkout.html",
            context={
                "tier": tier,
                "error": "Workspace slug may only contain lowercase letters, numbers, and hyphens (e.g. 'my-isp').",
                "form_data": form_data,
            },
            status_code=400,
        )

    # Check for existing company slug
    existing_tenant = db.scalar(select(Tenant).where(Tenant.slug == company_slug))
    if existing_tenant:
        return templates.TemplateResponse(
            request=request,
            name="checkout.html",
            context={"tier": tier, "error": f"The workspace slug '{company_slug}' is already taken. Please choose another.", "form_data": form_data},
            status_code=400,
        )

    # Check for existing user email
    existing_user = db.scalar(select(TenantUser).where(TenantUser.email == admin_email))
    if existing_user:
        return templates.TemplateResponse(
            request=request,
            name="checkout.html",
            context={"tier": tier, "error": f"An administrator account with email '{admin_email}' already exists. Please log in or use another email.", "form_data": form_data},
            status_code=400,
        )

    # Generate unique payment reference
    reference = f"sub_{company_slug[:12]}_{secrets.token_hex(6)}"

    # Create pending checkout
    pending = PendingSubscriptionCheckout(
        paystack_reference=reference,
        company_name=company_name,
        company_slug=company_slug,
        company_email=company_email,
        company_phone=company_phone,
        admin_name=admin_name,
        admin_email=admin_email,
        tier=tier,
        amount_kes=tier.monthly_price_kes,
        currency="KES",
        status="pending",
    )
    db.add(pending)
    db.commit()

    # Determine dynamic callback url based on the current request domain
    # This guarantees it redirects back to the correct domain (e.g. cowen.vercel.app)
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    dynamic_callback = f"{proto}://{host}/checkout/callback"
    cb_url = (
        saas_settings.platform_paystack_callback_url
        if ("localhost" not in saas_settings.platform_paystack_callback_url or "localhost" in host)
        else dynamic_callback
    )

    # Initialize Paystack checkout
    try:
        init_res = paystack.initialize_transaction(
            email=admin_email,
            amount_kes=tier.monthly_price_kes,
            reference=reference,
            callback_url=cb_url,
            metadata={
                "company_name": company_name,
                "company_slug": company_slug,
                "tier": tier.value,
                "admin_name": admin_name,
            },
        )
        auth_url = init_res.get("authorization_url")
        if not auth_url:
            raise PaystackPlatformError("Missing authorization URL from Paystack response.")
        return RedirectResponse(url=auth_url, status_code=303)
    except PaystackPlatformError as exc:
        logger.error("Paystack transaction initialization failed for %s: %s", reference, exc)
        return templates.TemplateResponse(
            request=request,
            name="checkout.html",
            context={
                "tier": tier,
                "error": f"Could not initiate Paystack payment: {exc}",
                "form_data": form_data,
            },
            status_code=502,
        )


# ---------------------------------------------------------
# 2. Payment Callback & Status Screens
# ---------------------------------------------------------
@onboarding_router.get("/checkout/callback", response_class=HTMLResponse)
def checkout_callback(
    request: Request,
    reference: str | None = None,
    trxref: str | None = None,
    db: Session = Depends(get_saas_db),
):
    """
    Browser return endpoint after user completes Paystack checkout.
    Verifies transaction with Paystack server-side before showing status.
    """
    ref = reference or trxref
    if not ref:
        raise HTTPException(status_code=400, detail="Missing payment reference.")

    pending = db.scalar(
        select(PendingSubscriptionCheckout).where(PendingSubscriptionCheckout.paystack_reference == ref)
    )
    if not pending:
        raise HTTPException(status_code=404, detail="Pending checkout record not found.")

    # Check if already provisioned
    if pending.status == "paid" and pending.provisioned_tenant_id:
        tenant = db.scalar(select(Tenant).where(Tenant.id == pending.provisioned_tenant_id))
        return templates.TemplateResponse(
            request=request,
            name="checkout_status.html",
            context={
                "status": "already_provisioned",
                "reference": ref,
                "company_name": pending.company_name,
                "tenant_slug": tenant.slug if tenant else pending.company_slug,
                "admin_email": pending.admin_email,
                "tier": pending.tier.value,
                "invitation_url": None,
            },
        )

    # Perform server-side Paystack verification
    try:
        verified_data = paystack.verify_transaction(ref)
        if verified_data.get("status") == "success":
            # Provision tenant!
            proto = request.headers.get("x-forwarded-proto", request.url.scheme)
            host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
            request_base_url = f"{proto}://{host}"
            result = process_payment_and_provision(db, verified_data, base_url=request_base_url)
            return templates.TemplateResponse(
                request=request,
                name="checkout_status.html",
                context={
                    "status": "provisioned",
                    "reference": ref,
                    "company_name": pending.company_name,
                    "tenant_slug": result.get("tenant_slug", pending.company_slug),
                    "admin_email": pending.admin_email,
                    "tier": pending.tier.value,
                    "invitation_url": result.get("invitation_url"),
                },
            )
        else:
            return templates.TemplateResponse(
                request=request,
                name="checkout_status.html",
                context={
                    "status": "failed",
                    "reference": ref,
                    "company_name": pending.company_name,
                    "tenant_slug": pending.company_slug,
                    "admin_email": pending.admin_email,
                    "tier": pending.tier.value,
                    "invitation_url": None,
                },
            )
    except Exception as exc:
        logger.warning("Callback verification pending for %s: %s", ref, exc)
        return templates.TemplateResponse(
            request=request,
            name="checkout_status.html",
            context={
                "status": "pending",
                "reference": ref,
                "company_name": pending.company_name,
                "tenant_slug": pending.company_slug,
                "admin_email": pending.admin_email,
                "tier": pending.tier.value,
                "invitation_url": None,
            },
        )


@onboarding_router.get("/checkout/status/{reference}", response_class=HTMLResponse)
def checkout_status_page(reference: str, request: Request, db: Session = Depends(get_saas_db)):
    """Status screen for tracking payment verification."""
    pending = db.scalar(
        select(PendingSubscriptionCheckout).where(PendingSubscriptionCheckout.paystack_reference == reference)
    )
    if not pending:
        raise HTTPException(status_code=404, detail="Checkout reference not found.")

    tenant = (
        db.scalar(select(Tenant).where(Tenant.id == pending.provisioned_tenant_id))
        if pending.provisioned_tenant_id
        else None
    )

    return templates.TemplateResponse(
        request=request,
        name="checkout_status.html",
        context={
            "status": "provisioned" if pending.status == "paid" else pending.status,
            "reference": reference,
            "company_name": pending.company_name,
            "tenant_slug": tenant.slug if tenant else pending.company_slug,
            "admin_email": pending.admin_email,
            "tier": pending.tier.value,
            "invitation_url": None,
        },
    )


@onboarding_router.get("/checkout/status/{reference}/json")
def checkout_status_json(reference: str, db: Session = Depends(get_saas_db)):
    """JSON status API for browser polling."""
    pending = db.scalar(
        select(PendingSubscriptionCheckout).where(PendingSubscriptionCheckout.paystack_reference == reference)
    )
    if not pending:
        raise HTTPException(status_code=404, detail="Reference not found.")

    return {
        "reference": reference,
        "status": "provisioned" if pending.status == "paid" else pending.status,
        "provisioned_tenant_id": pending.provisioned_tenant_id,
    }


# ---------------------------------------------------------
# 3. Secure Paystack Webhook
# ---------------------------------------------------------
@onboarding_router.post("/api/webhooks/paystack")
async def paystack_webhook(
    request: Request,
    db: Session = Depends(get_saas_db),
):
    """
    Safeguards 1, 2, 3, 4, 5:
    Secure webhook endpoint verifying HMAC-SHA512 signatures and executing idempotent provisioning.
    """
    raw_body = await request.body()
    
    # Safeguard 1: Support x-paystack-signature and legacy/case variants
    signature = (
        request.headers.get("x-paystack-signature")
        or request.headers.get("X-Paystack-Signature")
        or request.headers.get("x-paystack-signature-sha512")
    )

    if not signature or not paystack.verify_signature(raw_body, signature):
        logger.warning("Rejected Paystack webhook: signature verification failed.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Paystack webhook signature.",
        )

    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload.")

    event = payload.get("event")
    if event != "charge.success":
        # We only provision on confirmed charge success
        return {"status": "ignored", "event": event}

    data = payload.get("data", {})
    try:
        result = process_payment_and_provision(
            db=db,
            paystack_data=data,
            raw_response_text=raw_body.decode("utf-8", errors="replace"),
        )
        return {"status": "ok", "provisioning": result}
    except ProvisioningError as exc:
        logger.error("Provisioning error processing webhook: %s", exc)
        return JSONResponse(status_code=400, content={"error": str(exc)})


# ---------------------------------------------------------
# 4. Administrator Invitation Acceptance Flow
# ---------------------------------------------------------
@onboarding_router.get("/invite/{token}", response_class=HTMLResponse)
def view_invitation(token: str, request: Request, db: Session = Depends(get_saas_db)):
    """Validates single-use unexpired invitation token and displays password setup screen."""
    token_hashed = hash_token(token)
    now = datetime.now(timezone.utc)

    invitation = db.scalar(
        select(TenantInvitation).where(
            TenantInvitation.token_hash == token_hashed,
            TenantInvitation.is_used == False,
            TenantInvitation.expires_at > now,
        )
    )

    if not invitation:
        return HTMLResponse(
            "<!doctype html><body style='background:#090a0f;color:#fff;font-family:sans-serif;padding:60px;text-align:center;'>"
            "<h2 style='color:#ef4444;'>Invitation Expired or Invalid</h2>"
            "<p style='color:#949eb5;'>This invitation token has expired, already been used, or does not exist.</p>"
            "<a href='/' style='color:#dfb758;text-decoration:none;'>&larr; Return to Homepage</a>"
            "</body>",
            status_code=404,
        )

    tenant = db.scalar(select(Tenant).where(Tenant.id == invitation.tenant_id))
    company_name = tenant.name if tenant else "Your Company"

    return templates.TemplateResponse(
        request=request,
        name="invite.html",
        context={
            "token": token,
            "company_name": company_name,
            "full_name": invitation.full_name,
            "email": invitation.email,
            "error": None,
        },
    )


@onboarding_router.post("/invite/{token}")
def accept_invitation(
    token: str,
    request: Request,
    password: str = Form(...),
    password_confirm: str = Form(...),
    db: Session = Depends(get_saas_db),
):
    """Sets administrator password, consumes single-use invitation, and signs user in."""
    token_hashed = hash_token(token)
    now = datetime.now(timezone.utc)

    invitation = db.scalar(
        select(TenantInvitation).where(
            TenantInvitation.token_hash == token_hashed,
            TenantInvitation.is_used == False,
            TenantInvitation.expires_at > now,
        )
    )

    if not invitation:
        raise HTTPException(status_code=404, detail="Invitation link is invalid or expired.")

    tenant = db.scalar(select(Tenant).where(Tenant.id == invitation.tenant_id))
    company_name = tenant.name if tenant else "Your Company"

    if len(password) < 8:
        return templates.TemplateResponse(
            request=request,
            name="invite.html",
            context={
                "token": token,
                "company_name": company_name,
                "full_name": invitation.full_name,
                "email": invitation.email,
                "error": "Password must be at least 8 characters.",
            },
            status_code=400,
        )

    if password != password_confirm:
        return templates.TemplateResponse(
            request=request,
            name="invite.html",
            context={
                "token": token,
                "company_name": company_name,
                "full_name": invitation.full_name,
                "email": invitation.email,
                "error": "Passwords do not match.",
            },
            status_code=400,
        )

    # 1. Create or update TenantUser
    existing_user = db.scalar(select(TenantUser).where(TenantUser.email == invitation.email))
    if not existing_user:
        user = TenantUser(
            tenant_id=invitation.tenant_id,
            email=invitation.email,
            full_name=invitation.full_name,
            hashed_password=hash_password(password),
            role=invitation.role,
            is_active=True,
        )
        db.add(user)
    else:
        existing_user.hashed_password = hash_password(password)
        existing_user.is_active = True
        user = existing_user

    # 2. Mark invitation used (single-use enforcement)
    invitation.is_used = True
    invitation.used_at = now

    db.commit()
    db.refresh(user)

    # 3. Authenticate session
    if "session" in request.scope:
        request.session["user_id"] = user.id

    # Redirect to tenant profile/dashboard
    return RedirectResponse(url="/api/tenant/me", status_code=303)
