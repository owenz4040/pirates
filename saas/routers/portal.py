"""Customer-facing Hotspot Captive Portal, purchase flows, and tenant payment webhooks."""
from __future__ import annotations

import json
import logging
from decimal import Decimal
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from saas.database import get_saas_db
from saas.models.hotspot import HotspotNetwork, HotspotPackage, HotspotPortalDesign, HotspotVoucher, VoucherStatus
from saas.models.payments import CustomerPayment, TenantPaymentConfig
from saas.models.router import Router, RouterStatus
from saas.models.tenant import Tenant, TenantBranding, TenantStatus
from saas.services.daraja import parse_stk_callback
from saas.services.hotspot_billing import (
    HotspotBillingError,
    complete_hotspot_payment,
    get_hotspot_payment_status,
    initiate_hotspot_purchase,
)
from saas.services.paystack import verify_signature, verify_transaction

logger = logging.getLogger("saas.portal")

portal_router = APIRouter(tags=["Captive Portal"])
templates = Jinja2Templates(directory="saas/templates")


class PurchaseRequest(BaseModel):
    tenant_slug: str
    package_id: str
    gateway: str  # "mpesa" or "paystack"
    customer_phone: str | None = None
    customer_email: str | None = None
    router_id: str | None = None
    client_mac: str | None = None
    client_ip: str | None = None
    link_login_only: str | None = None


@portal_router.get("/portal", response_class=HTMLResponse)
@portal_router.get("/portal/{tenant_slug}", response_class=HTMLResponse)
def customer_portal_page(
    request: Request,
    tenant_slug: str | None = None,
    tenant: str | None = Query(None),
    router: str | None = Query(None),
    mac: str | None = Query(None),
    ip: str | None = Query(None),
    link_login_only: str | None = Query(None),
    link_orig: str | None = Query(None),
    error: str | None = Query(None),
    db: Session = Depends(get_saas_db),
):
    """Customer-facing mobile-first captive portal."""
    effective_slug = tenant_slug or tenant
    target_tenant: Tenant | None = None

    if effective_slug:
        target_tenant = db.scalar(
            select(Tenant).where(Tenant.slug == effective_slug.strip(), Tenant.status == TenantStatus.active)
        )

    # If no slug provided or not found, fallback to first active tenant
    if not target_tenant:
        target_tenant = db.scalar(
            select(Tenant).where(Tenant.status == TenantStatus.active).order_by(Tenant.created_at.asc())
        )

    if not target_tenant:
        return HTMLResponse(
            "<h3>Hotspot Portal Offline</h3><p>No active network operator configured.</p>",
            status_code=503,
        )

    # Tenant branding & portal design
    branding = db.scalar(select(TenantBranding).where(TenantBranding.tenant_id == target_tenant.id))
    design = db.scalar(select(HotspotPortalDesign).where(HotspotPortalDesign.tenant_id == target_tenant.id))
    payment_config = db.scalar(select(TenantPaymentConfig).where(TenantPaymentConfig.tenant_id == target_tenant.id))

    # Active packages
    packages = db.scalars(
        select(HotspotPackage)
        .where(HotspotPackage.tenant_id == target_tenant.id, HotspotPackage.is_active == True)
        .order_by(HotspotPackage.price_kes.asc())
    ).all()

    # Hotspot network details (SSID)
    network: HotspotNetwork | None = None
    if router:
        network = db.scalar(
            select(HotspotNetwork).where(HotspotNetwork.tenant_id == target_tenant.id, HotspotNetwork.router_id == router)
        )
    if not network:
        network = db.scalar(
            select(HotspotNetwork).where(HotspotNetwork.tenant_id == target_tenant.id).order_by(HotspotNetwork.created_at.desc())
        )

    brand_name = (design.brand_name if design else None) or (branding.company_title if branding else None) or target_tenant.name
    ssid_name = network.ssid if network else "High-Speed WiFi"

    # Gateway availability
    has_mpesa = bool(payment_config and payment_config.mpesa_enabled)
    has_paystack = bool(payment_config and payment_config.paystack_enabled)

    return templates.TemplateResponse(
        request=request,
        name="portal/index.html",
        context={
            "tenant": target_tenant,
            "branding": branding,
            "design": design,
            "packages": packages,
            "network": network,
            "brand_name": brand_name,
            "ssid_name": ssid_name,
            "has_mpesa": has_mpesa,
            "has_paystack": has_paystack,
            "router_id": router or "",
            "client_mac": mac or "",
            "client_ip": ip or "",
            "link_login_only": link_login_only or "http://10.5.50.1/login",
            "link_orig": link_orig or "https://google.com",
            "error_msg": error,
        },
    )


@portal_router.post("/api/portal/purchase")
def portal_purchase_endpoint(
    request: Request,
    payload: PurchaseRequest,
    db: Session = Depends(get_saas_db),
):
    """Initiates an M-Pesa STK push or Paystack checkout for a hotspot package."""
    base_url = str(request.base_url).rstrip("/")
    try:
        result = initiate_hotspot_purchase(
            db,
            tenant_slug=payload.tenant_slug,
            package_id=payload.package_id,
            gateway=payload.gateway,
            customer_phone=payload.customer_phone,
            customer_email=payload.customer_email,
            router_id=payload.router_id,
            client_mac=payload.client_mac,
            client_ip=payload.client_ip,
            link_login_only=payload.link_login_only,
            base_url=base_url,
        )
        return JSONResponse(content=result)
    except HotspotBillingError as exc:
        return JSONResponse(status_code=400, content={"status": "error", "message": str(exc)})
    except Exception as exc:
        logger.exception("Unexpected error in hotspot purchase: %s", exc)
        return JSONResponse(status_code=500, content={"status": "error", "message": "Failed to initiate purchase."})


@portal_router.get("/api/portal/payment-status")
def portal_payment_status_endpoint(
    reference: str = Query(...),
    db: Session = Depends(get_saas_db),
):
    """Polls real-time payment confirmation status and returns generated voucher credentials."""
    status_data = get_hotspot_payment_status(db, reference.strip())
    return JSONResponse(content=status_data)


@portal_router.get("/portal/paystack-callback")
def portal_paystack_callback(
    reference: str = Query(...),
    db: Session = Depends(get_saas_db),
):
    """Handles browser redirect after customer completes Paystack checkout."""
    clean_ref = reference.strip()
    payment = db.scalar(select(CustomerPayment).where(CustomerPayment.reference == clean_ref))
    if not payment:
        raise HTTPException(status_code=404, detail="Transaction not found.")

    payment_config = db.scalar(
        select(TenantPaymentConfig).where(TenantPaymentConfig.tenant_id == payment.tenant_id)
    )
    secret_key = payment_config.get_paystack_secret() if payment_config else None

    try:
        verification = verify_transaction(clean_ref, secret_key=secret_key)
        if verification.get("status") == "success":
            complete_hotspot_payment(
                db,
                reference=clean_ref,
                gateway="paystack",
                provider_data=verification,
            )
            return RedirectResponse(
                url=f"/portal/connected?reference={clean_ref}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
    except Exception as exc:
        logger.warning("Paystack callback verification failed for reference %s: %s", clean_ref, exc)

    return RedirectResponse(
        url=f"/portal?error=Payment+verification+pending+or+failed",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@portal_router.get("/portal/connected", response_class=HTMLResponse)
def portal_connected_page(
    request: Request,
    reference: str = Query(...),
    db: Session = Depends(get_saas_db),
):
    """Display connection confirmation and automatic login triggers."""
    clean_ref = reference.strip()
    payment = db.scalar(select(CustomerPayment).where(CustomerPayment.reference == clean_ref))
    if not payment:
        raise HTTPException(status_code=404, detail="Transaction reference not found.")

    voucher: HotspotVoucher | None = None
    if payment.voucher_id:
        voucher = db.scalar(select(HotspotVoucher).where(HotspotVoucher.id == payment.voucher_id))

    tenant = db.scalar(select(Tenant).where(Tenant.id == payment.tenant_id))
    package = db.scalar(select(HotspotPackage).where(HotspotPackage.id == payment.package_id))
    branding = db.scalar(select(TenantBranding).where(TenantBranding.tenant_id == payment.tenant_id))

    brand_name = branding.company_title if branding else (tenant.name if tenant else "WiFi Access")

    return templates.TemplateResponse(
        request=request,
        name="portal/connected.html",
        context={
            "payment": payment,
            "voucher": voucher,
            "tenant": tenant,
            "package": package,
            "brand_name": brand_name,
            "link_login_only": payment.link_login_only or "http://10.5.50.1/login",
        },
    )


# =====================================================================
# Authenticated Provider Webhooks for ISP Tenant Customer Payments
# =====================================================================

@portal_router.post("/api/webhook/mpesa/{tenant_id}")
async def mpesa_tenant_webhook(
    request: Request,
    tenant_id: str,
    db: Session = Depends(get_saas_db),
):
    """Handles Safaricom Daraja STK Push callbacks for tenant ISP voucher payments."""
    tenant = db.scalar(select(Tenant).where(Tenant.id == tenant_id))
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found.")

    try:
        body_bytes = await request.body()
        payload = json.loads(body_bytes.decode("utf-8"))
    except Exception as exc:
        logger.error("Invalid JSON in M-Pesa webhook for tenant %s: %s", tenant_id, exc)
        return JSONResponse(status_code=400, content={"ResultCode": 1, "ResultDesc": "Invalid JSON"})

    parsed = parse_stk_callback(payload)
    checkout_id = parsed.get("checkout_request_id")

    if not checkout_id:
        logger.warning("M-Pesa callback missing CheckoutRequestID for tenant %s", tenant_id)
        return JSONResponse(content={"ResultCode": 0, "ResultDesc": "Accepted"})

    # Find matching CustomerPayment by checkout_request_id in metadata
    payments = db.scalars(
        select(CustomerPayment).where(
            CustomerPayment.tenant_id == tenant_id,
            CustomerPayment.gateway == "mpesa",
            CustomerPayment.status == "pending",
        )
    ).all()

    target_payment: CustomerPayment | None = None
    for p in payments:
        if p.metadata_json and checkout_id in p.metadata_json:
            target_payment = p
            break

    if target_payment:
        if parsed.get("is_success"):
            complete_hotspot_payment(
                db,
                reference=target_payment.reference,
                gateway="mpesa",
                provider_data=payload,
                receipt_number=parsed.get("receipt_number"),
            )
            logger.info("M-Pesa payment confirmed for reference %s (Receipt: %s)", target_payment.reference, parsed.get("receipt_number"))
        else:
            target_payment.status = "failed"
            db.commit()
            logger.warning("M-Pesa payment failed for reference %s: %s", target_payment.reference, parsed.get("result_desc"))

    return JSONResponse(content={"ResultCode": 0, "ResultDesc": "Accepted"})


@portal_router.post("/api/webhook/paystack/{tenant_id}")
async def paystack_tenant_webhook(
    request: Request,
    tenant_id: str,
    x_paystack_signature: str = Header(None, alias="x-paystack-signature"),
    db: Session = Depends(get_saas_db),
):
    """Handles Paystack webhooks for customer payments using tenant's encrypted secret key."""
    tenant = db.scalar(select(Tenant).where(Tenant.id == tenant_id))
    payment_config = db.scalar(select(TenantPaymentConfig).where(TenantPaymentConfig.tenant_id == tenant_id))

    if not tenant or not payment_config:
        raise HTTPException(status_code=404, detail="Tenant payment config not found.")

    secret_key = payment_config.get_paystack_secret()
    if not secret_key:
        raise HTTPException(status_code=400, detail="Tenant Paystack secret not configured.")

    body_bytes = await request.body()
    if not verify_signature(body_bytes, x_paystack_signature, secret_key=secret_key):
        raise HTTPException(status_code=401, detail="Invalid Paystack signature.")

    try:
        event = json.loads(body_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed JSON.")

    if event.get("event") == "charge.success":
        data = event.get("data", {})
        reference = data.get("reference")
        if reference:
            complete_hotspot_payment(
                db,
                reference=reference,
                gateway="paystack",
                provider_data=data,
            )

    return JSONResponse(content={"status": "ok"})
