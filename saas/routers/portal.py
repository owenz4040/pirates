"""Customer-facing Hotspot Captive Portal, purchase flows, and tenant payment webhooks."""
from __future__ import annotations

import json
import logging
import urllib.parse
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


def validate_captive_login_url(url_str: str | None, network: HotspotNetwork | None, router: Router | None = None) -> str | None:
    """Strictly validates captive portal login URL against the selected HotspotNetwork configuration.

    Guarantees:
    - Parses URL using urllib.parse.
    - Rejects credentials embedded in URL (user:pass).
    - Rejects fragments (#).
    - Rejects external hosts, arbitrary domains, and unlisted subnets.
    - Destination hostname MUST match HotspotNetwork.gateway_ip, HotspotNetwork.dns_name, or router.ip_address.
    - Path must be standard RouterOS login path (/login or /login/).
    - Returns None if invalid or untrusted.
    """
    if not url_str or not isinstance(url_str, str):
        return None
    url_clean = url_str.strip()
    try:
        parsed = urllib.parse.urlparse(url_clean)
    except Exception:
        return None

    if parsed.scheme not in ("http", "https"):
        return None
    if parsed.username or parsed.password:
        return None
    if parsed.fragment:
        return None

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        return None

    allowed_destinations = set()
    if network:
        if network.gateway_ip:
            allowed_destinations.add(network.gateway_ip.lower().strip())
        if network.dns_name:
            allowed_destinations.add(network.dns_name.lower().strip())
    if router and router.ip_address:
        allowed_destinations.add(router.ip_address.lower().strip())

    if not allowed_destinations or hostname not in allowed_destinations:
        return None

    clean_path = parsed.path.rstrip("/")
    if clean_path not in ("/login", ""):
        return None

    return url_clean


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
    if not effective_slug or not effective_slug.strip():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Hotspot network identifier required.",
        )

    target_tenant = db.scalar(
        select(Tenant).where(Tenant.slug == effective_slug.strip(), Tenant.status == TenantStatus.active)
    )
    if not target_tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Hotspot network not found or inactive.",
        )

    # Hotspot network details (SSID)
    network: HotspotNetwork | None = None
    target_router: Router | None = None
    if router:
        network = db.scalar(
            select(HotspotNetwork).where(HotspotNetwork.tenant_id == target_tenant.id, HotspotNetwork.router_id == router)
        )
        target_router = db.scalar(
            select(Router).where(Router.tenant_id == target_tenant.id, Router.id == router)
        )
    if not network:
        network = db.scalar(
            select(HotspotNetwork).where(HotspotNetwork.tenant_id == target_tenant.id).order_by(HotspotNetwork.created_at.desc())
        )
    if not target_router and network and network.router_id:
        target_router = db.scalar(
            select(Router).where(Router.tenant_id == target_tenant.id, Router.id == network.router_id)
        )

    # Validate client-supplied link_login_only strictly against router / network gateway
    validated_login_url = validate_captive_login_url(link_login_only, network, target_router)

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
            "link_login_only": validated_login_url or "",
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
    tenant_slug: str | None = Query(None),
    db: Session = Depends(get_saas_db),
):
    """Polls real-time payment confirmation status and returns generated voucher credentials ONLY after router acknowledgement."""
    status_data = get_hotspot_payment_status(db, reference.strip(), tenant_slug=tenant_slug)
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
            v_data = verification.get("data", {})
            v_curr = str(v_data.get("currency", "")).upper()
            v_amt = Decimal(str(v_data.get("amount", 0))) / Decimal(100)
            if v_curr == "KES" and v_amt == payment.amount_kes:
                complete_hotspot_payment(
                    db,
                    reference=clean_ref,
                    tenant_id=payment.tenant_id,
                    gateway="paystack",
                    provider_data=verification,
                    receipt_number=str(v_data.get("id", clean_ref)),
                    verified_amount_kes=payment.amount_kes,
                )
                return RedirectResponse(
                    url=f"/portal/connected?reference={clean_ref}",
                    status_code=status.HTTP_303_SEE_OTHER,
                )
            else:
                logger.error("Paystack callback amount or currency mismatch for ref %s", clean_ref)
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
            "link_login_only": payment.link_login_only or "",
        },
    )


# =====================================================================
# Authenticated Provider Webhooks for ISP Tenant Customer Payments
# =====================================================================

@portal_router.post("/api/webhook/mpesa/{tenant_id}")
async def mpesa_tenant_webhook(
    request: Request,
    tenant_id: str,
    token: str | None = Query(None),
    db: Session = Depends(get_saas_db),
):
    """Handles Safaricom Daraja STK Push callbacks with secure token and amount verification."""
    tenant = db.scalar(select(Tenant).where(Tenant.id == tenant_id))
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found.")

    payment_config = db.scalar(select(TenantPaymentConfig).where(TenantPaymentConfig.tenant_id == tenant_id))
    if not payment_config or not payment_config.verify_callback_token(token):
        logger.warning("Rejected unauthorized M-Pesa callback for tenant %s: token mismatch or absent", tenant_id)
        return JSONResponse(status_code=401, content={"ResultCode": 1, "ResultDesc": "Unauthorized callback token"})

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

    # Correlate using exact indexed checkout_request_id scoped to tenant
    target_payment = db.scalar(
        select(CustomerPayment).where(
            CustomerPayment.tenant_id == tenant_id,
            CustomerPayment.checkout_request_id == checkout_id,
            CustomerPayment.gateway == "mpesa",
        )
    )

    if not target_payment:
        logger.warning("M-Pesa callback checkout_request_id '%s' not found for tenant %s", checkout_id, tenant_id)
        return JSONResponse(content={"ResultCode": 0, "ResultDesc": "Accepted"})

    if parsed.get("is_success"):
        # Validate amount
        paid_amount = parsed.get("amount")
        if paid_amount is None or Decimal(str(paid_amount)) != target_payment.amount_kes:
            logger.error(
                "M-Pesa amount mismatch for ref %s: expected %s, got %s",
                target_payment.reference,
                target_payment.amount_kes,
                paid_amount,
            )
            target_payment.status = "failed"
            db.commit()
            return JSONResponse(content={"ResultCode": 0, "ResultDesc": "Amount mismatch recorded"})

        # Validate receipt uniqueness
        receipt_no = parsed.get("receipt_number")
        if not receipt_no or not receipt_no.strip():
            logger.error("M-Pesa callback missing receipt number for ref %s", target_payment.reference)
            target_payment.status = "failed"
            db.commit()
            return JSONResponse(content={"ResultCode": 0, "ResultDesc": "Missing receipt"})

        # Check for duplicate receipt on another payment
        existing_receipt = db.scalar(
            select(CustomerPayment).where(
                CustomerPayment.tenant_id == tenant_id,
                CustomerPayment.provider_reference == receipt_no.strip(),
                CustomerPayment.id != target_payment.id,
            )
        )
        if existing_receipt:
            logger.error(
                "Duplicate M-Pesa receipt '%s' detected on payment %s (original %s)",
                receipt_no,
                target_payment.reference,
                existing_receipt.reference,
            )
            target_payment.status = "failed"
            db.commit()
            return JSONResponse(content={"ResultCode": 0, "ResultDesc": "Duplicate receipt rejected"})

        # Finalize payment and queue router command with voucher in pending_provisioning
        complete_hotspot_payment(
            db,
            reference=target_payment.reference,
            tenant_id=tenant_id,
            gateway="mpesa",
            provider_data=payload,
            receipt_number=receipt_no.strip(),
            verified_amount_kes=target_payment.amount_kes,
        )
        logger.info("M-Pesa payment confirmed for ref %s (Receipt: %s)", target_payment.reference, receipt_no)
    else:
        target_payment.status = "failed"
        db.commit()
        logger.warning("M-Pesa payment failed for ref %s: %s", target_payment.reference, parsed.get("result_desc"))

    return JSONResponse(content={"ResultCode": 0, "ResultDesc": "Accepted"})


@portal_router.post("/api/webhook/paystack/{tenant_id}")
async def paystack_tenant_webhook(
    request: Request,
    tenant_id: str,
    x_paystack_signature: str = Header(None, alias="x-paystack-signature"),
    db: Session = Depends(get_saas_db),
):
    """Handles Paystack webhooks for customer payments using tenant's encrypted secret key with strict isolation."""
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
            payment = db.scalar(
                select(CustomerPayment).where(
                    CustomerPayment.reference == reference,
                    CustomerPayment.tenant_id == tenant_id,
                )
            )
            if not payment:
                logger.warning("Paystack webhook reference %s not found for tenant %s", reference, tenant_id)
                return JSONResponse(content={"status": "ignored", "reason": "Unknown reference for tenant"})

            # Verify currency
            currency = str(data.get("currency", "")).upper()
            if currency != "KES":
                logger.error("Paystack currency mismatch for ref %s: expected KES, got %s", reference, currency)
                payment.status = "failed"
                db.commit()
                return JSONResponse(content={"status": "error", "message": "Currency mismatch"})

            # Verify amount (Paystack amount is in kobo/cents: divide by 100)
            raw_amount = data.get("amount")
            if raw_amount is not None:
                paid_kes = Decimal(str(raw_amount)) / Decimal(100)
                if paid_kes != payment.amount_kes:
                    logger.error("Paystack amount mismatch for ref %s: expected %s, got %s", reference, payment.amount_kes, paid_kes)
                    payment.status = "failed"
                    db.commit()
                    return JSONResponse(content={"status": "error", "message": "Amount mismatch"})

            complete_hotspot_payment(
                db,
                reference=reference,
                tenant_id=tenant_id,
                gateway="paystack",
                provider_data=data,
                receipt_number=str(data.get("id", reference)),
                verified_amount_kes=payment.amount_kes,
            )

    return JSONResponse(content={"status": "ok"})
