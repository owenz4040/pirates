"""Hotspot purchase, payment gateway coordination (M-Pesa / Paystack), and automated voucher provisioning."""
from __future__ import annotations

import json
import logging
import secrets
import string
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from saas.config import saas_settings
from saas.models.hotspot import HotspotPackage, HotspotVoucher, VoucherStatus
from saas.models.payments import CustomerPayment, TenantPaymentConfig
from saas.models.router import Router, RouterCommand, RouterCommandStatus, RouterStatus
from saas.models.tenant import Tenant, TenantStatus
from saas.security.sanitizer import (
    build_hotspot_profile_command,
    build_hotspot_user_command,
    format_routeros_duration,
)
from saas.services.daraja import format_phone_number, initiate_stk_push, parse_stk_callback
from saas.services.paystack import initialize_transaction, verify_transaction

logger = logging.getLogger("saas.hotspot_billing")

_VOUCHER_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # Omits 0, O, 1, I to prevent user typos


class HotspotBillingError(RuntimeError):
    """Raised when hotspot purchase, payment, or voucher activation fails."""
    pass


def generate_secure_voucher_code(length: int = 8) -> str:
    """Generate cryptographically secure uppercase voucher code avoiding ambiguous characters."""
    return "".join(secrets.choice(_VOUCHER_ALPHABET) for _ in range(length))


def initiate_hotspot_purchase(
    db: Session,
    *,
    tenant_slug: str,
    package_id: str,
    gateway: str,
    customer_phone: str | None = None,
    customer_email: str | None = None,
    router_id: str | None = None,
    client_mac: str | None = None,
    client_ip: str | None = None,
    link_login_only: str | None = None,
    base_url: str = "https://cowen.vercel.app",
) -> dict[str, Any]:
    """Initiates a customer hotspot purchase via M-Pesa STK Push or Paystack Checkout."""
    tenant = db.scalar(
        select(Tenant).where(Tenant.slug == tenant_slug, Tenant.status == TenantStatus.active)
    )
    if not tenant:
        raise HotspotBillingError(f"ISP tenant '{tenant_slug}' not found or suspended.")

    package = db.scalar(
        select(HotspotPackage).where(
            HotspotPackage.id == package_id,
            HotspotPackage.tenant_id == tenant.id,
            HotspotPackage.is_active == True,
        )
    )
    if not package:
        raise HotspotBillingError("Selected hotspot package is invalid, expired, or inactive.")

    payment_config = db.scalar(
        select(TenantPaymentConfig).where(TenantPaymentConfig.tenant_id == tenant.id)
    )

    clean_gateway = gateway.strip().lower()
    if clean_gateway not in ("mpesa", "paystack"):
        raise HotspotBillingError(f"Unsupported payment gateway: '{gateway}'.")

    # Generate unique payment reference
    reference = f"HPAY-{secrets.token_hex(6).upper()}"

    # Determine router
    selected_router: Router | None = None
    if router_id:
        selected_router = db.scalar(
            select(Router).where(Router.id == router_id, Router.tenant_id == tenant.id)
        )
    if not selected_router:
        # Fallback to first online router for tenant
        selected_router = db.scalar(
            select(Router).where(
                Router.tenant_id == tenant.id,
                Router.status != RouterStatus.suspended,
            ).order_by(Router.created_at.asc())
        )

    # Persist pending CustomerPayment record
    payment = CustomerPayment(
        tenant_id=tenant.id,
        package_id=package.id,
        router_id=selected_router.id if selected_router else None,
        gateway=clean_gateway,
        reference=reference,
        amount_kes=package.price_kes,
        phone_number=format_phone_number(customer_phone) if customer_phone else None,
        client_mac=client_mac[:32] if client_mac else None,
        client_ip=client_ip[:45] if client_ip else None,
        link_login_only=link_login_only[:255] if link_login_only else None,
        status="pending",
    )
    db.add(payment)
    db.commit()

    if clean_gateway == "mpesa":
        if not payment_config or not payment_config.mpesa_enabled:
            raise HotspotBillingError("M-Pesa is not enabled for this ISP network.")
        mpesa_creds = payment_config.get_mpesa_credentials()
        consumer_key = mpesa_creds.get("consumer_key")
        consumer_secret = mpesa_creds.get("consumer_secret")
        passkey = mpesa_creds.get("passkey")
        shortcode = payment_config.mpesa_shortcode or payment_config.mpesa_till_number

        if not consumer_key or not consumer_secret or not passkey or not shortcode:
            raise HotspotBillingError("Incomplete M-Pesa Daraja credentials configured for this ISP.")

        if not customer_phone:
            raise HotspotBillingError("Phone number is required for M-Pesa STK Push.")

        formatted_phone = format_phone_number(customer_phone)
        callback_token = payment_config.get_callback_token()
        callback_url = f"{base_url}/api/webhook/mpesa/{tenant.id}?token={callback_token}"
        is_till = (payment_config.mpesa_type == "till")

        stk_res = initiate_stk_push(
            consumer_key=consumer_key,
            consumer_secret=consumer_secret,
            passkey=passkey,
            shortcode=shortcode,
            phone_number=formatted_phone,
            amount_kes=package.price_kes,
            callback_url=callback_url,
            account_reference="HOTSPOT",
            transaction_desc=f"{package.name[:10]} Pass",
            is_till=is_till,
        )

        checkout_req_id = stk_res.get("checkout_request_id")
        payment.checkout_request_id = checkout_req_id
        payment.metadata_json = json.dumps({
            "checkout_request_id": checkout_req_id,
            "merchant_request_id": stk_res.get("merchant_request_id"),
            "customer_phone": formatted_phone,
        })
        db.commit()

        return {
            "status": "stk_sent",
            "gateway": "mpesa",
            "reference": reference,
            "checkout_request_id": stk_res.get("checkout_request_id"),
            "amount_kes": float(package.price_kes),
            "phone": formatted_phone,
            "message": f"STK push sent to {formatted_phone}. Enter your M-Pesa PIN on your phone.",
        }

    else:  # Paystack
        if not payment_config or not payment_config.paystack_enabled:
            raise HotspotBillingError("Paystack payments are not enabled for this ISP network.")
        secret_key = payment_config.get_paystack_secret()
        if not secret_key:
            raise HotspotBillingError("Tenant Paystack secret key is missing.")

        email = customer_email.strip() if customer_email else f"customer_{reference.lower()}@hotspot.local"
        callback_url = f"{base_url}/portal/paystack-callback?reference={reference}"

        paystack_res = initialize_transaction(
            email=email,
            amount_kes=package.price_kes,
            reference=reference,
            callback_url=callback_url,
            metadata={
                "tenant_id": tenant.id,
                "package_id": package.id,
                "package_name": package.name,
                "type": "hotspot_purchase",
            },
            secret_key=secret_key,
        )

        payment.metadata_json = json.dumps({
            "access_code": paystack_res.get("access_code"),
            "authorization_url": paystack_res.get("authorization_url"),
        })
        db.commit()

        return {
            "status": "checkout_url",
            "gateway": "paystack",
            "reference": reference,
            "authorization_url": paystack_res.get("authorization_url"),
            "access_code": paystack_res.get("access_code"),
            "message": "Redirecting to secure Paystack checkout...",
        }


def complete_hotspot_payment(
    db: Session,
    *,
    reference: str,
    tenant_id: str,
    gateway: str,
    provider_data: dict[str, Any] | None = None,
    receipt_number: str | None = None,
    verified_amount_kes: Decimal | None = None,
) -> dict[str, Any]:
    """Idempotently finalizes payment, creates voucher in pending_provisioning, and queues MikroTik user provisioning."""
    # Enforce strict tenant isolation on customer payment lookup
    payment = db.scalar(
        select(CustomerPayment).where(
            CustomerPayment.reference == reference,
            CustomerPayment.tenant_id == tenant_id,
        )
    )
    if not payment:
        raise HotspotBillingError(f"Customer payment reference '{reference}' not found for tenant '{tenant_id}'.")

    # Amount validation: Reject if verified amount does not match package amount
    if verified_amount_kes is not None and verified_amount_kes != payment.amount_kes:
        payment.status = "failed"
        db.commit()
        raise HotspotBillingError(f"Payment amount mismatch: expected {payment.amount_kes}, received {verified_amount_kes}.")

    # Idempotency guard: If already completed, check voucher provisioning state
    if payment.status in ("completed", "paid") and payment.voucher_id:
        voucher = db.scalar(select(HotspotVoucher).where(HotspotVoucher.id == payment.voucher_id))
        if voucher:
            is_active = (voucher.status == VoucherStatus.active)
            return {
                "status": "completed" if is_active else "provisioning",
                "reference": reference,
                "voucher_code": voucher.code if is_active else None,
                "voucher_password": (voucher.password or voucher.code) if is_active else None,
                "link_login_only": payment.link_login_only,
                "client_mac": payment.client_mac,
                "client_ip": payment.client_ip,
                "message": "Payment verified." if not is_active else "Payment confirmed and active.",
            }

    tenant = db.scalar(select(Tenant).where(Tenant.id == payment.tenant_id))
    package = db.scalar(select(HotspotPackage).where(HotspotPackage.id == payment.package_id))
    if not tenant or not package:
        raise HotspotBillingError("Associated tenant or package no longer exists.")

    # Mark payment as completed / paid
    payment.status = "completed"
    payment.paid_at = datetime.now(timezone.utc)

    # Store receipt details in metadata
    meta = {}
    if payment.metadata_json:
        try:
            meta = json.loads(payment.metadata_json)
        except Exception:
            pass
    if receipt_number:
        meta["receipt_number"] = receipt_number
        payment.provider_reference = receipt_number
    elif provider_data and isinstance(provider_data, dict) and provider_data.get("reference"):
        payment.provider_reference = provider_data.get("reference")
    if provider_data:
        meta["provider_data"] = provider_data
    payment.metadata_json = json.dumps(meta)

    # Generate cryptographically secure voucher in pending_provisioning status
    voucher_code = generate_secure_voucher_code(8)
    voucher_duration = package.duration_minutes
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=voucher_duration)

    voucher = HotspotVoucher(
        tenant_id=tenant.id,
        package_id=package.id,
        router_id=payment.router_id,
        code=voucher_code,
        password=voucher_code,
        status=VoucherStatus.pending_provisioning,
        customer_payment_id=payment.id,
        first_used_at=None,
        expires_at=expires_at,
    )
    db.add(voucher)
    db.flush()

    payment.voucher_id = voucher.id

    # Build and queue MikroTik Hotspot User Provisioning command
    profile_name = f"COwen-{package.name[:16].replace(' ', '_')}"
    profile_cmd = build_hotspot_profile_command(
        name=profile_name,
        rate_limit=package.rate_limit,
        session_timeout_minutes=voucher_duration,
        shared_users=1,
    )
    user_cmd = build_hotspot_user_command(
        code=voucher_code,
        password=voucher_code,
        profile=profile_name,
        voucher_id=voucher.id,
        limit_uptime_minutes=voucher_duration,
        limit_bytes_total=(package.data_limit_mb * 1024 * 1024) if package.data_limit_mb else None,
    )
    combined_script = f"{profile_cmd};\n{user_cmd}"

    if payment.router_id:
        cmd = RouterCommand(
            tenant_id=tenant.id,
            router_id=payment.router_id,
            description=f"Provision Hotspot Voucher: {voucher_code} ({package.name})",
            script=combined_script,
            status=RouterCommandStatus.pending,
            voucher_id=voucher.id,
        )
        db.add(cmd)
        db.flush()
        voucher.router_command_id = cmd.id

    db.commit()

    return {
        "status": "provisioning",
        "reference": reference,
        "voucher_code": None,  # Not revealed while pending router acknowledgement
        "package_name": package.name,
        "duration_minutes": voucher_duration,
        "rate_limit": package.rate_limit,
        "link_login_only": payment.link_login_only,
        "client_mac": payment.client_mac,
        "client_ip": payment.client_ip,
        "message": "Payment verified. Provisioning queued on router.",
    }


def get_hotspot_payment_status(db: Session, reference: str, tenant_slug: str | None = None) -> dict[str, Any]:
    """Queries payment status and returns voucher credentials ONLY after router acknowledgement."""
    query = select(CustomerPayment).where(CustomerPayment.reference == reference)
    if tenant_slug:
        tenant = db.scalar(select(Tenant).where(Tenant.slug == tenant_slug.strip()))
        if tenant:
            query = query.where(CustomerPayment.tenant_id == tenant.id)

    payment = db.scalar(query)
    if not payment:
        return {"status": "not_found", "message": "Transaction not found."}

    if payment.status in ("completed", "paid") and payment.voucher_id:
        voucher = db.scalar(select(HotspotVoucher).where(HotspotVoucher.id == payment.voucher_id))
        package = db.scalar(select(HotspotPackage).where(HotspotPackage.id == payment.package_id))
        
        if not voucher:
            return {"status": "provisioning", "reference": reference, "message": "Generating access credentials..."}

        # Stage 1: Router provisioning in progress
        if voucher.status == VoucherStatus.pending_provisioning:
            # Check if router command has definitively failed
            if voucher.router_command_id:
                cmd = db.scalar(select(RouterCommand).where(RouterCommand.id == voucher.router_command_id))
                if cmd and cmd.status == RouterCommandStatus.failed:
                    voucher.status = VoucherStatus.provisioning_failed
                    db.commit()
                    return {
                        "status": "failed",
                        "reference": reference,
                        "message": "Router provisioning failed. Please contact your network operator.",
                    }

            return {
                "status": "provisioning",
                "reference": reference,
                "message": "Payment received. Your internet access is being prepared. Please wait while we connect you.",
                "package_name": package.name if package else "WiFi Access",
            }

        # Stage 2: Router confirmed creation (ACK received)
        if voucher.status == VoucherStatus.active:
            return {
                "status": "completed",
                "reference": reference,
                "voucher_code": voucher.code,
                "voucher_password": voucher.password or voucher.code,
                "package_name": package.name if package else "WiFi Access",
                "duration_minutes": package.duration_minutes if package else 60,
                "rate_limit": package.rate_limit if package else "5M/10M",
                "link_login_only": payment.link_login_only,
                "client_mac": payment.client_mac,
                "client_ip": payment.client_ip,
            }

        if voucher.status == VoucherStatus.provisioning_failed:
            return {
                "status": "failed",
                "reference": reference,
                "message": "Router provisioning failed. Please contact your network operator.",
            }

        if voucher.status == VoucherStatus.expired:
            return {
                "status": "expired",
                "reference": reference,
                "message": "This access voucher has expired.",
            }

    if payment.status == "failed":
        return {"status": "failed", "reference": reference, "message": "Payment was declined or failed."}

    return {"status": "awaiting_payment", "reference": reference, "message": "Awaiting payment confirmation."}
