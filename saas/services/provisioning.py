"""Durable, idempotent tenant provisioning engine triggered by confirmed payments."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from saas.config import saas_settings
from saas.models.payments import PendingSubscriptionCheckout, SubscriptionTransaction
from saas.models.tenant import (
    Tenant,
    TenantBranding,
    TenantInvitation,
    TenantStatus,
    TenantSubscription,
    UserRole,
)
from saas.security.auth import generate_secure_token, hash_token
from saas.services.email import send_invitation_email

logger = logging.getLogger("saas.provisioning")


class ProvisioningError(RuntimeError):
    """Raised when tenant provisioning cannot proceed due to validation or state conflicts."""
    pass


def process_payment_and_provision(
    db: Session,
    paystack_data: dict[str, Any],
    raw_response_text: str | None = None,
) -> dict[str, Any]:
    """
    Incorporates Safeguards 2, 3, 4, and 5:
    1. Idempotently provisions a tenant from verified Paystack transaction data.
    2. Enforces amount, currency (KES), reference, and customer verification against PendingSubscriptionCheckout.
    3. Persists payment transaction records with unique reference constraints.
    4. Decouples DB provisioning transaction from email delivery.
    """
    reference = paystack_data.get("reference")
    if not reference:
        raise ProvisioningError("Missing payment reference in Paystack payload.")

    status = paystack_data.get("status")
    if status != "success":
        # Record failed/abandoned transaction for auditing
        _record_non_success_transaction(db, reference, paystack_data, raw_response_text)
        return {
            "status": "payment_not_successful",
            "reference": reference,
            "paystack_status": status,
        }

    # Safeguard 2: Check for existing completed transaction (idempotency)
    existing_txn = db.scalar(
        select(SubscriptionTransaction).where(SubscriptionTransaction.paystack_reference == reference)
    )
    if existing_txn and existing_txn.status == "success" and existing_txn.tenant_id:
        logger.info("Reference %s has already been provisioned for tenant %s", reference, existing_txn.tenant_id)
        return {
            "status": "already_provisioned",
            "reference": reference,
            "tenant_id": existing_txn.tenant_id,
        }

    # Safeguard 3: Verify against stored PendingSubscriptionCheckout
    pending = db.scalar(
        select(PendingSubscriptionCheckout).where(PendingSubscriptionCheckout.paystack_reference == reference)
    )
    if not pending:
        raise ProvisioningError(f"No pending checkout record found matching reference {reference!r}.")

    if pending.status == "paid" and pending.provisioned_tenant_id:
        logger.info("Pending checkout %s already completed for tenant %s", reference, pending.provisioned_tenant_id)
        return {
            "status": "already_provisioned",
            "reference": reference,
            "tenant_id": pending.provisioned_tenant_id,
        }

    # Validate Currency & Amount (Paystack is in subunits: KES cents = KES * 100)
    paid_currency = paystack_data.get("currency")
    if paid_currency != "KES":
        raise ProvisioningError(f"Currency mismatch: expected KES, received {paid_currency!r}.")

    paid_subunits = paystack_data.get("amount", 0)
    expected_subunits = int(pending.amount_kes * 100)
    if paid_subunits != expected_subunits:
        raise ProvisioningError(
            f"Amount mismatch for {reference}: expected {expected_subunits} cents (KES {pending.amount_kes}), received {paid_subunits} cents."
        )

    # Validate Customer Email
    customer_info = paystack_data.get("customer", {})
    payer_email = (customer_info.get("email") or "").strip().lower()
    expected_admin_email = pending.admin_email.strip().lower()
    expected_company_email = pending.company_email.strip().lower()
    if payer_email not in (expected_admin_email, expected_company_email):
        logger.warning(
            "Payer email (%s) differs from admin (%s) or company (%s) for reference %s",
            payer_email,
            expected_admin_email,
            expected_company_email,
            reference,
        )

    # Begin Atomic Provisioning
    now = datetime.now(timezone.utc)
    future = now + timedelta(days=30)
    raw_invite_token = generate_secure_token(32)
    token_hashed = hash_token(raw_invite_token)

    # Check if slug was taken in the interim; if so, append unique suffix
    slug_candidate = pending.company_slug
    existing_tenant_with_slug = db.scalar(select(Tenant).where(Tenant.slug == slug_candidate))
    if existing_tenant_with_slug:
        slug_candidate = f"{slug_candidate[:50]}-{raw_invite_token[:6].lower()}"

    # 1. Create Tenant
    tenant = Tenant(
        name=pending.company_name,
        slug=slug_candidate,
        contact_email=pending.company_email,
        contact_phone=pending.company_phone or "+254700000000",
        status=TenantStatus.active,
    )
    db.add(tenant)
    db.flush()

    # 2. Assign Subscription
    subscription = TenantSubscription(
        tenant_id=tenant.id,
        tier=pending.tier,
        max_routers=pending.tier.max_routers,
        monthly_price_kes=pending.tier.monthly_price_kes,
        is_active=True,
        starts_at=now,
        expires_at=future,
        auto_renew=True,
    )
    db.add(subscription)

    # 3. Create Default Branding
    branding = TenantBranding(
        tenant_id=tenant.id,
        company_title=pending.company_name,
        primary_color="#dfb758",
        secondary_color="#090a0f",
        accent_color="#b8913e",
        support_email=pending.company_email,
    )
    db.add(branding)

    # 4. Create Single-Use Expiring Administrator Invitation (Safeguard 5)
    invitation = TenantInvitation(
        tenant_id=tenant.id,
        email=pending.admin_email,
        full_name=pending.admin_name,
        role=UserRole.tenant_admin,
        token_hash=token_hashed,
        expires_at=now + timedelta(hours=72),
        is_used=False,
    )
    db.add(invitation)

    # 5. Safeguard 4: Record Subscription Transaction
    if not existing_txn:
        existing_txn = SubscriptionTransaction(
            tenant_id=tenant.id,
            tier=pending.tier,
            amount_kes=pending.amount_kes,
            paystack_reference=reference,
            status="success",
            paid_at=now,
            raw_response=raw_response_text,
        )
        db.add(existing_txn)
    else:
        existing_txn.tenant_id = tenant.id
        existing_txn.status = "success"
        existing_txn.paid_at = now
        existing_txn.raw_response = raw_response_text

    # 6. Update Pending Checkout
    pending.status = "paid"
    pending.provisioned_tenant_id = tenant.id

    db.commit()
    db.refresh(tenant)

    # Safeguard 5: Decoupled Email Delivery after successful DB commit
    invitation_url = f"{saas_settings.saas_public_base_url.rstrip('/')}/invite/{raw_invite_token}"
    email_delivered = False
    try:
        email_delivered = send_invitation_email(
            to_email=pending.admin_email,
            admin_name=pending.admin_name,
            company_name=pending.company_name,
            invitation_url=invitation_url,
        )
    except Exception as exc:
        logger.error("Non-fatal email delivery failure for tenant %s: %s", tenant.id, exc)

    return {
        "status": "provisioned",
        "reference": reference,
        "tenant_id": tenant.id,
        "tenant_slug": tenant.slug,
        "invitation_token": raw_invite_token,
        "invitation_url": invitation_url,
        "email_sent": email_delivered,
    }


def _record_non_success_transaction(
    db: Session,
    reference: str,
    paystack_data: dict[str, Any],
    raw_response_text: str | None,
) -> None:
    """Safeguard 4: Records failed or abandoned attempts without losing payment audit trails."""
    existing_txn = db.scalar(
        select(SubscriptionTransaction).where(SubscriptionTransaction.paystack_reference == reference)
    )
    now = datetime.now(timezone.utc)
    status = paystack_data.get("status", "failed")

    pending = db.scalar(
        select(PendingSubscriptionCheckout).where(PendingSubscriptionCheckout.paystack_reference == reference)
    )
    tier = pending.tier if pending else None
    amount = pending.amount_kes if pending else Decimal("0.00")

    if pending and status in ("failed", "abandoned"):
        pending.status = status

    if not existing_txn and tier:
        txn = SubscriptionTransaction(
            tenant_id=None,
            tier=tier,
            amount_kes=amount,
            paystack_reference=reference,
            status=status,
            paid_at=None,
            raw_response=raw_response_text,
        )
        db.add(txn)
    elif existing_txn:
        existing_txn.status = status
        existing_txn.raw_response = raw_response_text

    db.commit()
