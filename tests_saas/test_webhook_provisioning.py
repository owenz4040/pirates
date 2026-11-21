"""Tests for durable, idempotent tenant provisioning and payment verification safeguards."""
from __future__ import annotations

from decimal import Decimal

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from saas.models.payments import PendingSubscriptionCheckout, SubscriptionTransaction
from saas.models.tenant import SubscriptionTier, Tenant, TenantInvitation, TenantStatus, TenantSubscription
from saas.services.provisioning import ProvisioningError, process_payment_and_provision


@pytest.fixture
def pending_checkout(db_session: Session) -> PendingSubscriptionCheckout:
    """Creates a sample pending checkout record."""
    pending = PendingSubscriptionCheckout(
        paystack_reference="ref_test_starter_1001",
        company_name="Kifaru Networks",
        company_slug="kifaru-net",
        company_email="billing@kifaru.net",
        company_phone="+254711223344",
        admin_name="James Mwangi",
        admin_email="james@kifaru.net",
        tier=SubscriptionTier.starter,
        amount_kes=Decimal("1000.00"),
        currency="KES",
        status="pending",
    )
    db_session.add(pending)
    db_session.commit()
    return pending


def test_successful_provisioning_flow(db_session: Session, pending_checkout: PendingSubscriptionCheckout):
    """
    Test complete provisioning upon verified payment:
    Creates Tenant, Subscription, Branding, Invitation, and SubscriptionTransaction.
    """
    paystack_data = {
        "reference": pending_checkout.paystack_reference,
        "status": "success",
        "currency": "KES",
        "amount": 100000,  # 1,000.00 KES in cents
        "customer": {"email": "james@kifaru.net"},
    }

    result = process_payment_and_provision(db_session, paystack_data)

    assert result["status"] == "provisioned"
    assert result["reference"] == pending_checkout.paystack_reference
    assert result["tenant_slug"] == "kifaru-net"
    assert "invitation_token" in result
    assert result["invitation_url"].startswith("http")

    # Verify database state
    tenant = db_session.scalar(select(Tenant).where(Tenant.id == result["tenant_id"]))
    assert tenant is not None
    assert tenant.name == "Kifaru Networks"
    assert tenant.status == TenantStatus.active

    # Subscription checks
    assert tenant.subscription is not None
    assert tenant.subscription.tier == SubscriptionTier.starter
    assert tenant.subscription.max_routers == 1

    # Invitation checks (Safeguard 5: token is hashed, not plaintext)
    invitation = db_session.scalar(select(TenantInvitation).where(TenantInvitation.tenant_id == tenant.id))
    assert invitation is not None
    assert invitation.email == "james@kifaru.net"
    assert invitation.is_used is False
    assert len(invitation.token_hash) == 64
    assert result["invitation_token"] not in invitation.token_hash

    # Transaction audit checks (Safeguard 4)
    txn = db_session.scalar(
        select(SubscriptionTransaction).where(SubscriptionTransaction.paystack_reference == pending_checkout.paystack_reference)
    )
    assert txn is not None
    assert txn.status == "success"
    assert txn.tenant_id == tenant.id


def test_idempotent_webhook_processing(db_session: Session, pending_checkout: PendingSubscriptionCheckout):
    """Safeguard 2: Repeated webhook calls for same reference do not create duplicate tenants."""
    paystack_data = {
        "reference": pending_checkout.paystack_reference,
        "status": "success",
        "currency": "KES",
        "amount": 100000,
        "customer": {"email": "james@kifaru.net"},
    }

    # First run
    res1 = process_payment_and_provision(db_session, paystack_data)
    assert res1["status"] == "provisioned"
    tenant_id = res1["tenant_id"]

    # Second run (duplicate webhook delivery)
    res2 = process_payment_and_provision(db_session, paystack_data)
    assert res2["status"] == "already_provisioned"
    assert res2["tenant_id"] == tenant_id

    # Verify only ONE tenant and ONE transaction exist
    tenants = db_session.scalars(select(Tenant).where(Tenant.slug == "kifaru-net")).all()
    assert len(tenants) == 1

    txns = db_session.scalars(
        select(SubscriptionTransaction).where(SubscriptionTransaction.paystack_reference == pending_checkout.paystack_reference)
    ).all()
    assert len(txns) == 1


def test_amount_mismatch_rejected(db_session: Session, pending_checkout: PendingSubscriptionCheckout):
    """Safeguard 3: If amount received is less or mismatched, reject provisioning."""
    paystack_data = {
        "reference": pending_checkout.paystack_reference,
        "status": "success",
        "currency": "KES",
        "amount": 50000,  # 500 KES instead of 1,000 KES
        "customer": {"email": "james@kifaru.net"},
    }

    with pytest.raises(ProvisioningError) as exc_info:
        process_payment_and_provision(db_session, paystack_data)

    assert "Amount mismatch" in str(exc_info.value)

    # Ensure no tenant was created
    tenant = db_session.scalar(select(Tenant).where(Tenant.slug == "kifaru-net"))
    assert tenant is None


def test_currency_mismatch_rejected(db_session: Session, pending_checkout: PendingSubscriptionCheckout):
    """Safeguard 3: If currency is not KES, reject provisioning."""
    paystack_data = {
        "reference": pending_checkout.paystack_reference,
        "status": "success",
        "currency": "USD",
        "amount": 100000,
        "customer": {"email": "james@kifaru.net"},
    }

    with pytest.raises(ProvisioningError) as exc_info:
        process_payment_and_provision(db_session, paystack_data)

    assert "Currency mismatch" in str(exc_info.value)


def test_failed_paystack_payment_recorded(db_session: Session, pending_checkout: PendingSubscriptionCheckout):
    """Safeguard 4: Failed payment records are retained for auditing."""
    paystack_data = {
        "reference": pending_checkout.paystack_reference,
        "status": "failed",
        "gateway_response": "Insufficient funds",
    }

    res = process_payment_and_provision(db_session, paystack_data)
    assert res["status"] == "payment_not_successful"

    txn = db_session.scalar(
        select(SubscriptionTransaction).where(SubscriptionTransaction.paystack_reference == pending_checkout.paystack_reference)
    )
    assert txn is not None
    assert txn.status == "failed"


def test_api_webhook_signature_rejection(client):
    """Test that POST /api/webhooks/paystack rejects missing or invalid signatures with 401."""
    payload = b'{"event":"charge.success"}'

    # 1. Missing header
    res1 = client.post("/api/webhooks/paystack", content=payload)
    assert res1.status_code == 401

    # 2. Bogus signature
    res2 = client.post(
        "/api/webhooks/paystack",
        content=payload,
        headers={"x-paystack-signature": "bogus_signature_abc123"},
    )
    assert res2.status_code == 401


def test_api_webhook_valid_signature_provisions_tenant(client, db_session: Session, pending_checkout: PendingSubscriptionCheckout, monkeypatch):
    """Test that POST /api/webhooks/paystack with valid signature provisions tenant end-to-end."""
    import hashlib
    import hmac
    import json
    from saas.config import saas_settings

    secret = "test_platform_secret_for_webhook_456"
    monkeypatch.setattr(saas_settings, "platform_paystack_secret_key", secret)

    event_payload = {
        "event": "charge.success",
        "data": {
            "reference": pending_checkout.paystack_reference,
            "status": "success",
            "currency": "KES",
            "amount": 100000,
            "customer": {"email": "james@kifaru.net"},
        },
    }
    raw_body = json.dumps(event_payload).encode("utf-8")
    valid_sig = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha512).hexdigest()

    response = client.post(
        "/api/webhooks/paystack",
        content=raw_body,
        headers={"x-paystack-signature": valid_sig, "content-type": "application/json"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["provisioning"]["status"] == "provisioned"

    # Verify tenant exists
    tenant = db_session.scalar(select(Tenant).where(Tenant.slug == "kifaru-net"))
    assert tenant is not None
    assert tenant.status == TenantStatus.active

