"""Automated test suite for the November 22, 2026 Hotspot Security Remediation milestone.

Validates:
1. M-Pesa callback token authentication, amount validation, receipt deduplication, and STK query.
2. Paystack HMAC signature verification, currency checking, and cross-tenant reference isolation.
3. Two-stage voucher activation (pending_provisioning -> active on router ACK, or provisioning_failed on router error).
4. Captive portal tenant isolation (rejection of missing/invalid tenant slugs) and login URL sanitization.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from decimal import Decimal
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from saas.models.hotspot import HotspotNetwork, HotspotPackage, HotspotVoucher, VoucherStatus
from saas.models.payments import CustomerPayment, TenantPaymentConfig
from saas.models.router import Router, RouterCommand, RouterCommandStatus
from saas.models.tenant import Tenant
from saas.routers.portal import validate_captive_login_url
from saas.services.daraja import query_stk_status
from saas.services.hotspot_billing import complete_hotspot_payment, get_hotspot_payment_status


# =====================================================================
# 1. M-Pesa Callback Security & Validation Tests
# =====================================================================

def test_mpesa_callback_rejects_missing_or_invalid_token(client: TestClient, db_session: Session, seed_data: dict):
    """M-Pesa webhook callback MUST return 401 Unauthorized if token is absent or invalid."""
    tenant_a = seed_data["tenant_a"]

    pay_config = TenantPaymentConfig(tenant_id=tenant_a.id, mpesa_enabled=True)
    real_token = pay_config.generate_callback_token()
    db_session.add(pay_config)
    db_session.commit()

    payload = {"Body": {"stkCallback": {"CheckoutRequestID": "ws_TEST_1", "ResultCode": 0}}}

    # Case A: Missing token
    resp_no_token = client.post(f"/api/webhook/mpesa/{tenant_a.id}", json=payload)
    assert resp_no_token.status_code == 401

    # Case B: Forged token
    resp_bad_token = client.post(f"/api/webhook/mpesa/{tenant_a.id}?token=bad_forged_token", json=payload)
    assert resp_bad_token.status_code == 401

    # Case C: Valid token
    resp_ok_token = client.post(f"/api/webhook/mpesa/{tenant_a.id}?token={real_token}", json=payload)
    # 200 accepted (even though checkout_id ws_TEST_1 does not exist in DB)
    assert resp_ok_token.status_code == 200


def test_mpesa_callback_rejects_incorrect_amount(client: TestClient, db_session: Session, seed_data: dict):
    """M-Pesa callback MUST reject and fail transaction if customer paid less or more than package price."""
    tenant_a = seed_data["tenant_a"]
    router_a = seed_data["router_a"]

    pkg = HotspotPackage(
        tenant_id=tenant_a.id,
        name="KES 100 24h Pass",
        duration_minutes=1440,
        price_kes=Decimal("100.00"),
    )
    db_session.add(pkg)
    db_session.flush()

    pay_config = TenantPaymentConfig(tenant_id=tenant_a.id, mpesa_enabled=True)
    token = pay_config.generate_callback_token()
    db_session.add(pay_config)

    payment = CustomerPayment(
        tenant_id=tenant_a.id,
        package_id=pkg.id,
        router_id=router_a.id,
        gateway="mpesa",
        reference="HPAY-AMOUNT-TEST",
        checkout_request_id="ws_REQ_AMOUNT_99",
        amount_kes=Decimal("100.00"),
        status="pending",
    )
    db_session.add(payment)
    db_session.commit()

    # Callback indicates customer paid only KES 1.00 instead of 100.00
    tampered_payload = {
        "Body": {
            "stkCallback": {
                "CheckoutRequestID": "ws_REQ_AMOUNT_99",
                "ResultCode": 0,
                "ResultDesc": "Success",
                "CallbackMetadata": {
                    "Item": [
                        {"Name": "Amount", "Value": 1.00},
                        {"Name": "MpesaReceiptNumber", "Value": "QGH111BAD"},
                    ]
                },
            }
        }
    }

    resp = client.post(f"/api/webhook/mpesa/{tenant_a.id}?token={token}", json=tampered_payload)
    assert resp.status_code == 200

    db_session.refresh(payment)
    # Payment must be marked failed, and NO voucher generated
    assert payment.status == "failed"
    assert payment.voucher_id is None


def test_mpesa_callback_rejects_duplicate_receipt(client: TestClient, db_session: Session, seed_data: dict):
    """M-Pesa callback MUST reject receipt numbers that were already recorded on another payment."""
    tenant_a = seed_data["tenant_a"]
    router_a = seed_data["router_a"]

    pkg = HotspotPackage(tenant_id=tenant_a.id, name="Pass", duration_minutes=60, price_kes=Decimal("20.00"))
    db_session.add(pkg)
    db_session.flush()

    # Pre-existing completed payment with receipt QGH_EXISTING_1
    existing_p = CustomerPayment(
        tenant_id=tenant_a.id,
        package_id=pkg.id,
        router_id=router_a.id,
        gateway="mpesa",
        reference="HPAY-EXISTING-1",
        provider_reference="QGH_EXISTING_1",
        amount_kes=Decimal("20.00"),
        status="completed",
    )
    # New pending payment
    new_p = CustomerPayment(
        tenant_id=tenant_a.id,
        package_id=pkg.id,
        router_id=router_a.id,
        gateway="mpesa",
        reference="HPAY-ATTACK-2",
        checkout_request_id="ws_REQ_DUP_RECEIPT",
        amount_kes=Decimal("20.00"),
        status="pending",
    )
    pay_config = TenantPaymentConfig(tenant_id=tenant_a.id, mpesa_enabled=True)
    token = pay_config.generate_callback_token()
    db_session.add_all([existing_p, new_p, pay_config])
    db_session.commit()

    replayed_payload = {
        "Body": {
            "stkCallback": {
                "CheckoutRequestID": "ws_REQ_DUP_RECEIPT",
                "ResultCode": 0,
                "CallbackMetadata": {
                    "Item": [
                        {"Name": "Amount", "Value": 20.00},
                        {"Name": "MpesaReceiptNumber", "Value": "QGH_EXISTING_1"},
                    ]
                },
            }
        }
    }

    resp = client.post(f"/api/webhook/mpesa/{tenant_a.id}?token={token}", json=replayed_payload)
    assert resp.status_code == 200

    db_session.refresh(new_p)
    assert new_p.status == "failed"
    assert new_p.voucher_id is None


def test_stk_query_status():
    """Verify Safaricom Daraja STK Query service helper."""
    with patch("httpx.post") as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {
            "ResponseCode": "0",
            "ResponseDescription": "Success",
            "MerchantRequestID": "29115-34620561-1",
            "CheckoutRequestID": "ws_QUERY_123",
            "ResultCode": "0",
            "ResultDesc": "The service request is processed successfully.",
        }
        with patch("saas.services.daraja.get_oauth_token", return_value="mock_token"):
            query_res = query_stk_status(
                consumer_key="key",
                consumer_secret="secret",
                passkey="passkey",
                shortcode="174379",
                checkout_request_id="ws_QUERY_123",
            )
            assert query_res["is_successful"] is True
            assert query_res["result_code"] == 0


# =====================================================================
# 2. Paystack Security & Isolation Tests
# =====================================================================

def test_paystack_webhook_rejects_invalid_signature(client: TestClient, db_session: Session, seed_data: dict):
    """Paystack webhook MUST return 401 when HMAC-SHA512 signature is invalid."""
    tenant_a = seed_data["tenant_a"]
    pay_config = TenantPaymentConfig(tenant_id=tenant_a.id, paystack_enabled=True)
    pay_config.set_paystack_secret("sk_test_alpha_secret")
    db_session.add(pay_config)
    db_session.commit()

    payload = json.dumps({"event": "charge.success", "data": {"reference": "HPAY-1"}}).encode("utf-8")
    resp = client.post(
        f"/api/webhook/paystack/{tenant_a.id}",
        content=payload,
        headers={"x-paystack-signature": "invalid_hex_signature"},
    )
    assert resp.status_code == 401


def test_paystack_webhook_cross_tenant_isolation(client: TestClient, db_session: Session, seed_data: dict):
    """Paystack webhook for Tenant A MUST NOT complete or activate a payment belonging to Tenant B."""
    tenant_a = seed_data["tenant_a"]
    tenant_b = seed_data["tenant_b"]
    router_b = seed_data["router_b"]

    pkg_b = HotspotPackage(tenant_id=tenant_b.id, name="Beta Pass", duration_minutes=60, price_kes=Decimal("50.00"))
    db_session.add(pkg_b)
    db_session.flush()

    payment_b = CustomerPayment(
        tenant_id=tenant_b.id,
        package_id=pkg_b.id,
        router_id=router_b.id,
        gateway="paystack",
        reference="HPAY-TENANT-B-TARGET",
        amount_kes=Decimal("50.00"),
        status="pending",
    )
    db_session.add(payment_b)

    secret_a = "sk_test_alpha_secret"
    pay_config_a = TenantPaymentConfig(tenant_id=tenant_a.id, paystack_enabled=True)
    pay_config_a.set_paystack_secret(secret_a)
    db_session.add(pay_config_a)
    db_session.commit()

    # Attacker posts to Tenant A's webhook with Tenant A's valid signature, but pointing to Tenant B's reference
    event_payload = {
        "event": "charge.success",
        "data": {
            "reference": "HPAY-TENANT-B-TARGET",
            "amount": 5000,
            "currency": "KES",
            "status": "success",
        },
    }
    body_bytes = json.dumps(event_payload).encode("utf-8")
    signature = hmac.new(secret_a.encode("utf-8"), body_bytes, hashlib.sha512).hexdigest()

    resp = client.post(
        f"/api/webhook/paystack/{tenant_a.id}",
        content=body_bytes,
        headers={"x-paystack-signature": signature, "Content-Type": "application/json"},
    )
    assert resp.status_code == 200
    assert resp.json().get("reason") == "Unknown reference for tenant"

    db_session.refresh(payment_b)
    # Payment B remains pending; Tenant A cannot activate Tenant B's voucher
    assert payment_b.status == "pending"
    assert payment_b.voucher_id is None


def test_paystack_webhook_rejects_wrong_currency_or_amount(client: TestClient, db_session: Session, seed_data: dict):
    """Paystack webhook rejects USD or mismatched amounts."""
    tenant_a = seed_data["tenant_a"]
    router_a = seed_data["router_a"]

    pkg = HotspotPackage(tenant_id=tenant_a.id, name="Pass", duration_minutes=60, price_kes=Decimal("50.00"))
    db_session.add(pkg)
    db_session.flush()

    payment = CustomerPayment(
        tenant_id=tenant_a.id,
        package_id=pkg.id,
        router_id=router_a.id,
        gateway="paystack",
        reference="HPAY-CURR-TEST",
        amount_kes=Decimal("50.00"),
        status="pending",
    )
    secret = "sk_test_curr_secret"
    pay_config = TenantPaymentConfig(tenant_id=tenant_a.id, paystack_enabled=True)
    pay_config.set_paystack_secret(secret)
    db_session.add_all([payment, pay_config])
    db_session.commit()

    # Wrong currency (USD instead of KES)
    payload_usd = {
        "event": "charge.success",
        "data": {"reference": "HPAY-CURR-TEST", "amount": 5000, "currency": "USD"},
    }
    body = json.dumps(payload_usd).encode()
    sig = hmac.new(secret.encode(), body, hashlib.sha512).hexdigest()
    resp = client.post(f"/api/webhook/paystack/{tenant_a.id}", content=body, headers={"x-paystack-signature": sig})
    assert resp.status_code == 200
    assert resp.json().get("status") == "error"

    db_session.refresh(payment)
    assert payment.status == "failed"


# =====================================================================
# 3. Two-Stage Voucher Lifecycle & Router Acknowledgement Tests
# =====================================================================

def test_two_stage_voucher_lifecycle(client: TestClient, db_session: Session, seed_data: dict):
    """Verifies that vouchers remain unusable in pending_provisioning until physical router ACKs success."""
    tenant_a = seed_data["tenant_a"]
    router_a = seed_data["router_a"]

    pkg = HotspotPackage(tenant_id=tenant_a.id, name="2 Hr Pass", duration_minutes=120, price_kes=Decimal("40.00"))
    db_session.add(pkg)
    db_session.flush()

    payment = CustomerPayment(
        tenant_id=tenant_a.id,
        package_id=pkg.id,
        router_id=router_a.id,
        gateway="mpesa",
        reference="HPAY-TWO-STAGE-01",
        amount_kes=Decimal("40.00"),
        status="pending",
    )
    db_session.add(payment)
    db_session.commit()

    # Step 1: Query status before payment -> awaiting_payment
    st_await = get_hotspot_payment_status(db_session, payment.reference)
    assert st_await["status"] == "awaiting_payment"

    # Step 2: Payment verified via provider
    res_paid = complete_hotspot_payment(
        db_session,
        reference=payment.reference,
        tenant_id=tenant_a.id,
        gateway="mpesa",
        receipt_number="QGH_STAGE_123",
        verified_amount_kes=Decimal("40.00"),
    )
    assert res_paid["status"] == "provisioning"
    assert res_paid["voucher_code"] is None  # Code withheld while pending provisioning

    # Check database state: voucher is pending_provisioning
    voucher = db_session.scalar(select(HotspotVoucher).where(HotspotVoucher.customer_payment_id == payment.id))
    assert voucher is not None
    assert voucher.status == VoucherStatus.pending_provisioning

    # Status endpoint reports provisioning (not completed!)
    st_prov = get_hotspot_payment_status(db_session, payment.reference)
    assert st_prov["status"] == "provisioning"
    assert "voucher_code" not in st_prov

    # Step 3: Router acknowledges command execution
    cmd = db_session.scalar(select(RouterCommand).where(RouterCommand.id == voucher.router_command_id))
    assert cmd is not None

    ack_resp = client.post(
        "/api/router/ack",
        headers={"X-Router-Token": "alpha_token_1"},
        data={"ok": cmd.id, "failed": ""},
    )
    assert ack_resp.status_code == 200

    db_session.refresh(voucher)
    assert voucher.status == VoucherStatus.active

    # Step 4: Now polling endpoint returns completed with voucher credentials
    st_done = get_hotspot_payment_status(db_session, payment.reference)
    assert st_done["status"] == "completed"
    assert st_done["voucher_code"] == voucher.code


def test_router_acknowledgement_failure_handling(client: TestClient, db_session: Session, seed_data: dict):
    """When router fails to execute script, voucher transitions to provisioning_failed, not active."""
    tenant_a = seed_data["tenant_a"]
    router_a = seed_data["router_a"]

    pkg = HotspotPackage(tenant_id=tenant_a.id, name="Pass", duration_minutes=60, price_kes=Decimal("30.00"))
    db_session.add(pkg)
    db_session.flush()

    payment = CustomerPayment(
        tenant_id=tenant_a.id,
        package_id=pkg.id,
        router_id=router_a.id,
        gateway="mpesa",
        reference="HPAY-FAIL-TEST-01",
        amount_kes=Decimal("30.00"),
        status="pending",
    )
    db_session.add(payment)
    db_session.commit()

    complete_hotspot_payment(
        db_session,
        reference=payment.reference,
        tenant_id=tenant_a.id,
        gateway="mpesa",
        receipt_number="QGH_FAIL_123",
        verified_amount_kes=Decimal("30.00"),
    )

    voucher = db_session.scalar(select(HotspotVoucher).where(HotspotVoucher.customer_payment_id == payment.id))
    cmd = db_session.scalar(select(RouterCommand).where(RouterCommand.id == voucher.router_command_id))

    # Router reports command execution failed
    ack_resp = client.post(
        "/api/router/ack",
        headers={"X-Router-Token": "alpha_token_1"},
        data={"ok": "", "failed": cmd.id},
    )
    assert ack_resp.status_code == 200

    db_session.refresh(cmd)
    db_session.refresh(voucher)
    assert cmd.status == RouterCommandStatus.failed
    assert voucher.status == VoucherStatus.provisioning_failed

    # Customer polling reports failure
    st = get_hotspot_payment_status(db_session, payment.reference)
    assert st["status"] == "failed"


# =====================================================================
# 4. Captive Portal Tenant Isolation & URL Security Tests
# =====================================================================

def test_portal_rejects_missing_or_invalid_tenant_slug(client: TestClient, seed_data: dict):
    """Portal MUST return 404 when slug is missing, empty, or non-existent (no silent fallback!)."""
    # 1. Missing slug -> 404
    resp_empty = client.get("/portal")
    assert resp_empty.status_code == 404

    # 2. Non-existent slug -> 404
    resp_bad = client.get("/portal/this-tenant-does-not-exist-xyz")
    assert resp_bad.status_code == 404

    # 3. Valid tenant slug -> 200
    tenant_a = seed_data["tenant_a"]
    resp_ok = client.get(f"/portal/{tenant_a.slug}")
    assert resp_ok.status_code == 200


def test_captive_login_url_validation():
    """validate_captive_login_url strictly validates against network gateway IP and dns_name."""
    network = HotspotNetwork(
        router_id="r1",
        name="Net",
        gateway_ip="10.5.50.1",
        dns_name="login.hotspot",
    )

    # Valid cases
    assert validate_captive_login_url("http://10.5.50.1/login", network) == "http://10.5.50.1/login"
    assert validate_captive_login_url("http://login.hotspot/login", network) == "http://login.hotspot/login"
    assert validate_captive_login_url("http://10.5.50.1", network) == "http://10.5.50.1"

    # Malicious external attacker URL (phishing / credential stealing)
    assert validate_captive_login_url("https://attacker.com/login", network) is None
    assert validate_captive_login_url("http://evil-logger.com/capture", network) is None

    # Embedded credentials (user:pass@host)
    assert validate_captive_login_url("http://admin:pass@10.5.50.1/login", network) is None

    # Unlisted arbitrary private IP
    assert validate_captive_login_url("http://192.168.1.1/login", network) is None
    assert validate_captive_login_url("http://10.0.0.1/login", network) is None

    # Malicious protocols
    assert validate_captive_login_url("javascript:alert(1)", network) is None
    assert validate_captive_login_url("file:///etc/passwd", network) is None
