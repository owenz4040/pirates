"""Automated tests for customer hotspot captive portal, M-Pesa & Paystack billing, and router activation."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from decimal import Decimal
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from saas.models.hotspot import HotspotNetwork, HotspotPackage, HotspotPortalDesign, HotspotVoucher, VoucherStatus
from saas.models.payments import CustomerPayment, TenantPaymentConfig
from saas.models.router import Router, RouterCommand, RouterStatus
from saas.security.sanitizer import (
    build_hotspot_profile_command,
    build_hotspot_user_command,
    build_hotspot_walled_garden_command,
    format_routeros_duration,
    generate_routeros_captive_portal_templates,
)


def test_format_routeros_duration():
    """Verify conversion of minutes to RouterOS time strings."""
    assert format_routeros_duration(30) == "30m"
    assert format_routeros_duration(60) == "1h"
    assert format_routeros_duration(120) == "2h"
    assert format_routeros_duration(1440) == "1d"
    assert format_routeros_duration(4320) == "3d"
    assert format_routeros_duration(10080) == "7d"
    assert format_routeros_duration(43200) == "30d"
    assert format_routeros_duration(90) == "90m"


def test_build_hotspot_user_command_with_limits():
    """Verify command generation includes uptime limits and ownership markers."""
    cmd = build_hotspot_user_command(
        code="VOUCH-TEST1",
        password="secretpassword",
        profile="COwen-Profile-10M",
        voucher_id="vouch-456",
        limit_uptime_minutes=60,
        limit_bytes_total=1073741824,
    )
    assert 'name="VOUCH-TEST1"' in cmd
    assert 'password="secretpassword"' in cmd
    assert 'profile="COwen-Profile-10M"' in cmd
    assert 'limit-uptime="1h"' in cmd
    assert 'limit-bytes-total=1073741824' in cmd
    assert 'comment="COwen-Voucher:vouch-456"' in cmd


def test_build_hotspot_profile_command_with_timeout():
    """Verify hotspot profile includes session-timeout and keepalive."""
    cmd = build_hotspot_profile_command(
        name="COwen-Pkg-1Hr",
        rate_limit="5M/10M",
        session_timeout_minutes=60,
    )
    assert 'name="COwen-Pkg-1Hr"' in cmd
    assert 'rate-limit="5M/10M"' in cmd
    assert 'session-timeout="1h"' in cmd
    assert 'keepalive-timeout=2m' in cmd


def test_build_hotspot_walled_garden():
    """Verify walled garden entries whitelist portal and payment providers."""
    script = build_hotspot_walled_garden_command(portal_host="cowen.vercel.app")
    assert "/ip hotspot walled-garden" in script
    assert 'dst-host="cowen.vercel.app"' in script
    assert 'dst-host="*.paystack.com"' in script
    assert 'dst-host="*.safaricom.co.ke"' in script
    assert 'dst-host="connectivitycheck.gstatic.com"' in script
    assert 'dst-host="captive.apple.com"' in script


def test_generate_captive_portal_templates():
    """Verify RouterOS captive portal template generation."""
    templates = generate_routeros_captive_portal_templates(
        portal_base_url="https://cowen.vercel.app/portal",
        tenant_slug="alpha-isp",
        brand_name="Pirate's WiFi",
    )
    assert "login.html" in templates
    assert "alogin.html" in templates
    assert "status.html" in templates
    assert "https://cowen.vercel.app/portal" in templates["login.html"]
    assert "Pirate's WiFi" in templates["login.html"]
    assert "$(link-login-only)" in templates["login.html"]


def test_portal_landing_page(client: TestClient, db_session: Session, seed_data: dict):
    """Test public captive portal page for a tenant."""
    tenant_a = seed_data["tenant_a"]
    
    design = HotspotPortalDesign(
        tenant_id=tenant_a.id,
        brand_name="Alpha Ultra WiFi",
        headline="Fast & Affordable Surfing",
        primary_color="#dfb758",
    )
    db_session.add(design)

    pkg = HotspotPackage(
        tenant_id=tenant_a.id,
        name="1 Hour Pass",
        duration_minutes=60,
        price_kes=Decimal("20.00"),
        rate_limit="5M/5M",
        is_active=True,
    )
    db_session.add(pkg)
    db_session.commit()

    resp = client.get(f"/portal/{tenant_a.slug}")
    assert resp.status_code == 200
    html = resp.text
    assert "Alpha Ultra WiFi" in html
    assert "Fast &amp; Affordable Surfing" in html or "Fast & Affordable Surfing" in html
    assert "1 Hour Pass" in html


def test_mpesa_purchase_initiation(client: TestClient, db_session: Session, seed_data: dict):
    """Test client initiating M-Pesa STK push on the portal."""
    tenant_a = seed_data["tenant_a"]
    router_a = seed_data["router_a"]

    pkg = HotspotPackage(
        tenant_id=tenant_a.id,
        name="10 Min Blast",
        duration_minutes=10,
        price_kes=Decimal("10.00"),
        rate_limit="5M/5M",
        is_active=True,
    )
    db_session.add(pkg)

    pay_config = TenantPaymentConfig(
        tenant_id=tenant_a.id,
        mpesa_enabled=True,
        mpesa_shortcode="174379",
    )
    pay_config.set_mpesa_credentials("consumer_key", "consumer_secret", "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919")
    db_session.add(pay_config)
    db_session.commit()

    mock_stk_result = {
        "success": True,
        "checkout_request_id": "ws_CO_TEST_998877",
        "merchant_request_id": "mr_TEST_123",
        "customer_phone": "254712345678",
    }

    with patch("saas.services.hotspot_billing.initiate_stk_push", return_value=mock_stk_result):
        resp = client.post(
            "/api/portal/purchase",
            json={
                "tenant_slug": tenant_a.slug,
                "package_id": pkg.id,
                "router_id": router_a.id,
                "gateway": "mpesa",
                "customer_phone": "0712345678",
                "client_mac": "AA:BB:CC:DD:EE:FF",
                "client_ip": "10.5.50.45",
                "link_login_only": "http://10.5.50.1/login",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "stk_sent"
        assert data["checkout_request_id"] == "ws_CO_TEST_998877"
        assert "reference" in data

        reference = data["reference"]
        payment = db_session.scalar(select(CustomerPayment).where(CustomerPayment.reference == reference))
        assert payment is not None
        assert payment.status == "pending"
        assert payment.gateway == "mpesa"


def test_mpesa_callback_automatic_activation(client: TestClient, db_session: Session, seed_data: dict):
    """Test Safaricom Daraja STK callback automatically activates voucher and queues router command."""
    tenant_a = seed_data["tenant_a"]
    router_a = seed_data["router_a"]

    pkg = HotspotPackage(
        tenant_id=tenant_a.id,
        name="1 Day Pass",
        duration_minutes=1440,
        price_kes=Decimal("50.00"),
        rate_limit="10M/10M",
        is_active=True,
    )
    db_session.add(pkg)
    db_session.flush()

    payment = CustomerPayment(
        tenant_id=tenant_a.id,
        package_id=pkg.id,
        router_id=router_a.id,
        gateway="mpesa",
        reference="CO-HOT-MP-TEST01",
        amount_kes=Decimal("50.00"),
        phone_number="254712345678",
        status="pending",
        client_mac="AA:BB:CC:DD:EE:FF",
        client_ip="10.5.50.45",
        link_login_only="http://10.5.50.1/login",
        metadata_json=json.dumps({"checkout_request_id": "ws_CO_TEST_CALLBACK_11"}),
    )
    db_session.add(payment)
    db_session.commit()

    callback_payload = {
        "Body": {
            "stkCallback": {
                "MerchantRequestID": "29115-34620561-1",
                "CheckoutRequestID": "ws_CO_TEST_CALLBACK_11",
                "ResultCode": 0,
                "ResultDesc": "The service request is processed successfully.",
                "CallbackMetadata": {
                    "Item": [
                        {"Name": "Amount", "Value": 50.00},
                        {"Name": "MpesaReceiptNumber", "Value": "QGH786XYZ"},
                        {"Name": "TransactionDate", "Value": 20261122120000},
                        {"Name": "PhoneNumber", "Value": 254712345678},
                    ]
                },
            }
        }
    }

    resp = client.post(f"/api/webhook/mpesa/{tenant_a.id}", json=callback_payload)
    assert resp.status_code == 200
    res_data = resp.json()
    assert res_data["ResultCode"] == 0

    db_session.refresh(payment)
    assert payment.status == "completed"
    assert payment.provider_reference == "QGH786XYZ"
    assert payment.paid_at is not None

    voucher = db_session.scalar(
        select(HotspotVoucher).where(HotspotVoucher.customer_payment_id == payment.id)
    )
    assert voucher is not None
    assert voucher.status == VoucherStatus.active
    assert voucher.package_id == pkg.id
    assert voucher.tenant_id == tenant_a.id

    cmd = db_session.scalar(
        select(RouterCommand)
        .where(RouterCommand.router_id == router_a.id)
        .order_by(RouterCommand.created_at.desc())
    )
    assert cmd is not None
    assert voucher.code in cmd.script
    assert f"COwen-Voucher:{voucher.id}" in cmd.script
    assert cmd.status == "pending"


def test_paystack_webhook_automatic_activation(client: TestClient, db_session: Session, seed_data: dict):
    """Test Paystack charge.success webhook activates voucher with HMAC signature."""
    tenant_a = seed_data["tenant_a"]
    router_a = seed_data["router_a"]

    pkg = HotspotPackage(
        tenant_id=tenant_a.id,
        name="Weekly Surfer",
        duration_minutes=10080,
        price_kes=Decimal("250.00"),
        rate_limit="8M/8M",
        is_active=True,
    )
    db_session.add(pkg)
    db_session.flush()

    payment = CustomerPayment(
        tenant_id=tenant_a.id,
        package_id=pkg.id,
        router_id=router_a.id,
        gateway="paystack",
        reference="HPAY-PAYSTACK-TEST99",
        amount_kes=Decimal("250.00"),
        status="pending",
        link_login_only="http://10.5.50.1/login",
    )
    db_session.add(payment)

    secret = "sk_test_mock_secret_key_12345"
    pay_config = TenantPaymentConfig(
        tenant_id=tenant_a.id,
        paystack_enabled=True,
        paystack_public_key="pk_test_123",
    )
    pay_config.set_paystack_secret(secret)
    db_session.add(pay_config)
    db_session.commit()

    event_payload = {
        "event": "charge.success",
        "data": {
            "reference": "HPAY-PAYSTACK-TEST99",
            "amount": 25000,
            "currency": "KES",
            "status": "success",
        },
    }
    body_bytes = json.dumps(event_payload).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha512).hexdigest()

    resp = client.post(
        f"/api/webhook/paystack/{tenant_a.id}",
        content=body_bytes,
        headers={"x-paystack-signature": signature, "Content-Type": "application/json"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"

    db_session.refresh(payment)
    assert payment.status == "completed"
    assert payment.paid_at is not None

    voucher = db_session.scalar(
        select(HotspotVoucher).where(HotspotVoucher.customer_payment_id == payment.id)
    )
    assert voucher is not None
    assert voucher.status == VoucherStatus.active
    assert voucher.package_id == pkg.id


def test_payment_status_polling(client: TestClient, db_session: Session, seed_data: dict):
    """Test polling endpoint used by captive portal for auto-login."""
    tenant_a = seed_data["tenant_a"]
    router_a = seed_data["router_a"]

    pkg = HotspotPackage(
        tenant_id=tenant_a.id,
        name="Speed Pass",
        duration_minutes=60,
        price_kes=Decimal("20.00"),
    )
    db_session.add(pkg)
    db_session.flush()

    payment = CustomerPayment(
        tenant_id=tenant_a.id,
        package_id=pkg.id,
        router_id=router_a.id,
        gateway="mpesa",
        reference="CO-HOT-POLL-123",
        amount_kes=Decimal("20.00"),
        status="pending",
        link_login_only="http://10.5.50.1/login",
    )
    db_session.add(payment)
    db_session.commit()

    resp = client.get(f"/api/portal/payment-status?reference={payment.reference}")
    assert resp.status_code == 200
    assert resp.json()["status"] == "pending"

    voucher = HotspotVoucher(
        tenant_id=tenant_a.id,
        package_id=pkg.id,
        router_id=router_a.id,
        code="POLL-VOUCH-77",
        password="secretpassword",
        status=VoucherStatus.active,
        customer_payment_id=payment.id,
    )
    db_session.add(voucher)
    db_session.flush()

    payment.status = "completed"
    payment.voucher_id = voucher.id
    db_session.commit()

    resp = client.get(f"/api/portal/payment-status?reference={payment.reference}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed"
    assert data["voucher_code"] == "POLL-VOUCH-77"
    assert data["voucher_password"] == "secretpassword"
    assert data["link_login_only"] == "http://10.5.50.1/login"


def test_tenant_walled_garden_and_template_downloads(client: TestClient, db_session: Session, seed_data: dict):
    """Test downloading walled garden rules and portal templates from tenant dashboard."""
    user_a = seed_data["user_a"]

    get_resp = client.get("/tenant/login")
    assert get_resp.status_code == 200
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', get_resp.text)
    assert match is not None
    csrf_token = match.group(1)

    login_resp = client.post(
        "/tenant/login",
        data={"email": user_a.email, "password": "AlphaPass123!", "csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert login_resp.status_code == 303

    resp = client.get("/tenant/hotspot/walled-garden/rsc")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    assert "/ip hotspot walled-garden" in resp.text
    assert "cowen.vercel.app" in resp.text

    resp_tmpl = client.get("/tenant/hotspot/templates/login.html")
    assert resp_tmpl.status_code == 200
    assert resp_tmpl.headers["content-type"].startswith("text/html")
    assert "$(link-login-only)" in resp_tmpl.text
