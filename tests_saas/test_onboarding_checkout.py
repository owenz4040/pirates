"""Tests for customer onboarding checkout initiation and server-side validation."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from saas.models.payments import PendingSubscriptionCheckout
from saas.models.tenant import SubscriptionTier


def test_checkout_page_display(client):
    """Test GET /checkout displays correct plan summary."""
    response = client.get("/checkout?plan=growth")
    assert response.status_code == 200
    html = response.text
    assert "Growth" in html
    assert "4 Routers" in html
    assert "KSh 3,500.00" in html


def test_checkout_initiate_validation_invalid_slug(client):
    """Test that invalid workspace slug (spaces, uppercase, symbols) is rejected."""
    payload = {
        "plan": "starter",
        "company_name": "Lake Net",
        "company_slug": "Lake Net & Co!",  # Invalid slug
        "company_email": "info@lakenet.co.ke",
        "company_phone": "+254711223344",
        "admin_name": "Daniel Otieno",
        "admin_email": "daniel@lakenet.co.ke",
    }
    response = client.post("/checkout/initiate", data=payload)
    assert response.status_code == 400
    assert "Workspace slug may only contain" in response.text


def test_checkout_initiate_duplicate_slug_rejected(client, seed_data):
    """Test that existing company slug cannot be claimed by a new signup."""
    payload = {
        "plan": "starter",
        "company_name": "Another Alpha",
        "company_slug": "alpha-isp",  # Already taken in seed_data
        "company_email": "new@alpha.com",
        "company_phone": "+254700000000",
        "admin_name": "Impostor Admin",
        "admin_email": "impostor@alpha.com",
    }
    response = client.post("/checkout/initiate", data=payload)
    assert response.status_code == 400
    assert "already taken" in response.text


def test_checkout_initiate_duplicate_email_rejected(client, seed_data):
    """Test that existing user email cannot be reused for a new tenant signup."""
    payload = {
        "plan": "basic",
        "company_name": "New ISP Company",
        "company_slug": "new-isp-unique",
        "company_email": "contact@newisp.com",
        "company_phone": "+254700000000",
        "admin_name": "Alpha Admin",
        "admin_email": "admin@alphanetworks.ke",  # Already exists in seed_data
    }
    response = client.post("/checkout/initiate", data=payload)
    assert response.status_code == 400
    assert "administrator account with email" in response.text


def test_successful_checkout_stores_pending_record(client, db_session: Session, monkeypatch):
    """Test successful checkout submission creates PendingSubscriptionCheckout record."""
    # Mock Paystack transaction initialization so external HTTP call succeeds
    def mock_init_transaction(**kwargs):
        return {
            "authorization_url": f"https://checkout.paystack.com/mock-{kwargs['reference']}",
            "access_code": "mock_access_code",
            "reference": kwargs["reference"],
        }

    monkeypatch.setattr("saas.services.paystack.initialize_transaction", mock_init_transaction)

    payload = {
        "plan": "growth",
        "company_name": "Savannah Fiber",
        "company_slug": "savannah-fiber",
        "company_email": "billing@savannah.co.ke",
        "company_phone": "+254722114455",
        "admin_name": "Grace Wanjiku",
        "admin_email": "grace@savannah.co.ke",
    }
    response = client.post("/checkout/initiate", data=payload, follow_redirects=False)
    
    # Must redirect to Paystack authorization_url
    assert response.status_code == 303
    assert "https://checkout.paystack.com/mock-sub_savannah-fib_" in response.headers["location"]

    # Verify database pending record exists
    pending = db_session.scalar(
        select(PendingSubscriptionCheckout).where(PendingSubscriptionCheckout.company_slug == "savannah-fiber")
    )
    assert pending is not None
    assert pending.tier == SubscriptionTier.growth
    assert pending.amount_kes == SubscriptionTier.growth.monthly_price_kes
    assert pending.status == "pending"
    assert pending.admin_email == "grace@savannah.co.ke"


def test_checkout_callback_verified_payment_provisions_account(client, db_session: Session, monkeypatch):
    """Test browser redirect /checkout/callback verifies with Paystack API and provisions tenant."""
    from decimal import Decimal
    from saas.models.tenant import Tenant

    ref = "ref_cb_test_9988"
    pending = PendingSubscriptionCheckout(
        paystack_reference=ref,
        company_name="Rift Valley WiFi",
        company_slug="rift-wifi",
        company_email="admin@riftwifi.ke",
        company_phone="+254700000000",
        admin_name="Kevin Bett",
        admin_email="kevin@riftwifi.ke",
        tier=SubscriptionTier.basic,
        amount_kes=Decimal("1500.00"),
        currency="KES",
        status="pending",
    )
    db_session.add(pending)
    db_session.commit()

    # Mock server-side verification returning success
    def mock_verify(reference):
        assert reference == ref
        return {
            "reference": ref,
            "status": "success",
            "currency": "KES",
            "amount": 150000,
            "customer": {"email": "kevin@riftwifi.ke"},
        }

    monkeypatch.setattr("saas.services.paystack.verify_transaction", mock_verify)

    response = client.get(f"/checkout/callback?reference={ref}")
    assert response.status_code == 200
    assert "Payment Confirmed & Account Provisioned!" in response.text
    assert "Rift Valley WiFi" in response.text
    assert "rift-wifi" in response.text

    # Verify tenant was provisioned
    tenant = db_session.scalar(select(Tenant).where(Tenant.slug == "rift-wifi"))
    assert tenant is not None
    assert tenant.subscription.max_routers == 2


def test_checkout_status_polling_endpoints(client, db_session: Session):
    """Test /checkout/status/{reference} and JSON polling endpoint."""
    from decimal import Decimal

    ref = "ref_poll_123"
    pending = PendingSubscriptionCheckout(
        paystack_reference=ref,
        company_name="Nandi Net",
        company_slug="nandi-net",
        company_email="info@nandi.net",
        company_phone="+254700000000",
        admin_name="Nandi Admin",
        admin_email="admin@nandi.net",
        tier=SubscriptionTier.starter,
        amount_kes=Decimal("1000.00"),
        currency="KES",
        status="pending",
    )
    db_session.add(pending)
    db_session.commit()

    # HTML status view
    html_res = client.get(f"/checkout/status/{ref}")
    assert html_res.status_code == 200
    assert "Confirming Transaction..." in html_res.text

    # JSON polling view
    json_res = client.get(f"/checkout/status/{ref}/json")
    assert json_res.status_code == 200
    data = json_res.json()
    assert data["reference"] == ref
    assert data["status"] == "pending"

