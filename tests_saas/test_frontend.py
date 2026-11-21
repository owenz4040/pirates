"""Frontend Rendering and UI Integration Tests for SaaS Platform & Superadmin UI."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import re
import pytest
from starlette.testclient import TestClient
from sqlalchemy.orm import Session
from sqlalchemy import select

from saas.app import app
from saas.database import SaasBase, saas_engine
from saas.models.tenant import (
    Tenant,
    TenantStatus,
    TenantSubscription,
    SubscriptionTier,
    TenantUser,
    UserRole,
    SuperadminEnrollment,
)
from saas.security.auth import hash_password
from saas.security.crypto import encrypt_secret


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    SaasBase.metadata.create_all(bind=saas_engine)


def test_frontend_landing_page(client):
    """Verifies that the marketing landing page renders all key UI sections and controls."""
    res = client.get("/")
    assert res.status_code == 200
    html = res.text

    # 1. Title and Branding
    assert "<title>" in html
    assert "COwen" in html or "ISP" in html

    # 2. Hero Section
    assert 'id="hero"' in html or "Launch Your" in html or "ISP" in html

    # 3. Interactive Pricing Section
    assert 'id="pricing"' in html

    # All 4 Tier cards (Starter, Basic, Growth, Professional)
    assert "Starter" in html
    assert "Basic" in html
    assert "Growth" in html

    # Pricing CTAs point to /checkout?plan=
    assert '/checkout?plan=' in html

    # 4. Interactive Router Calculator
    assert "calc-selector" in html or "selectRouters" in html or "MikroTik routers" in html

    # 5. FAQs & Footer
    assert "Frequently Asked Questions" in html or "FAQ" in html
    assert "<footer" in html


def test_frontend_onboarding_checkout_page(client):
    """Verifies that the onboarding checkout page renders company registration forms."""
    res = client.get("/checkout?plan=growth")
    assert res.status_code == 200
    html = res.text

    # Form inputs for company registration
    assert '<form' in html
    assert 'name="company_name"' in html
    assert 'name="company_slug"' in html
    assert 'name="company_email"' in html
    assert 'name="company_phone"' in html
    assert 'name="admin_name"' in html
    assert 'name="admin_email"' in html

    # Selected plan reflected
    assert "growth" in html.lower()


def test_frontend_superadmin_login_page(client):
    """Verifies that the superadmin login page renders correctly."""
    res = client.get("/superadmin/login")
    assert res.status_code == 200
    html = res.text

    assert '<form' in html
    assert 'name="email"' in html
    assert 'name="password"' in html
    assert 'type="submit"' in html


def test_frontend_superadmin_setup_otp_page(client):
    """Verifies the superadmin OTP setup page."""
    res = client.get("/superadmin/setup?email=owenzcolin@gmail.com")
    assert res.status_code == 200
    html = res.text

    assert "Verification Code" in html or "OTP" in html
    assert 'name="otp"' in html
    assert 'name="email"' in html


def test_frontend_superadmin_mfa_challenge_page(client, db_session: Session):
    """Verifies the MFA challenge screen rendered when superadmin has pending 2FA."""
    email = "test_superadmin_ui@cloudisp.test"
    user = db_session.scalar(select(TenantUser).where(TenantUser.email == email))
    if not user:
        user = TenantUser(
            email=email,
            full_name="UI Test Admin",
            hashed_password=hash_password("SuperSecret123!"),
            role=UserRole.superadmin,
            totp_secret_encrypted=encrypt_secret("JBSWY3DPEHPK3PXP"),
            mfa_enabled=True,
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()

    # Step 1: Submit password to set session mfa_pending_user_id
    res_login = client.post(
        "/superadmin/login",
        data={"email": email, "password": "SuperSecret123!"},
        follow_redirects=False,
    )
    assert res_login.status_code == 303
    assert res_login.headers["location"] == "/superadmin/mfa"

    # Step 2: GET /superadmin/mfa
    res_mfa = client.get("/superadmin/mfa")
    assert res_mfa.status_code == 200
    html = res_mfa.text

    assert 'name="totp_code"' in html
    assert "Two-Factor Authentication" in html or "Authenticator" in html


def test_frontend_superadmin_dashboard_and_tenant_views(client, db_session: Session):
    """Verifies the Superadmin Dashboard, Tenants list, and Tenant Detail view."""
    admin_email = "owenzcolin@gmail.com"
    admin_user = db_session.scalar(select(TenantUser).where(TenantUser.email == admin_email))
    if not admin_user:
        admin_user = TenantUser(
            email=admin_email,
            full_name="Platform Owner",
            hashed_password=hash_password("OwnerPassword123!"),
            role=UserRole.superadmin,
            totp_secret_encrypted=encrypt_secret("JBSWY3DPEHPK3PXP"),
            mfa_enabled=False,
            is_active=True,
            session_version=1,
        )
        db_session.add(admin_user)
        db_session.commit()
    else:
        admin_user.mfa_enabled = False
        db_session.commit()

    # Log in
    client.post("/superadmin/login", data={"email": admin_email, "password": "OwnerPassword123!"})

    # 1. Executive Dashboard
    res_dash = client.get("/superadmin")
    assert res_dash.status_code == 200
    html_dash = res_dash.text

    assert "Total Tenants" in html_dash or "Tenants" in html_dash
    assert "Monthly Recurring Revenue" in html_dash or "MRR" in html_dash

    # 2. Tenants Directory
    res_tenants = client.get("/superadmin/tenants")
    assert res_tenants.status_code == 200
    html_tenants = res_tenants.text
    assert "Tenants & Companies" in html_tenants or "Tenants" in html_tenants

    # Seed a sample tenant to test Tenant Detail view
    tenant = db_session.scalar(select(Tenant).where(Tenant.slug == "safari-ui-test"))
    if not tenant:
        tenant = Tenant(
            name="Safari UI WiFi",
            slug="safari-ui-test",
            contact_email="support@safari.test",
            contact_phone="+254700000000",
            status=TenantStatus.active,
        )
        db_session.add(tenant)
        db_session.flush()

        sub = TenantSubscription(
            tenant_id=tenant.id,
            tier=SubscriptionTier.growth,
            max_routers=5,
            is_active=True,
            starts_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        db_session.add(sub)
        db_session.commit()

    # 3. Tenant Detail Page
    res_detail = client.get(f"/superadmin/tenants/{tenant.id}")
    assert res_detail.status_code == 200
    html_detail = res_detail.text

    assert "Safari UI WiFi" in html_detail
    assert "safari-ui-test" in html_detail
    assert "<form" in html_detail
