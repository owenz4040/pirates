"""Comprehensive test suite for the COwen ISP SaaS Tenant Admin Portal (Milestone 3)."""
import os
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

# Use in-memory SQLite for high-speed isolated test execution
os.environ["SAAS_ENV"] = "test"
os.environ["SAAS_DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SAAS_SESSION_SECRET"] = "test-session-secret-key-32-bytes-long!"

from saas.app import app
from saas.database import SaasBase, get_saas_db
from saas.models.hotspot import HotspotPackage, HotspotVoucher, VoucherStatus
from saas.models.payments import CustomerPayment, SubscriptionTransaction, TenantPaymentConfig
from saas.models.pppoe import ConnectionType, CustomerStatus, PPPoECustomer, PPPoEPlan
from saas.models.router import Router, RouterCommand, RouterCommandStatus, RouterStatus
from saas.models.tenant import (
    SubscriptionTier,
    Tenant,
    TenantBranding,
    TenantStatus,
    TenantSubscription,
    TenantUser,
    UserRole,
)
from saas.security.auth import hash_password, hash_token

test_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="module", autouse=True)
def setup_test_db():
    SaasBase.metadata.create_all(bind=test_engine)
    yield
    SaasBase.metadata.drop_all(bind=test_engine)


@pytest.fixture
def db_session():
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    # Override FastAPI dependency
    app.dependency_overrides[get_saas_db] = lambda: session

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session):
    return TestClient(app)


def create_mock_tenant(db, name="Speedy WiFi", slug="speedy-wifi", tier=SubscriptionTier.starter):
    admin_email = f"admin@{slug}.com"
    tenant = Tenant(
        id=str(uuid.uuid4()),
        name=name,
        slug=slug,
        contact_email=admin_email,
        contact_phone="+254700000001",
        status=TenantStatus.active,
    )
    db.add(tenant)
    db.flush()

    now = datetime.now(timezone.utc)
    sub = TenantSubscription(
        tenant_id=tenant.id,
        tier=tier,
        max_routers=tier.max_routers,
        monthly_price_kes=tier.monthly_price_kes,
        is_active=True,
        starts_at=now,
        expires_at=now + timedelta(days=30),
    )
    db.add(sub)

    branding = TenantBranding(
        tenant_id=tenant.id,
        company_title=f"{name} Billing",
        primary_color="#dfb758",
    )
    db.add(branding)

    admin_user = TenantUser(
        id=str(uuid.uuid4()),
        tenant_id=tenant.id,
        email=admin_email,
        full_name="Alice Admin",
        hashed_password=hash_password("ValidPassword123!"),
        role=UserRole.tenant_admin,
        is_active=True,
        email_verified=True,
    )
    db.add(admin_user)
    db.commit()
    db.refresh(tenant)
    db.refresh(admin_user)
    return tenant, admin_user


# =====================================================================
# Tests: Authentication & Session
# =====================================================================

def test_tenant_login_page_renders(client):
    response = client.get("/tenant/login")
    assert response.status_code == 200
    assert "COwen ISP SaaS" in response.text
    assert "Tenant ISP Administration Console" in response.text


def test_tenant_login_success(client, db_session):
    tenant, admin = create_mock_tenant(db_session, "Alpha ISP", "alpha-isp")
    get_resp = client.get("/tenant/login")
    import re
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', get_resp.text)
    csrf = match.group(1) if match else ""

    response = client.post(
        "/tenant/login",
        data={"email": admin.email, "password": "ValidPassword123!", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["Location"] == "/tenant/dashboard"


def test_tenant_login_invalid_password(client, db_session):
    tenant, admin = create_mock_tenant(db_session, "Beta ISP", "beta-isp")
    get_resp = client.get("/tenant/login")
    import re
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', get_resp.text)
    csrf = match.group(1) if match else ""

    response = client.post(
        "/tenant/login",
        data={"email": admin.email, "password": "WrongPassword", "csrf_token": csrf},
    )
    assert response.status_code == 401
    assert "Invalid email or password" in response.text


def test_unauthenticated_dashboard_redirects_to_login(client):
    response = client.get("/tenant/dashboard", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["Location"].startswith("/tenant/login")


# =====================================================================
# Tests: Router Fleet & Subscription Limits
# =====================================================================

def test_starter_tier_router_limit_enforced(client, db_session):
    tenant, admin = create_mock_tenant(db_session, "Gamma ISP", "gamma-isp", tier=SubscriptionTier.starter)

    # 1st router: should succeed
    headers = {"Authorization": f"Bearer {admin.id}"}
    resp1 = client.post(
        "/tenant/routers/add",
        data={"name": "Core-Router-1", "location": "Nairobi PoP"},
        headers=headers,
    )
    assert resp1.status_code == 200
    assert "Router Successfully Created: Core-Router-1" in resp1.text
    assert "COwen_Sync_Script" in resp1.text

    # 2nd router: must be blocked because Starter tier allows only 1 router
    resp2 = client.post(
        "/tenant/routers/add",
        data={"name": "Core-Router-2", "location": "Mombasa PoP"},
        headers=headers,
    )
    assert resp2.status_code == 403
    assert "Router limit reached" in resp2.text


# =====================================================================
# Tests: Outbound HTTPS Polling API
# =====================================================================

def test_outbound_https_router_sync_and_command_delivery(client, db_session):
    tenant, admin = create_mock_tenant(db_session, "Delta ISP", "delta-isp")

    # Manually provision a router with a known token
    raw_token = "delta-test-secret-token-12345"
    token_hashed = hash_token(raw_token)

    router = Router(
        tenant_id=tenant.id,
        name="Delta-CCR",
        token_hash=token_hashed,
        status=RouterStatus.provisioning,
    )
    db_session.add(router)
    db_session.commit()

    # Stage a command in the router queue
    cmd = RouterCommand(
        tenant_id=tenant.id,
        router_id=router.id,
        description="Add PPPoE user",
        script='/ppp secret add name="user1" password="pass"',
        status=RouterCommandStatus.pending,
    )
    db_session.add(cmd)
    db_session.commit()

    # Simulate MikroTik RouterOS outbound /tool fetch sync
    sync_resp = client.post(
        "/api/router/sync",
        headers={"X-Router-Token": raw_token, "Accept": "application/json"},
        json={
            "version": "7.15.2",
            "board": "CCR2004-16G-2S+",
            "uptime": "4w2d18h",
            "cpu_load": 12,
        },
    )
    assert sync_resp.status_code == 200
    data = sync_resp.json()
    assert data["status"] == "ok"
    assert len(data["commands"]) == 1
    assert data["commands"][0]["id"] == cmd.id

    # Verify router state in DB updated to online with telemetry
    db_session.refresh(router)
    assert router.status == RouterStatus.online
    assert router.version == "7.15.2"
    assert router.board == "CCR2004-16G-2S+"
    assert router.cpu_load == 12
    assert router.last_seen_at is not None

    # Router reports command completion
    result_resp = client.post(
        "/api/router/command-result",
        headers={"X-Router-Token": raw_token},
        json={"command_id": cmd.id, "status": "done"},
    )
    assert result_resp.status_code == 200
    db_session.refresh(cmd)
    assert cmd.status == RouterCommandStatus.done
    assert cmd.finished_at is not None


# =====================================================================
# Tests: PPPoE Plan & Subscriber Provisioning
# =====================================================================

def test_pppoe_plan_and_subscriber_flow(client, db_session):
    tenant, admin = create_mock_tenant(db_session, "Epsilon ISP", "epsilon-isp")
    headers = {"Authorization": f"Bearer {admin.id}"}

    # Add router
    router = Router(
        tenant_id=tenant.id,
        name="Epsilon-Router",
        token_hash="fakehash",
        status=RouterStatus.online,
    )
    db_session.add(router)
    db_session.commit()

    # Add speed plan
    plan_resp = client.post(
        "/tenant/pppoe/plans/add",
        data={"name": "20 Mbps Fiber", "rate_limit": "20M/20M", "price_kes": 3500, "duration_days": 30},
        headers=headers,
        follow_redirects=False,
    )
    assert plan_resp.status_code == 303

    plan = db_session.scalar(select(PPPoEPlan).where(PPPoEPlan.tenant_id == tenant.id))
    assert plan is not None
    assert plan.name == "20 Mbps Fiber"

    # Add subscriber
    sub_resp = client.post(
        "/tenant/pppoe/subscribers/add",
        data={
            "router_id": router.id,
            "plan_id": plan.id,
            "username": "client_001",
            "password": "Password123!",
            "full_name": "Bob Smith",
            "phone_number": "254711223344",
            "connection_type": "pppoe",
        },
        headers=headers,
        follow_redirects=False,
    )
    assert sub_resp.status_code == 303

    # Verify subscriber created and command queued
    cust = db_session.scalar(select(PPPoECustomer).where(PPPoECustomer.username == "client_001"))
    assert cust is not None
    assert cust.full_name == "Bob Smith"

    queued_cmd = db_session.scalar(
        select(RouterCommand).where(RouterCommand.router_id == router.id)
    )
    assert queued_cmd is not None
    assert 'client_001' in queued_cmd.script


# =====================================================================
# Tests: Hotspot Packages & Batch Vouchers
# =====================================================================

def test_hotspot_package_and_voucher_batch(client, db_session):
    tenant, admin = create_mock_tenant(db_session, "Zeta ISP", "zeta-isp")
    headers = {"Authorization": f"Bearer {admin.id}"}

    # Create package
    pkg = HotspotPackage(
        tenant_id=tenant.id,
        name="12 Hours Unlimited",
        price_kes=Decimal("50.00"),
        duration_minutes=720,
        rate_limit="10M/10M",
    )
    db_session.add(pkg)
    db_session.commit()

    # Generate batch of 10 vouchers
    resp = client.post(
        "/tenant/hotspot/vouchers/generate",
        data={"package_id": pkg.id, "quantity": 10},
        headers=headers,
        follow_redirects=False,
    )
    assert resp.status_code == 303

    vouchers = db_session.scalars(
        select(HotspotVoucher).where(HotspotVoucher.tenant_id == tenant.id)
    ).all()
    assert len(vouchers) == 10
    assert all(v.status == VoucherStatus.unused for v in vouchers)
    assert len({v.code for v in vouchers}) == 10  # All unique codes


# =====================================================================
# Tests: Encrypted Payment Credentials
# =====================================================================

def test_tenant_payment_credentials_encrypted(client, db_session):
    tenant, admin = create_mock_tenant(db_session, "Eta ISP", "eta-isp")
    headers = {"Authorization": f"Bearer {admin.id}"}

    client.post(
        "/tenant/payments/mpesa",
        data={
            "mpesa_type": "paybill",
            "shortcode": "174379",
            "consumer_key": "my-secret-key",
            "consumer_secret": "my-secret-secret",
            "passkey": "my-passkey-1234",
        },
        headers=headers,
        follow_redirects=False,
    )

    config = db_session.scalar(
        select(TenantPaymentConfig).where(TenantPaymentConfig.tenant_id == tenant.id)
    )
    assert config is not None
    assert config.mpesa_enabled is True
    # Verify raw strings are not in the raw database fields
    assert config.mpesa_consumer_key_encrypted != "my-secret-key"
    assert config.mpesa_consumer_secret_encrypted != "my-secret-secret"
    # Decryption works via helper
    creds = config.get_mpesa_credentials()
    assert creds["consumer_key"] == "my-secret-key"
    assert creds["consumer_secret"] == "my-secret-secret"
    assert creds["passkey"] == "my-passkey-1234"


# =====================================================================
# Tests: Financial Reporting & Cross-Tenant Isolation
# =====================================================================

def test_reports_strictly_isolate_tenant_revenue(client, db_session):
    tenant_a, admin_a = create_mock_tenant(db_session, "Tenant A", "tenant-a")
    tenant_b, admin_b = create_mock_tenant(db_session, "Tenant B", "tenant-b")

    # Payment for Tenant A
    db_session.add(CustomerPayment(
        tenant_id=tenant_a.id,
        reference="TXN_AAA",
        amount_kes=Decimal("2500.00"),
        gateway="mpesa",
        status="completed",
    ))
    # Payment for Tenant B
    db_session.add(CustomerPayment(
        tenant_id=tenant_b.id,
        reference="TXN_BBB",
        amount_kes=Decimal("9999.00"),
        gateway="mpesa",
        status="completed",
    ))
    # Platform subscription transaction (must NEVER appear in tenant reports)
    db_session.add(SubscriptionTransaction(
        tenant_id=tenant_a.id,
        tier=SubscriptionTier.starter,
        amount_kes=Decimal("1000.00"),
        paystack_reference="SUB_REF_PLATFORM",
        status="success",
    ))
    db_session.commit()

    # Query Tenant A's reports page
    headers_a = {"Authorization": f"Bearer {admin_a.id}"}
    resp_a = client.get("/tenant/reports", headers=headers_a)
    assert resp_a.status_code == 200
    assert "KES 2,500.00" in resp_a.text
    assert "TXN_AAA" in resp_a.text
    # Must NOT leak Tenant B's data
    assert "TXN_BBB" not in resp_a.text
    assert "KES 9,999.00" not in resp_a.text
    # Must NOT include platform subscription revenue
    assert "SUB_REF_PLATFORM" not in resp_a.text
