"""Fixtures and test environment for SaaS multi-tenant isolation tests."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

# Ensure master encryption key is set for testing
os.environ["ENCRYPTION_MASTER_KEY"] = "4l1gBw3uG40iO1sT2j8s5x6v7y8z9a0b1c2d3e4f5g6="

from saas.app import app
from saas.database import SaasBase, get_saas_db
from saas.models.hotspot import HotspotPackage, HotspotVoucher, VoucherStatus
from saas.models.payments import TenantPaymentConfig
from saas.models.pppoe import ConnectionType, CustomerStatus, PPPoECustomer, PPPoEPlan
from saas.models.router import Router, RouterStatus
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


@pytest.fixture
def test_engine():
    """In-memory SQLite database created fresh for each test to ensure complete isolation."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SaasBase.metadata.create_all(bind=engine)
    yield engine
    SaasBase.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def db_session(test_engine) -> Generator[Session, None, None]:
    """Provides a fresh database session rolled back or cleared for each test."""
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def seed_data(db_session: Session):
    """
    Seeds two completely distinct tenants (Alpha Networks & Beta Fiber) and one platform Superadmin.
    """
    now = datetime.now(timezone.utc)
    future = now + timedelta(days=30)

    # 1. Superadmin User
    superadmin = TenantUser(
        email="superadmin@saasplatform.com",
        hashed_password=hash_password("SuperSecret123!"),
        full_name="Platform Superadmin",
        role=UserRole.superadmin,
        is_active=True,
    )
    db_session.add(superadmin)

    # 2. Tenant Alpha (Starter tier: max 1 router)
    tenant_a = Tenant(
        name="Alpha Networks",
        slug="alpha-isp",
        contact_email="owner@alphanetworks.ke",
        contact_phone="+254711000111",
        status=TenantStatus.active,
    )
    db_session.add(tenant_a)
    db_session.flush()

    sub_a = TenantSubscription(
        tenant_id=tenant_a.id,
        tier=SubscriptionTier.starter,
        max_routers=1,
        monthly_price_kes=Decimal("1000.00"),
        starts_at=now,
        expires_at=future,
    )
    user_a = TenantUser(
        tenant_id=tenant_a.id,
        email="admin@alphanetworks.ke",
        hashed_password=hash_password("AlphaPass123!"),
        full_name="Alpha Admin",
        role=UserRole.tenant_admin,
        is_active=True,
    )
    branding_a = TenantBranding(
        tenant_id=tenant_a.id,
        company_title="Alpha High-Speed Internet",
        primary_color="#0055ff",
    )
    router_a1 = Router(
        tenant_id=tenant_a.id,
        name="Alpha-Core-CCR",
        token_hash=hash_token("alpha_token_1"),
        status=RouterStatus.online,
        location="Nairobi CBD",
    )
    plan_a = PPPoEPlan(
        tenant_id=tenant_a.id,
        name="Alpha 10Mbps Home",
        rate_limit="10M/10M",
        price_kes=Decimal("2000.00"),
    )
    db_session.add_all([sub_a, user_a, branding_a, router_a1, plan_a])
    db_session.flush()

    cust_a = PPPoECustomer(
        tenant_id=tenant_a.id,
        router_id=router_a1.id,
        plan_id=plan_a.id,
        username="alpha_user_01",
        password="secretpassword",
        full_name="John Doe (Alpha)",
        status=CustomerStatus.active,
    )
    hotspot_pkg_a = HotspotPackage(
        tenant_id=tenant_a.id,
        name="Alpha 1Hr Pass",
        price_kes=Decimal("50.00"),
        duration_minutes=60,
    )
    db_session.add_all([cust_a, hotspot_pkg_a])
    db_session.flush()

    voucher_a = HotspotVoucher(
        tenant_id=tenant_a.id,
        package_id=hotspot_pkg_a.id,
        router_id=router_a1.id,
        code="ALPHA1234",
        status=VoucherStatus.unused,
    )
    db_session.add(voucher_a)

    # 3. Tenant Beta (Basic tier: max 2 routers)
    tenant_b = Tenant(
        name="Beta Fiber",
        slug="beta-fiber",
        contact_email="owner@betafiber.ke",
        contact_phone="+254722000222",
        status=TenantStatus.active,
    )
    db_session.add(tenant_b)
    db_session.flush()

    sub_b = TenantSubscription(
        tenant_id=tenant_b.id,
        tier=SubscriptionTier.basic,
        max_routers=2,
        monthly_price_kes=Decimal("1500.00"),
        starts_at=now,
        expires_at=future,
    )
    user_b = TenantUser(
        tenant_id=tenant_b.id,
        email="admin@betafiber.ke",
        hashed_password=hash_password("BetaPass123!"),
        full_name="Beta Admin",
        role=UserRole.tenant_admin,
        is_active=True,
    )
    router_b1 = Router(
        tenant_id=tenant_b.id,
        name="Beta-Mombasa-Node",
        token_hash=hash_token("beta_token_1"),
        status=RouterStatus.online,
        location="Mombasa Old Town",
    )
    plan_b = PPPoEPlan(
        tenant_id=tenant_b.id,
        name="Beta 20Mbps Gold",
        rate_limit="20M/20M",
        price_kes=Decimal("3500.00"),
    )
    db_session.add_all([sub_b, user_b, router_b1, plan_b])
    db_session.flush()

    cust_b = PPPoECustomer(
        tenant_id=tenant_b.id,
        router_id=router_b1.id,
        plan_id=plan_b.id,
        username="beta_user_01",
        password="betapassword",
        full_name="Jane Smith (Beta)",
        status=CustomerStatus.active,
    )
    hotspot_pkg_b = HotspotPackage(
        tenant_id=tenant_b.id,
        name="Beta 24Hr Unlimited",
        price_kes=Decimal("150.00"),
        duration_minutes=1440,
    )
    db_session.add_all([cust_b, hotspot_pkg_b])
    db_session.flush()

    voucher_b = HotspotVoucher(
        tenant_id=tenant_b.id,
        package_id=hotspot_pkg_b.id,
        router_id=router_b1.id,
        code="BETA9999",
        status=VoucherStatus.unused,
    )
    db_session.add(voucher_b)

    db_session.commit()

    return {
        "superadmin": superadmin,
        "tenant_a": tenant_a,
        "user_a": user_a,
        "router_a": router_a1,
        "plan_a": plan_a,
        "customer_a": cust_a,
        "voucher_a": voucher_a,
        "tenant_b": tenant_b,
        "user_b": user_b,
        "router_b": router_b1,
        "plan_b": plan_b,
        "customer_b": cust_b,
        "voucher_b": voucher_b,
    }


@pytest.fixture
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """Test client with SaaS database dependency overridden to test session."""
    def _override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_saas_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
