"""Tests for Platform Superadmin authentication, metrics dashboard, and tenant controls."""
from __future__ import annotations

from decimal import Decimal

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from saas.models.audit import SuperadminAuditLog
from saas.models.payments import SubscriptionTransaction
from saas.models.tenant import SubscriptionTier, Tenant, TenantStatus, TenantUser, UserRole
from saas.security.auth import hash_password
from saas.security.bootstrap import bootstrap_superadmin


def test_superadmin_bootstrap(db_session: Session):
    """Test bootstrapping initial platform superadmin account."""
    admin = bootstrap_superadmin(
        db=db_session,
        email="owner@platform.com",
        password="MasterAdminSecret99!",
        full_name="Platform Owner",
    )
    assert admin is not None
    assert admin.role == UserRole.superadmin
    assert admin.tenant_id is None

    # Idempotent re-run
    admin_again = bootstrap_superadmin(
        db=db_session,
        email="owner@platform.com",
        password="MasterAdminSecret99!",
    )
    assert admin_again.id == admin.id


def test_superadmin_unauthorized_redirect(client):
    """Test unauthenticated request to /superadmin redirects to /superadmin/login."""
    response = client.get("/superadmin", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/superadmin/login"


def test_superadmin_login_flow(client, seed_data):
    """Test successful login sets session and grants access to /superadmin."""
    # 1. Invalid password
    bad_res = client.post(
        "/superadmin/login",
        data={"email": "superadmin@saasplatform.com", "password": "WrongPassword!"},
    )
    assert bad_res.status_code == 401
    assert "Invalid administrative credentials" in bad_res.text

    # 2. Valid credentials
    good_res = client.post(
        "/superadmin/login",
        data={"email": "superadmin@saasplatform.com", "password": "SuperSecret123!"},
        follow_redirects=False,
    )
    assert good_res.status_code == 303
    assert good_res.headers["location"] == "/superadmin"


def test_superadmin_dashboard_metrics(client, seed_data):
    """Test dashboard correctly computes live database KPIs."""
    superadmin: TenantUser = seed_data["superadmin"]

    response = client.get("/superadmin", headers={"Authorization": f"Bearer {superadmin.id}"})
    assert response.status_code == 200
    html = response.text

    # Total tenants seeded = 2 (Alpha & Beta)
    assert "Platform Executive Overview" in html
    assert "Monthly Recurring Revenue" in html
    # Starter (1,000) + Basic (1,500) = KSh 2,500.00
    assert "2,500.00" in html
    assert "Alpha Networks" in html
    assert "Beta Fiber" in html


def test_superadmin_tenant_list_and_search(client, seed_data):
    """Test /superadmin/tenants lists, filters, and searches tenants."""
    superadmin: TenantUser = seed_data["superadmin"]

    # Search for Alpha
    res_search = client.get("/superadmin/tenants?q=Alpha", headers={"Authorization": f"Bearer {superadmin.id}"})
    assert res_search.status_code == 200
    assert "Alpha Networks" in res_search.text
    assert "Beta Fiber" not in res_search.text

    # Filter active
    res_filter = client.get("/superadmin/tenants?status=active", headers={"Authorization": f"Bearer {superadmin.id}"})
    assert res_filter.status_code == 200
    assert "Alpha Networks" in res_filter.text
    assert "Beta Fiber" in res_filter.text


def test_superadmin_tenant_detail_view(client, seed_data):
    """Test /superadmin/tenants/{id} shows full profile and subscription controls."""
    superadmin: TenantUser = seed_data["superadmin"]
    tenant_a: Tenant = seed_data["tenant_a"]

    response = client.get(
        f"/superadmin/tenants/{tenant_a.id}",
        headers={"Authorization": f"Bearer {superadmin.id}"},
    )
    assert response.status_code == 200
    html = response.text
    assert "Alpha Networks" in html
    assert "Starter" in html
    assert "Alpha-Core-CCR" in html
    assert "admin@alphanetworks.ke" in html


def test_superadmin_suspend_and_reactivate_tenant(client, db_session: Session, seed_data):
    """Test suspending and reactivating a tenant updates status and records audit logs."""
    superadmin: TenantUser = seed_data["superadmin"]
    tenant_a: Tenant = seed_data["tenant_a"]

    # 1. Suspend
    suspend_res = client.post(
        f"/superadmin/tenants/{tenant_a.id}/suspend",
        data={"reason": "Payment dispute"},
        headers={"Authorization": f"Bearer {superadmin.id}"},
        follow_redirects=False,
    )
    assert suspend_res.status_code == 303

    db_session.refresh(tenant_a)
    assert tenant_a.status == TenantStatus.suspended

    # Verify audit log entry
    log_suspend = db_session.scalar(
        select(SuperadminAuditLog).where(
            SuperadminAuditLog.target_id == tenant_a.id,
            SuperadminAuditLog.action == "tenant.suspend",
        )
    )
    assert log_suspend is not None
    assert log_suspend.actor_email == superadmin.email
    assert log_suspend.reason == "Payment dispute"

    # 2. Reactivate
    reactivate_res = client.post(
        f"/superadmin/tenants/{tenant_a.id}/reactivate",
        data={"reason": "Dispute resolved"},
        headers={"Authorization": f"Bearer {superadmin.id}"},
        follow_redirects=False,
    )
    assert reactivate_res.status_code == 303

    db_session.refresh(tenant_a)
    assert tenant_a.status == TenantStatus.active


def test_superadmin_change_tier(client, db_session: Session, seed_data):
    """Test changing a tenant's subscription tier updates limits and prices."""
    superadmin: TenantUser = seed_data["superadmin"]
    tenant_a: Tenant = seed_data["tenant_a"]

    assert tenant_a.subscription.tier == SubscriptionTier.starter
    assert tenant_a.subscription.max_routers == 1

    res = client.post(
        f"/superadmin/tenants/{tenant_a.id}/change-tier",
        data={"tier": "growth", "reason": "Customer requested upgrade"},
        headers={"Authorization": f"Bearer {superadmin.id}"},
        follow_redirects=False,
    )
    assert res.status_code == 303

    db_session.refresh(tenant_a.subscription)
    assert tenant_a.subscription.tier == SubscriptionTier.growth
    assert tenant_a.subscription.max_routers == 4
    assert tenant_a.subscription.monthly_price_kes == Decimal("3500.00")

    # Verify audit log
    log = db_session.scalar(
        select(SuperadminAuditLog).where(SuperadminAuditLog.action == "tenant.change_tier")
    )
    assert log is not None
    assert "growth" in log.reason


def test_superadmin_override_router_limit(client, db_session: Session, seed_data):
    """Test manual router limit override applied by superadmin."""
    superadmin: TenantUser = seed_data["superadmin"]
    tenant_a: Tenant = seed_data["tenant_a"]

    res = client.post(
        f"/superadmin/tenants/{tenant_a.id}/override-router-limit",
        data={"max_routers": 10, "reason": "VIP trial expansion"},
        headers={"Authorization": f"Bearer {superadmin.id}"},
        follow_redirects=False,
    )
    assert res.status_code == 303

    db_session.refresh(tenant_a.subscription)
    assert tenant_a.subscription.max_routers == 10

    # Verify audit log
    log = db_session.scalar(
        select(SuperadminAuditLog).where(SuperadminAuditLog.action == "tenant.override_router_limit")
    )
    assert log is not None
    assert "10" in log.reason


def test_superadmin_finance_and_audit_log_views(client, db_session: Session, seed_data):
    """Test /superadmin/finance and /superadmin/audit-logs views."""
    superadmin: TenantUser = seed_data["superadmin"]
    tenant_a: Tenant = seed_data["tenant_a"]

    # Add a mock platform subscription transaction
    tx = SubscriptionTransaction(
        tenant_id=tenant_a.id,
        tier=SubscriptionTier.starter,
        amount_kes=Decimal("1000.00"),
        paystack_reference="ref_saas_sub_audit_1",
        status="success",
    )
    db_session.add(tx)
    db_session.commit()

    # Financial management view
    res_fin = client.get("/superadmin/finance", headers={"Authorization": f"Bearer {superadmin.id}"})
    assert res_fin.status_code == 200
    assert "Platform Subscription Revenue" in res_fin.text
    assert "ref_saas_sub_audit_1" in res_fin.text
    assert "Strict Financial Segregation" in res_fin.text

    # Audit logs view
    res_audit = client.get("/superadmin/audit-logs", headers={"Authorization": f"Bearer {superadmin.id}"})
    assert res_audit.status_code == 200
    assert "Superadmin Audit Logs" in res_audit.text
