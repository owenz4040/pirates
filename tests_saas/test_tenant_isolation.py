"""Tests ensuring absolute data isolation between different ISP tenants."""
from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from saas.models.hotspot import HotspotPackage, HotspotVoucher
from saas.models.pppoe import PPPoECustomer, PPPoEPlan
from saas.models.router import Router
from saas.models.tenant import TenantUser
from saas.security.context import TenantContext


def test_tenant_context_scoping_routers(db_session: Session, seed_data: dict):
    """Verify that TenantContext.scope_query restricts queries to the active tenant's routers."""
    tenant_a = seed_data["tenant_a"]
    user_a = seed_data["user_a"]
    context_a = TenantContext(tenant=tenant_a, user=user_a)

    query = select(Router)
    scoped_query = context_a.scope_query(query, Router)
    results = db_session.scalars(scoped_query).all()

    # Must only return Tenant Alpha's routers
    assert len(results) == 1
    assert results[0].tenant_id == tenant_a.id
    assert results[0].name == "Alpha-Core-CCR"

    # Must NOT include Tenant Beta's router
    router_names = [r.name for r in results]
    assert "Beta-Mombasa-Node" not in router_names


def test_tenant_context_scoping_customers(db_session: Session, seed_data: dict):
    """Verify that customers belonging to Tenant B cannot be seen by Tenant A."""
    tenant_a = seed_data["tenant_a"]
    user_a = seed_data["user_a"]
    context_a = TenantContext(tenant=tenant_a, user=user_a)

    query = select(PPPoECustomer)
    scoped_query = context_a.scope_query(query, PPPoECustomer)
    results = db_session.scalars(scoped_query).all()

    assert len(results) == 1
    assert results[0].tenant_id == tenant_a.id
    assert results[0].username == "alpha_user_01"

    # Beta's customer must be invisible
    usernames = [c.username for c in results]
    assert "beta_user_01" not in usernames


def test_tenant_context_scoping_vouchers(db_session: Session, seed_data: dict):
    """Verify that hotspot vouchers are strictly partitioned by tenant."""
    tenant_b = seed_data["tenant_b"]
    user_b = seed_data["user_b"]
    context_b = TenantContext(tenant=tenant_b, user=user_b)

    query = select(HotspotVoucher)
    scoped_query = context_b.scope_query(query, HotspotVoucher)
    results = db_session.scalars(scoped_query).all()

    assert len(results) == 1
    assert results[0].tenant_id == tenant_b.id
    assert results[0].code == "BETA9999"

    codes = [v.code for v in results]
    assert "ALPHA1234" not in codes


def test_superadmin_query_visibility(db_session: Session, seed_data: dict):
    """Verify that platform superadmin can inspect global entities across all tenants."""
    superadmin = seed_data["superadmin"]
    tenant_a = seed_data["tenant_a"]
    context_admin = TenantContext(tenant=tenant_a, user=superadmin)

    query = select(Router)
    scoped_query = context_admin.scope_query(query, Router)
    results = db_session.scalars(scoped_query).all()

    # Superadmin sees all routers across both tenants
    assert len(results) >= 2
    router_names = [r.name for r in results]
    assert "Alpha-Core-CCR" in router_names
    assert "Beta-Mombasa-Node" in router_names


def test_api_tenant_me_endpoint_isolation(client, seed_data: dict):
    """Test /api/tenant/me returns distinct company information based on authenticated user."""
    user_a: TenantUser = seed_data["user_a"]
    user_b: TenantUser = seed_data["user_b"]

    # Request as Alpha Admin
    resp_a = client.get("/api/tenant/me", headers={"Authorization": f"Bearer {user_a.id}"})
    assert resp_a.status_code == 200
    data_a = resp_a.json()
    assert data_a["slug"] == "alpha-isp"
    assert data_a["name"] == "Alpha Networks"
    assert data_a["subscription"]["tier"] == "starter"
    assert data_a["subscription"]["max_routers"] == 1

    # Request as Beta Admin
    resp_b = client.get("/api/tenant/me", headers={"Authorization": f"Bearer {user_b.id}"})
    assert resp_b.status_code == 200
    data_b = resp_b.json()
    assert data_b["slug"] == "beta-fiber"
    assert data_b["name"] == "Beta Fiber"
    assert data_b["subscription"]["tier"] == "basic"
    assert data_b["subscription"]["max_routers"] == 2
