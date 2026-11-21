"""Tests subscription package router limits (Starter: 1, Basic: 2, Growth: 4, Business: 6)."""
from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from saas.models.router import Router, RouterStatus
from saas.models.tenant import SubscriptionTier, TenantUser
from saas.security.auth import hash_token
from saas.security.context import SubscriptionLimitExceededError, TenantContext


def test_starter_tier_router_limit(db_session: Session, seed_data: dict):
    """
    Starter Plan allows 1 router.
    Tenant Alpha already has 1 router (Alpha-Core-CCR).
    Attempting to add a 2nd router must raise SubscriptionLimitExceededError.
    """
    tenant_a = seed_data["tenant_a"]
    user_a = seed_data["user_a"]
    context_a = TenantContext(tenant=tenant_a, user=user_a)

    assert tenant_a.subscription.tier == SubscriptionTier.starter
    assert tenant_a.subscription.max_routers == 1

    # Attempting to add router 2 must raise limit error
    with pytest.raises(SubscriptionLimitExceededError) as exc_info:
        context_a.assert_can_add_router(db_session)

    assert "Router limit reached" in str(exc_info.value)
    assert exc_info.value.current_count == 1
    assert exc_info.value.max_limit == 1


def test_basic_tier_router_limit(db_session: Session, seed_data: dict):
    """
    Basic Plan allows 2 routers.
    Tenant Beta has 1 router (Beta-Mombasa-Node).
    Can add a 2nd router, but a 3rd must fail.
    """
    tenant_b = seed_data["tenant_b"]
    user_b = seed_data["user_b"]
    context_b = TenantContext(tenant=tenant_b, user=user_b)

    assert tenant_b.subscription.tier == SubscriptionTier.basic
    assert tenant_b.subscription.max_routers == 2

    # Router 2: Should succeed
    context_b.assert_can_add_router(db_session)

    second_router = Router(
        tenant_id=tenant_b.id,
        name="Beta-Nyali-Node",
        token_hash=hash_token("beta_token_2"),
        status=RouterStatus.online,
    )
    db_session.add(second_router)
    db_session.commit()

    # Router 3: Must fail
    with pytest.raises(SubscriptionLimitExceededError) as exc_info:
        context_b.assert_can_add_router(db_session)

    assert exc_info.value.current_count == 2
    assert exc_info.value.max_limit == 2


def test_subscription_upgrade_unlocks_router_capacity(db_session: Session, seed_data: dict):
    """
    Upgrading Tenant Alpha from Starter (1 router) to Growth (4 routers)
    immediately allows adding routers up to 4.
    """
    tenant_a = seed_data["tenant_a"]
    user_a = seed_data["user_a"]
    context_a = TenantContext(tenant=tenant_a, user=user_a)

    # Initial check fails at 1/1
    with pytest.raises(SubscriptionLimitExceededError):
        context_a.assert_can_add_router(db_session)

    # Upgrade to Growth
    tenant_a.subscription.tier = SubscriptionTier.growth
    tenant_a.subscription.max_routers = SubscriptionTier.growth.max_routers
    db_session.commit()

    # Now router 2 can be added without error
    context_a.assert_can_add_router(db_session)


def test_api_create_router_limit_enforced_via_http(client, seed_data: dict):
    """
    Attempting POST /api/tenant/routers when at limit returns HTTP 403 Forbidden
    with structured error response.
    """
    user_a: TenantUser = seed_data["user_a"]

    payload = {
        "name": "Alpha-Second-Router",
        "location": "Westlands",
        "description": "Branch router",
    }
    response = client.post(
        "/api/tenant/routers",
        json=payload,
        headers={"Authorization": f"Bearer {user_a.id}"},
    )

    assert response.status_code == 403
    data = response.json()
    assert data["error"] == "subscription_limit_exceeded"
    assert data["current_count"] == 1
    assert data["max_limit"] == 1
