"""Tenant context and security enforcement utilities."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TypeVar

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from saas.database import get_saas_db
from saas.models.base import TenantScopedModel
from saas.models.router import Router
from saas.models.tenant import Tenant, TenantStatus, TenantUser, UserRole

T = TypeVar("T", bound=TenantScopedModel)


class SubscriptionLimitExceededError(Exception):
    """Raised when an action violates the tenant's current subscription limits."""
    def __init__(self, message: str, current_count: int, max_limit: int):
        super().__init__(message)
        self.current_count = current_count
        self.max_limit = max_limit


@dataclass
class TenantContext:
    """Security context holding authenticated tenant and user."""
    tenant: Tenant
    user: TenantUser

    @property
    def is_superadmin(self) -> bool:
        return self.user.role == UserRole.superadmin

    @property
    def is_tenant_admin(self) -> bool:
        return self.user.role in (UserRole.superadmin, UserRole.tenant_admin)

    def scope_query(self, query: Select[tuple[T]], model_cls: type[T]) -> Select[tuple[T]]:
        """
        Applies tenant isolation to a SQLAlchemy select query.
        Guarantees that a tenant can only query records belonging to their own tenant_id.
        """
        if self.is_superadmin and not getattr(self, "enforce_tenant_scoping_for_admin", False):
            # Superadmin can view tenant-scoped if requested, otherwise see all
            return query
        return query.where(model_cls.tenant_id == self.tenant.id)

    def assert_can_add_router(self, db: Session) -> None:
        """
        Verifies that adding a new router will not exceed the tenant's subscription limit.
        Starter: 1, Basic: 2, Growth: 4, Business: 6.
        """
        if not self.tenant.subscription:
            raise SubscriptionLimitExceededError("Tenant has no active subscription.", 0, 0)

        max_allowed = self.tenant.subscription.max_routers or self.tenant.subscription.tier.max_routers
        current_count = db.scalar(
            select(func.count(Router.id)).where(Router.tenant_id == self.tenant.id)
        ) or 0

        if current_count >= max_allowed:
            raise SubscriptionLimitExceededError(
                f"Router limit reached ({current_count}/{max_allowed}) for plan '{self.tenant.subscription.tier.value}'. Please upgrade your subscription to add more routers.",
                current_count=current_count,
                max_limit=max_allowed,
            )


def resolve_tenant_context(
    request: Request,
    authorization: str | None = Header(None),
    x_tenant_slug: str | None = Header(None),
    db: Session = Depends(get_saas_db),
) -> TenantContext:
    """
    FastAPI dependency that extracts the active tenant and authenticated user.
    Supports session user, API token, or tenant slug resolution.
    """
    # 1. Check session state if set by auth middleware
    user_id = request.session.get("user_id") if "session" in request.scope else None
    
    user: TenantUser | None = None
    if user_id:
        user = db.scalar(select(TenantUser).where(TenantUser.id == user_id, TenantUser.is_active == True))

    if not user:
        # Check Authorization header bearer token or fallback for testing / internal calls
        if authorization and authorization.startswith("Bearer "):
            token = authorization[7:].strip()
            # For testing/mocking or token session:
            user = db.scalar(select(TenantUser).where(TenantUser.id == token, TenantUser.is_active == True))

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Resolve tenant
    tenant: Tenant | None = None
    if user.role == UserRole.superadmin:
        if x_tenant_slug:
            tenant = db.scalar(select(Tenant).where(Tenant.slug == x_tenant_slug))
        elif user.tenant_id:
            tenant = db.scalar(select(Tenant).where(Tenant.id == user.tenant_id))
        else:
            # Platform superadmin without a specific tenant context
            # Create a virtual shell tenant or use target
            tenant = db.scalar(select(Tenant).order_by(Tenant.created_at.asc()))
    else:
        if not user.tenant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not associated with an ISP tenant.",
            )
        tenant = db.scalar(select(Tenant).where(Tenant.id == user.tenant_id))

    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant company not found.",
        )

    if tenant.status == TenantStatus.suspended:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This ISP account is currently suspended. Please contact platform support.",
        )

    return TenantContext(tenant=tenant, user=user)
