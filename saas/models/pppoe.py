"""PPPoE and Static IP subscriber and bandwidth package models."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from decimal import Decimal

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, Numeric, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from saas.database import SaasBase
from saas.models.base import TenantScopedModel


class CustomerStatus(str, enum.Enum):
    active = "active"
    suspended = "suspended"
    expired = "expired"


class ConnectionType(str, enum.Enum):
    pppoe = "pppoe"
    static = "static"


class PPPoEPlan(SaasBase, TenantScopedModel):
    """Bandwidth speed tier configured by a tenant."""
    __tablename__ = "saas_pppoe_plans"

    name: Mapped[str] = mapped_column(String(64), nullable=False)
    rate_limit: Mapped[str] = mapped_column(String(32), nullable=False)  # e.g. "10M/10M"
    marketing_speed: Mapped[str | None] = mapped_column(String(32), nullable=True)  # e.g. "10 Mbps"
    price_kes: Mapped[Decimal] = mapped_column(Numeric(10, 2), nullable=False)
    duration_days: Mapped[int] = mapped_column(Integer, default=30)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    customers: Mapped[list["PPPoECustomer"]] = relationship(back_populates="plan")


class PPPoECustomer(SaasBase, TenantScopedModel):
    """A PPPoE or Static subscriber belonging to a tenant."""
    __tablename__ = "saas_pppoe_customers"

    router_id: Mapped[str] = mapped_column(String(36), ForeignKey("saas_routers.id", ondelete="CASCADE"), index=True)
    plan_id: Mapped[str] = mapped_column(String(36), ForeignKey("saas_pppoe_plans.id"), index=True)
    
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    password: Mapped[str] = mapped_column(String(64), nullable=False)
    full_name: Mapped[str] = mapped_column(String(128), nullable=False)
    phone_number: Mapped[str | None] = mapped_column(String(32), nullable=True)
    email: Mapped[str | None] = mapped_column(String(128), nullable=True)
    
    connection_type: Mapped[ConnectionType] = mapped_column(Enum(ConnectionType), default=ConnectionType.pppoe)
    static_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    
    status: Mapped[CustomerStatus] = mapped_column(Enum(CustomerStatus), default=CustomerStatus.active)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    pay_token: Mapped[str] = mapped_column(String(32), unique=True, default=lambda: uuid.uuid4().hex[:16])

    plan: Mapped["PPPoEPlan"] = relationship(back_populates="customers")
