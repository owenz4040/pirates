from __future__ import annotations

import enum
import secrets
from datetime import datetime
from decimal import Decimal

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, Numeric, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from billing.db import Base


class Plan(Base):
    """A pricing/speed tier. `name` must match a RouterOS /ppp/profile name."""

    __tablename__ = "plans"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    rate_limit: Mapped[str] = mapped_column(String(32))  # RouterOS format, e.g. "9M/9M"
    # What customers are told the plan is (e.g. "10mbps") - independent of
    # `name`/`rate_limit`, since the RouterOS limit is often set below the
    # advertised speed for overhead. Falls back to parsing `name` if unset.
    marketing_speed: Mapped[str | None] = mapped_column(String(32), nullable=True)
    price_kes: Mapped[Decimal] = mapped_column(Numeric(10, 2))
    duration_days: Mapped[int] = mapped_column(default=30)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    customers: Mapped[list["Customer"]] = relationship(back_populates="plan")


class CustomerStatus(str, enum.Enum):
    active = "active"
    suspended = "suspended"  # manually suspended (e.g. support/abuse), not billing-related
    expired = "expired"  # suspended by the expiry worker for non-payment


class Customer(Base):
    """A subscriber. One row per PPPoE account."""

    __tablename__ = "customers"

    id: Mapped[int] = mapped_column(primary_key=True)
    pppoe_username: Mapped[str] = mapped_column(String(64), unique=True)
    full_name: Mapped[str] = mapped_column(String(128))
    phone_number: Mapped[str] = mapped_column(String(20), unique=True)  # 2547XXXXXXXX, used for M-Pesa STK push
    email: Mapped[str | None] = mapped_column(String(128), nullable=True)  # optional - welcome email if present
    # Unguessable secret embedded in the "Pay Now" email link so clicking it
    # can only trigger a charge for this one customer, not any username.
    pay_token: Mapped[str] = mapped_column(String(32), unique=True, default=lambda: secrets.token_hex(16))
    plan_id: Mapped[int] = mapped_column(ForeignKey("plans.id"))
    status: Mapped[CustomerStatus] = mapped_column(
        Enum(CustomerStatus, name="customer_status"), default=CustomerStatus.active
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reminder_2_days_sent: Mapped[bool] = mapped_column(default=False, server_default="false")
    reminder_1_day_sent: Mapped[bool] = mapped_column(default=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    plan: Mapped["Plan"] = relationship(back_populates="customers")
    payments: Mapped[list["Payment"]] = relationship(back_populates="customer")


class PaymentStatus(str, enum.Enum):
    pending = "pending"  # STK push sent, waiting on the Paystack webhook
    confirmed = "confirmed"
    failed = "failed"


class Payment(Base):
    """One M-Pesa payment attempt. `pending` rows are created before the Paystack webhook arrives."""

    __tablename__ = "payments"

    id: Mapped[int] = mapped_column(primary_key=True)
    customer_id: Mapped[int] = mapped_column(ForeignKey("customers.id"))
    amount_kes: Mapped[Decimal] = mapped_column(Numeric(10, 2))
    status: Mapped[PaymentStatus] = mapped_column(
        Enum(PaymentStatus, name="payment_status"), default=PaymentStatus.pending
    )
    mpesa_receipt: Mapped[str | None] = mapped_column(String(32), unique=True, nullable=True)
    checkout_request_id: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    phone_number: Mapped[str] = mapped_column(String(20))
    raw_callback: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    customer: Mapped["Customer"] = relationship(back_populates="payments")
