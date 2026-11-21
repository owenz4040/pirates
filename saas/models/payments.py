"""Tenant-specific payment configs and platform subscription transactions."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from decimal import Decimal

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from saas.database import SaasBase
from saas.models.base import TenantScopedModel
from saas.models.tenant import SubscriptionTier
from saas.security.crypto import decrypt_secret, encrypt_secret


class TenantPaymentConfig(SaasBase):
    """
    Independent payment gateway credentials configured by a tenant ISP.
    All sensitive credentials (API keys, secrets, passkeys) are encrypted at rest with AES-256-GCM / Fernet.
    """
    __tablename__ = "tenant_payment_configs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), unique=True)

    # M-Pesa Daraja Configuration
    mpesa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mpesa_type: Mapped[str] = mapped_column(String(16), default="paybill")  # "paybill" or "till"
    mpesa_shortcode: Mapped[str | None] = mapped_column(String(32), nullable=True)
    mpesa_till_number: Mapped[str | None] = mapped_column(String(32), nullable=True)
    mpesa_consumer_key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    mpesa_consumer_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    mpesa_passkey_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Tenant's Own Paystack Configuration (for their customers)
    paystack_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    paystack_public_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    paystack_secret_key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    tenant: Mapped["Tenant"] = relationship(back_populates="payment_config")

    # Helper encryption/decryption methods
    def set_mpesa_credentials(self, consumer_key: str, consumer_secret: str, passkey: str) -> None:
        self.mpesa_consumer_key_encrypted = encrypt_secret(consumer_key) if consumer_key else None
        self.mpesa_consumer_secret_encrypted = encrypt_secret(consumer_secret) if consumer_secret else None
        self.mpesa_passkey_encrypted = encrypt_secret(passkey) if passkey else None

    def get_mpesa_credentials(self) -> dict[str, str | None]:
        return {
            "consumer_key": decrypt_secret(self.mpesa_consumer_key_encrypted) if self.mpesa_consumer_key_encrypted else None,
            "consumer_secret": decrypt_secret(self.mpesa_consumer_secret_encrypted) if self.mpesa_consumer_secret_encrypted else None,
            "passkey": decrypt_secret(self.mpesa_passkey_encrypted) if self.mpesa_passkey_encrypted else None,
        }

    def set_paystack_secret(self, secret_key: str) -> None:
        self.paystack_secret_key_encrypted = encrypt_secret(secret_key) if secret_key else None

    def get_paystack_secret(self) -> str | None:
        return decrypt_secret(self.paystack_secret_key_encrypted) if self.paystack_secret_key_encrypted else None


class SubscriptionTransaction(SaasBase):
    """
    Platform revenue audit trail: Tenant ISP subscriptions paid to platform owner.
    Collected via platform Paystack.
    """
    __tablename__ = "saas_subscription_transactions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True)
    tier: Mapped[SubscriptionTier] = mapped_column(Enum(SubscriptionTier), nullable=False)
    amount_kes: Mapped[Decimal] = mapped_column(Numeric(10, 2), nullable=False)
    paystack_reference: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)  # pending, success, failed
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    raw_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class PendingSubscriptionCheckout(SaasBase):
    """
    Pending onboarding checkout session created before tenant exists.
    Once confirmed via Paystack webhook, this is transitioned to paid and the tenant is provisioned.
    """
    __tablename__ = "saas_pending_checkouts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    paystack_reference: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    company_name: Mapped[str] = mapped_column(String(128), nullable=False)
    company_slug: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    company_email: Mapped[str] = mapped_column(String(128), nullable=False)
    company_phone: Mapped[str] = mapped_column(String(32), default="")
    admin_name: Mapped[str] = mapped_column(String(128), nullable=False)
    admin_email: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    tier: Mapped[SubscriptionTier] = mapped_column(Enum(SubscriptionTier), nullable=False)
    amount_kes: Mapped[Decimal] = mapped_column(Numeric(10, 2), nullable=False)
    currency: Mapped[str] = mapped_column(String(8), default="KES")

    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)  # pending, paid, failed
    provisioned_tenant_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True, index=True
    )

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class CustomerPayment(SaasBase, TenantScopedModel):
    """
    Tenant ISP subscriber payments: PPPoE and Hotspot voucher revenue collected directly
    by the individual tenant via their own M-Pesa / Paystack.
    """
    __tablename__ = "saas_customer_payments"

    customer_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("saas_pppoe_customers.id", ondelete="SET NULL"), nullable=True, index=True
    )
    voucher_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("saas_hotspot_vouchers.id", ondelete="SET NULL"), nullable=True, index=True
    )
    gateway: Mapped[str] = mapped_column(String(32), default="mpesa")  # "mpesa", "paystack", "cash"
    reference: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    amount_kes: Mapped[Decimal] = mapped_column(Numeric(10, 2), nullable=False)
    phone_number: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)  # pending, completed, failed
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
