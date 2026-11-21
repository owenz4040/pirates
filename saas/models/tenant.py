"""Tenant, Branding, Subscription, and User models."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from decimal import Decimal

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from saas.database import SaasBase


class TenantStatus(str, enum.Enum):
    active = "active"
    suspended = "suspended"
    pending_payment = "pending_payment"


class SubscriptionTier(str, enum.Enum):
    starter = "starter"    # KSh 1,000 / 1 router
    basic = "basic"        # KSh 1,500 / 2 routers
    growth = "growth"      # KSh 3,500 / 4 routers
    business = "business"  # KSh 5,000 / 6 routers

    @property
    def max_routers(self) -> int:
        limits = {
            SubscriptionTier.starter: 1,
            SubscriptionTier.basic: 2,
            SubscriptionTier.growth: 4,
            SubscriptionTier.business: 6,
        }
        return limits.get(self, 1)

    @property
    def monthly_price_kes(self) -> Decimal:
        prices = {
            SubscriptionTier.starter: Decimal("1000.00"),
            SubscriptionTier.basic: Decimal("1500.00"),
            SubscriptionTier.growth: Decimal("3500.00"),
            SubscriptionTier.business: Decimal("5000.00"),
        }
        return prices.get(self, Decimal("1000.00"))


class UserRole(str, enum.Enum):
    superadmin = "superadmin"
    tenant_admin = "tenant_admin"
    tenant_staff = "tenant_staff"


class Tenant(SaasBase):
    """Company account representing an independent ISP or WiFi provider."""
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    contact_email: Mapped[str] = mapped_column(String(128), nullable=False)
    contact_phone: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[TenantStatus] = mapped_column(
        Enum(TenantStatus), default=TenantStatus.pending_payment, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Relationships
    branding: Mapped["TenantBranding"] = relationship(back_populates="tenant", uselist=False, cascade="all, delete-orphan")
    subscription: Mapped["TenantSubscription"] = relationship(back_populates="tenant", uselist=False, cascade="all, delete-orphan")
    users: Mapped[list["TenantUser"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    routers: Mapped[list["Router"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    payment_config: Mapped["TenantPaymentConfig"] = relationship(back_populates="tenant", uselist=False, cascade="all, delete-orphan")
    invitations: Mapped[list["TenantInvitation"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")


class TenantBranding(SaasBase):
    """Custom white-label branding configurations for a tenant."""
    __tablename__ = "tenant_brandings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), unique=True)
    logo_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    primary_color: Mapped[str] = mapped_column(String(32), default="#dfb758")
    secondary_color: Mapped[str] = mapped_column(String(32), default="#090a0f")
    accent_color: Mapped[str] = mapped_column(String(32), default="#b8913e")
    company_title: Mapped[str] = mapped_column(String(128), default="ISP Billing")
    support_phone: Mapped[str | None] = mapped_column(String(32), nullable=True)
    support_email: Mapped[str | None] = mapped_column(String(128), nullable=True)

    tenant: Mapped["Tenant"] = relationship(back_populates="branding")


class TenantSubscription(SaasBase):
    """Active SaaS subscription for a tenant."""
    __tablename__ = "tenant_subscriptions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), unique=True)
    tier: Mapped[SubscriptionTier] = mapped_column(Enum(SubscriptionTier), default=SubscriptionTier.starter)
    max_routers: Mapped[int] = mapped_column(Integer, default=1)
    monthly_price_kes: Mapped[Decimal] = mapped_column(Numeric(10, 2), default=Decimal("1000.00"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    auto_renew: Mapped[bool] = mapped_column(Boolean, default=True)

    tenant: Mapped["Tenant"] = relationship(back_populates="subscription")


class TenantUser(SaasBase):
    """Platform Superadmin, Tenant Admin, or Staff user."""
    __tablename__ = "tenant_users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)
    email: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(128), nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.tenant_admin, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=True)
    
    # Session version for immediate session revocation
    session_version: Mapped[int] = mapped_column(Integer, default=1)

    # Encrypted TOTP secret (AES-256 Fernet)
    totp_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    tenant: Mapped["Tenant | None"] = relationship(back_populates="users")
    recovery_codes: Mapped[list["TenantUserRecoveryCode"]] = relationship(cascade="all, delete-orphan")


class TenantUserRecoveryCode(SaasBase):
    """Single-use, hashed MFA recovery codes for emergency account access."""
    __tablename__ = "tenant_user_recovery_codes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenant_users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    code_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    is_used: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class SuperadminEnrollment(SaasBase):
    """
    Tracks initial CLI superadmin bootstrap, single-use email verification OTP,
    and mandatory MFA setup prior to account activation and role assignment.
    """
    __tablename__ = "saas_superadmin_enrollments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(128), default="Platform Owner")
    
    # Cryptographic SHA-256 hash of single-use 6-digit email OTP
    otp_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    otp_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    
    # Temporarily staged TOTP secret for MFA verification during setup (AES-256 encrypted)
    totp_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    setup_session_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_completed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class TenantInvitation(SaasBase):
    """Single-use, expiring invitation token for new tenant administrator setup."""
    __tablename__ = "tenant_invitations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    email: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(128), nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.tenant_admin, nullable=False)
    
    # SHA-256 hash of single-use secure random token
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_used: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    tenant: Mapped["Tenant"] = relationship(back_populates="invitations")
