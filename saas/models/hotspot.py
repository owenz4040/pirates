"""Hotspot packages, vouchers, and captive portal designs."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from saas.database import SaasBase
from saas.models.base import TenantScopedModel

if TYPE_CHECKING:
    from saas.models.deployment import HotspotDeployment
    from saas.models.router import Router, RouterCommand


class VoucherStatus(str, enum.Enum):
    unused = "unused"
    pending_provisioning = "pending_provisioning"
    active = "active"
    used = "used"
    expired = "expired"
    provisioning_failed = "provisioning_failed"


class HotspotPackage(SaasBase, TenantScopedModel):
    """Hotspot package with pricing, duration, and speed limits."""
    __tablename__ = "saas_hotspot_packages"

    name: Mapped[str] = mapped_column(String(64), nullable=False)
    price_kes: Mapped[Decimal] = mapped_column(Numeric(10, 2), nullable=False)
    duration_minutes: Mapped[int] = mapped_column(Integer, nullable=False)  # Duration in minutes
    rate_limit: Mapped[str] = mapped_column(String(32), default="5M/10M")
    data_limit_mb: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    vouchers: Mapped[list["HotspotVoucher"]] = relationship(back_populates="package", cascade="all, delete-orphan")


class HotspotVoucher(SaasBase, TenantScopedModel):
    """Time/Data voucher code for MikroTik hotspot login."""
    __tablename__ = "saas_hotspot_vouchers"

    package_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("saas_hotspot_packages.id", ondelete="CASCADE"), index=True
    )
    router_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("saas_routers.id", ondelete="SET NULL"), nullable=True, index=True
    )
    code: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    password: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[VoucherStatus] = mapped_column(Enum(VoucherStatus), default=VoucherStatus.unused, index=True)
    batch_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    customer_payment_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    router_command_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("saas_router_commands.id", use_alter=True, ondelete="SET NULL"), nullable=True, index=True
    )
    
    first_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    package: Mapped["HotspotPackage"] = relationship(back_populates="vouchers")
    router_command: Mapped["RouterCommand | None"] = relationship(foreign_keys=[router_command_id])


class HotspotPortalDesign(SaasBase, TenantScopedModel):
    """Custom captive portal branding and configuration per tenant."""
    __tablename__ = "saas_hotspot_portal_designs"

    name: Mapped[str] = mapped_column(String(64), default="Default Portal")
    template_id: Mapped[str] = mapped_column(String(32), default="gold_standard")
    brand_name: Mapped[str] = mapped_column(String(64), nullable=False)
    headline: Mapped[str] = mapped_column(String(128), default="Welcome to High-Speed WiFi")
    primary_color: Mapped[str] = mapped_column(String(32), default="#dfb758")
    secondary_color: Mapped[str] = mapped_column(String(32), default="#090a0f")
    accent_color: Mapped[str] = mapped_column(String(32), default="#b8913e")
    logo_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    background_image_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    custom_css: Mapped[str | None] = mapped_column(Text, nullable=True)
    banner_html: Mapped[str | None] = mapped_column(Text, nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    is_default: Mapped[bool] = mapped_column(Boolean, default=True)

    deployments: Mapped[list["HotspotDeployment"]] = relationship(back_populates="portal_design")


class HotspotNetwork(SaasBase, TenantScopedModel):
    """Automatic MikroTik Hotspot Network configuration, bridge ports, wireless, and DHCP."""
    __tablename__ = "saas_hotspot_networks"

    router_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("saas_routers.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(64), nullable=False)

    # Wireless Configuration
    ssid: Mapped[str] = mapped_column(String(64), nullable=False, default="COwen WiFi")
    wifi_security: Mapped[str] = mapped_column(String(32), default="open")  # open or wpa2-psk
    wifi_password_encrypted: Mapped[str | None] = mapped_column(String(255), nullable=True)
    wireless_band: Mapped[str] = mapped_column(String(32), default="2ghz-b/g/n")
    wireless_channel: Mapped[str] = mapped_column(String(32), default="auto")
    wireless_country: Mapped[str] = mapped_column(String(32), default="no_country_set")
    wlan_interface: Mapped[str | None] = mapped_column(String(32), default="wlan1")
    include_wlan: Mapped[bool] = mapped_column(Boolean, default=True)

    # Bridge & Ethernet Configuration
    bridge_name: Mapped[str] = mapped_column(String(32), default="COwen-Hotspot-Bridge")
    ethernet_ports_json: Mapped[str] = mapped_column(String(255), default='["ether2","ether3","ether4"]')

    # IP, DHCP & DNS Configuration
    gateway_ip: Mapped[str] = mapped_column(String(32), default="10.5.50.1")
    netmask: Mapped[str] = mapped_column(String(32), default="255.255.255.0")
    network_cidr: Mapped[str] = mapped_column(String(32), default="10.5.50.0/24")
    dhcp_pool_start: Mapped[str] = mapped_column(String(32), default="10.5.50.10")
    dhcp_pool_end: Mapped[str] = mapped_column(String(32), default="10.5.50.250")
    dns_name: Mapped[str] = mapped_column(String(64), default="login.hotspot")
    dns_servers: Mapped[str] = mapped_column(String(128), default="10.5.50.1,8.8.8.8,1.1.1.1")

    # Hotspot Server & Profile Configuration
    server_name: Mapped[str] = mapped_column(String(32), default="COwen-Hotspot-Server")
    server_profile_name: Mapped[str] = mapped_column(String(32), default="COwen-Hotspot-Profile")
    html_directory: Mapped[str] = mapped_column(String(64), default="hotspot")

    # Status: draft, queued, provisioned, failed
    status: Mapped[str] = mapped_column(String(32), default="draft", index=True)

    # Relationships
    router: Mapped["Router"] = relationship()

