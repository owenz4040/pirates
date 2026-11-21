"""Multi-Router entities, sync queues, and command models."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from saas.database import SaasBase
from saas.models.base import TenantScopedModel

if TYPE_CHECKING:
    from saas.models.tenant import Tenant


class RouterStatus(str, enum.Enum):
    online = "online"
    offline = "offline"
    provisioning = "provisioning"
    suspended = "suspended"


class RouterCommandStatus(str, enum.Enum):
    pending = "pending"
    sent = "sent"
    done = "done"
    failed = "failed"


class Router(SaasBase, TenantScopedModel):
    """A MikroTik router connected by a tenant ISP."""
    __tablename__ = "saas_routers"

    name: Mapped[str] = mapped_column(String(64), nullable=False)
    # Stored as SHA-256 hash for secure authentication comparison
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    location: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[RouterStatus] = mapped_column(Enum(RouterStatus), default=RouterStatus.provisioning)
    
    # Telemetry reported by router on sync
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    board: Mapped[str | None] = mapped_column(String(64), nullable=True)
    uptime: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cpu_load: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    tenant: Mapped["Tenant"] = relationship(back_populates="routers")
    commands: Mapped[list["RouterCommand"]] = relationship(back_populates="router", cascade="all, delete-orphan")


class RouterCommand(SaasBase, TenantScopedModel):
    """Queued command line to be pulled by a specific router."""
    __tablename__ = "saas_router_commands"

    router_id: Mapped[str] = mapped_column(String(36), ForeignKey("saas_routers.id", ondelete="CASCADE"), index=True)
    voucher_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("saas_hotspot_vouchers.id", use_alter=True, ondelete="SET NULL"), nullable=True, index=True
    )
    description: Mapped[str] = mapped_column(String(255), nullable=False)
    script: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[RouterCommandStatus] = mapped_column(
        Enum(RouterCommandStatus), default=RouterCommandStatus.pending, index=True
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    router: Mapped["Router"] = relationship(back_populates="commands")
