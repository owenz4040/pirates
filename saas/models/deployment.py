"""Hotspot captive portal deployment tracking and rollback models."""
from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from saas.database import SaasBase
from saas.models.base import TenantScopedModel


class DeploymentStatus(str, enum.Enum):
    pending = "pending"
    in_progress = "in_progress"
    verified = "verified"
    failed = "failed"
    rolled_back = "rolled_back"


class HotspotDeployment(SaasBase, TenantScopedModel):
    """Tracks a captive portal publishing job to a specific MikroTik router."""
    __tablename__ = "saas_hotspot_deployments"

    portal_design_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("saas_hotspot_portal_designs.id", ondelete="CASCADE"), index=True
    )
    router_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("saas_routers.id", ondelete="CASCADE"), index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    manifest_json: Mapped[str] = mapped_column(Text, nullable=False)  # JSON list of files, sizes, sha256
    backup_path: Mapped[str | None] = mapped_column(String(128), nullable=True)  # Router directory holding prior backup
    
    status: Mapped[DeploymentStatus] = mapped_column(
        Enum(DeploymentStatus), default=DeploymentStatus.pending, index=True
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    deployed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    portal_design: Mapped["HotspotPortalDesign"] = relationship(back_populates="deployments")
    router: Mapped["Router"] = relationship()
