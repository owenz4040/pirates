from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from librouteros.api import Api
from sqlalchemy import select
from sqlalchemy.orm import Session

from billing import services
from billing.db import get_db
from billing.mikrotik_dep import get_router_api
from billing.models import Plan
from billing.schemas import PlanCreate, PlanOut, PlanUpdate
from mikrotik.bandwidth import BandwidthProfileManager

router = APIRouter(prefix="/plans", tags=["plans"])


@router.get("", response_model=list[PlanOut])
def list_plans(db: Session = Depends(get_db)) -> list[Plan]:
    return list(db.scalars(select(Plan).order_by(Plan.price_kes)))


@router.post("", response_model=PlanOut, status_code=201)
def create_plan(payload: PlanCreate, db: Session = Depends(get_db)) -> Plan:
    if db.scalar(select(Plan).where(Plan.name == payload.name)):
        raise HTTPException(409, f"Plan {payload.name!r} already exists")
    plan = Plan(**payload.model_dump())
    db.add(plan)
    db.commit()
    db.refresh(plan)
    return plan


@router.patch("/{plan_id}", response_model=PlanOut)
def update_plan(
    plan_id: int,
    payload: PlanUpdate,
    db: Session = Depends(get_db),
    api: Api = Depends(get_router_api),
) -> Plan:
    """Edit a plan's price/speed/duration. Changing rate_limit also updates the RouterOS PPP profile."""
    plan = db.get(Plan, plan_id)
    if plan is None:
        raise HTTPException(404, f"No plan with id {plan_id}")
    bw = BandwidthProfileManager(api)
    return services.update_plan(
        db,
        bw,
        plan,
        rate_limit=payload.rate_limit,
        price_kes=payload.price_kes,
        duration_days=payload.duration_days,
    )
