from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from librouteros.api import Api
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from billing import services
from billing.db import get_db
from billing.mikrotik_dep import get_router_api
from billing.models import Customer, Plan
from billing.email import client as email_client
from billing.schemas import (
    ChangePlan,
    CustomerCreate,
    CustomerCreateOut,
    CustomerOut,
    CustomerStatusOut,
    CustomerUpdate,
)
from mikrotik.pppoe import PPPoEManager

router = APIRouter(prefix="/customers", tags=["customers"])


def _get_customer(db: Session, username: str) -> Customer:
    customer = db.scalar(select(Customer).where(Customer.pppoe_username == username))
    if customer is None:
        raise HTTPException(404, f"No customer {username!r}")
    return customer


@router.get("", response_model=list[CustomerOut])
def list_customers(db: Session = Depends(get_db)) -> list[Customer]:
    return list(db.scalars(select(Customer)))


@router.post("", response_model=CustomerCreateOut, status_code=201)
def create_customer(
    payload: CustomerCreate,
    db: Session = Depends(get_db),
    api: Api = Depends(get_router_api),
) -> dict:
    plan = db.get(Plan, payload.plan_id)
    if plan is None:
        raise HTTPException(404, f"No plan with id {payload.plan_id}")
    if db.scalar(select(Customer).where(Customer.pppoe_username == payload.pppoe_username)):
        raise HTTPException(409, f"PPPoE username {payload.pppoe_username!r} already exists")

    ppp = PPPoEManager(api)
    customer = services.create_customer(
        db,
        ppp,
        pppoe_username=payload.pppoe_username,
        pppoe_password=payload.pppoe_password,
        full_name=payload.full_name,
        phone_number=payload.phone_number,
        email=payload.email,
        plan=plan,
    )

    welcome_email_sent = False
    welcome_email_error = None
    if customer.email:
        try:
            paybill_info = services.request_paybill_charge(db, customer)
            subject, html, text = services.compose_welcome_email(customer, paybill_info)
            email_client.send_email(customer.email, subject, html, text)
            welcome_email_sent = True
        except Exception as exc:  # noqa: BLE001 - the welcome email is best-effort, never fatal to signup
            welcome_email_error = str(exc)
    else:
        welcome_email_error = "No email on file"

    return {
        **CustomerOut.model_validate(customer).model_dump(),
        "welcome_email_sent": welcome_email_sent,
        "welcome_email_error": welcome_email_error,
    }


@router.get("/{username}", response_model=CustomerStatusOut)
def get_customer(
    username: str,
    db: Session = Depends(get_db),
    api: Api = Depends(get_router_api),
) -> dict:
    customer = _get_customer(db, username)
    ppp = PPPoEManager(api)
    return {
        **CustomerOut.model_validate(customer).model_dump(),
        "online": ppp.is_online(username),
    }


@router.patch("/{username}", response_model=CustomerOut)
def update_customer(
    username: str,
    payload: CustomerUpdate,
    db: Session = Depends(get_db),
) -> Customer:
    """Edit contact details (name/phone/email). Doesn't touch the router or subscription state."""
    customer = _get_customer(db, username)
    try:
        return services.update_customer_details(
            db,
            customer,
            full_name=payload.full_name,
            phone_number=payload.phone_number,
            email=payload.email,
        )
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, f"Phone number {payload.phone_number!r} is already in use") from None


@router.post("/{username}/suspend", response_model=CustomerOut)
def suspend_customer(
    username: str,
    db: Session = Depends(get_db),
    api: Api = Depends(get_router_api),
) -> Customer:
    customer = _get_customer(db, username)
    ppp = PPPoEManager(api)
    return services.suspend_customer(db, ppp, customer)


@router.post("/{username}/plan", response_model=CustomerOut)
def change_customer_plan(
    username: str,
    payload: ChangePlan,
    db: Session = Depends(get_db),
    api: Api = Depends(get_router_api),
) -> Customer:
    """Move a customer to a different plan (e.g. a bandwidth upgrade). Applies on the router immediately if they're active."""
    customer = _get_customer(db, username)
    new_plan = db.get(Plan, payload.plan_id)
    if new_plan is None:
        raise HTTPException(404, f"No plan with id {payload.plan_id}")
    ppp = PPPoEManager(api)
    return services.change_plan(db, ppp, customer, new_plan)
