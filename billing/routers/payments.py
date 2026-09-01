from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from librouteros.api import Api
from sqlalchemy import select
from sqlalchemy.orm import Session

from billing import services
from billing.db import get_db
from billing.mikrotik_dep import get_router_api
from billing.models import Customer, Payment
from billing.schemas import PaymentCreate, PaymentOut
from mikrotik.pppoe import PPPoEManager

router = APIRouter(prefix="/customers/{username}/payments", tags=["payments"])


@router.get("", response_model=list[PaymentOut])
def list_payments(username: str, db: Session = Depends(get_db)) -> list[Payment]:
    customer = db.scalar(select(Customer).where(Customer.pppoe_username == username))
    if customer is None:
        raise HTTPException(404, f"No customer {username!r}")
    return list(customer.payments)


@router.post("", response_model=PaymentOut, status_code=201)
def record_payment(
    username: str,
    payload: PaymentCreate,
    db: Session = Depends(get_db),
    api: Api = Depends(get_router_api),
) -> Payment:
    """
    Manual payment entry: records the payment, extends the subscription, and
    re-enables the router account immediately (no webhook round-trip). Use
    this for cash payments or one-off adjustments; M-Pesa payments normally
    go through POST /customers/{username}/mpesa/charge instead, which
    confirms asynchronously via the Paystack webhook.
    """
    customer = db.scalar(select(Customer).where(Customer.pppoe_username == username))
    if customer is None:
        raise HTTPException(404, f"No customer {username!r}")

    ppp = PPPoEManager(api)
    return services.record_payment(
        db,
        ppp,
        customer=customer,
        amount_kes=payload.amount_kes,
        mpesa_receipt=payload.mpesa_receipt,
        phone_number=payload.phone_number,
    )
