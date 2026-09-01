from __future__ import annotations

import json
import secrets
from decimal import Decimal
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from billing import services
from billing.db import get_db
from billing.email import client as email_client
from billing.models import Customer, Payment
from billing.mpesa import paystack
from billing.mpesa.paystack import PaystackError
from billing.schemas import _normalize_kenyan_phone
from mikrotik.client import router_connection
from mikrotik.pppoe import PPPoEManager

router = APIRouter(tags=["mpesa"])


@router.post("/customers/{username}/mpesa/charge", status_code=202)
def charge(username: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Push an M-Pesa PIN prompt to the customer's phone, via Paystack, for their plan's price."""
    customer = db.scalar(select(Customer).where(Customer.pppoe_username == username))
    if customer is None:
        raise HTTPException(404, f"No customer {username!r}")
    try:
        reference = services.request_mpesa_charge(db, customer)
    except PaystackError as exc:
        raise HTTPException(502, str(exc)) from exc
    return {"reference": reference}


@router.post("/customers/{username}/mpesa/paybill", status_code=202)
def paybill_charge(username: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """
    Generate a one-time Paystack paybill code for this customer's plan price.

    Unlike /mpesa/charge, nothing is pushed to a phone - relay the returned
    paybill/account/amount to the customer (SMS, app screen, etc.) so they
    can pay manually via *334# or the M-Pesa app.
    """
    customer = db.scalar(select(Customer).where(Customer.pppoe_username == username))
    if customer is None:
        raise HTTPException(404, f"No customer {username!r}")
    try:
        return services.request_paybill_charge(db, customer)
    except PaystackError as exc:
        raise HTTPException(502, str(exc)) from exc


def _pay_page(heading: str, message: str, *, ok: bool) -> str:
    accent = "#c9a24b" if ok else "#e0554f"
    return f"""\
<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pirates Wifi</title></head>
<body style="margin:0;background:#050810;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <div style="max-width:420px;margin:64px auto;padding:0 20px;">
    <div style="background:#0c1120;border:1px solid {accent};border-radius:12px;padding:36px 28px;text-align:center;">
      <div style="color:{accent};font-size:11px;font-weight:600;letter-spacing:0.2em;text-transform:uppercase;margin-bottom:14px;">Pirates Wifi</div>
      <h1 style="margin:0 0 12px;color:#f5efe0;font-size:20px;">{heading}</h1>
      <p style="margin:0;color:#9aa3b8;font-size:14px;line-height:1.6;">{message}</p>
    </div>
  </div>
</body></html>
"""


@router.get("/pay/{username}/{token}/mpesa")
def public_mpesa_prompt(username: str, token: str, db: Session = Depends(get_db)) -> HTMLResponse:
    """
    Public, no-admin-auth landing page for the "Pay Now" button in the
    welcome email. `token` is the customer's unguessable pay_token, so this
    can only trigger a charge for the one customer that link was sent to -
    without it, anyone could spam any username's phone with M-Pesa prompts.
    """
    customer = db.scalar(select(Customer).where(Customer.pppoe_username == username))
    if customer is None or not secrets.compare_digest(customer.pay_token, token):
        return HTMLResponse(
            _pay_page("Link not found", "This payment link is invalid.", ok=False), status_code=404
        )

    try:
        services.request_mpesa_charge(db, customer)
    except PaystackError as exc:
        return HTMLResponse(_pay_page("Couldn't send prompt", str(exc), ok=False), status_code=502)

    return HTMLResponse(
        _pay_page(
            "Check your phone",
            f"An M-Pesa PIN prompt has been sent to {customer.phone_number}. Enter your PIN to complete "
            "payment - your internet activates automatically once it's confirmed.",
            ok=True,
        )
    )


@router.post("/paystack/webhook")
async def paystack_webhook(request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
    """
    Paystack posts every account event here (configure this URL once in the
    Paystack dashboard, not per-request). Verify the signature before trusting
    anything in the body - this endpoint is public and anyone can guess its path.
    """
    raw_body = await request.body()
    signature = request.headers.get("x-paystack-signature", "")
    if not signature or not paystack.verify_signature(raw_body, signature):
        raise HTTPException(401, "Invalid Paystack signature")

    payload = json.loads(raw_body)
    if not payload.get("event", "").startswith("charge."):
        return {"status": "ignored"}

    result = paystack.parse_webhook_event(payload)
    payment = db.scalar(select(Payment).where(Payment.checkout_request_id == result["reference"]))

    if payment is None and result["event"] == "charge.success" and result["status"] == "success" and result["payer_phone"]:
        # No exact paybill-code match - fall back to matching by the phone
        # number that actually paid, for walk-in payments that didn't use
        # the exact code we generated (e.g. typed their username instead).
        try:
            payer_phone = _normalize_kenyan_phone(result["payer_phone"])
        except ValueError:
            payer_phone = None
        customer = services.find_customer_by_phone(db, payer_phone) if payer_phone else None
        if customer is not None:
            payment = services.create_pending_payment(
                db,
                customer=customer,
                amount_kes=Decimal(str(result["amount_kes"])),
                phone_number=payer_phone,
                checkout_request_id=result["reference"],
            )

    if payment is None:
        return {"status": "ignored"}

    if result["event"] == "charge.success" and result["status"] == "success":
        with router_connection() as api:
            ppp = PPPoEManager(api)
            payment = services.confirm_payment(
                db,
                ppp,
                payment,
                mpesa_receipt=str(result["paystack_transaction_id"]),
                raw_callback=payload,
            )
        if payment.customer.email:
            try:
                subject, html, text = services.compose_receipt_email(payment.customer, payment)
                email_client.send_email(payment.customer.email, subject, html, text)
            except Exception:  # noqa: BLE001 - the receipt is best-effort, never fatal to activation
                pass
    else:
        services.fail_payment(db, payment, raw_callback=payload)

    return {"status": "ok"}
