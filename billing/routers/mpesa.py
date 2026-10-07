from __future__ import annotations

import html
import json
import secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from billing import router_sync, services
from billing.auth import require_admin
from billing.db import get_db
from billing.email import client as email_client
from billing.models import Customer, Payment, PaymentStatus
from billing.mpesa import paystack
from billing.mpesa.paystack import PaystackError
from billing.schemas import _normalize_kenyan_phone

router = APIRouter(tags=["mpesa"])


@router.post("/customers/{username}/mpesa/charge", status_code=202, dependencies=[Depends(require_admin)])
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


@router.post("/customers/{username}/mpesa/paybill", status_code=202, dependencies=[Depends(require_admin)])
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


# One M-Pesa request per customer per this long, however often the link is used.
PROMPT_COOLDOWN = timedelta(seconds=90)


def _pay_page(heading: str, message: str, *, ok: bool, button: str | None = None) -> str:
    accent = "#c9a24b" if ok else "#e0554f"
    form = (
        f'<form method="post" style="margin-top:22px;"><button type="submit" style="background:{accent};color:#050810;'
        f'border:0;border-radius:8px;padding:12px 22px;font-size:15px;font-weight:600;cursor:pointer;">'
        f"{html.escape(button)}</button></form>"
        if button
        else ""
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>Pirates Wifi</title></head>
<body style="margin:0;background:#050810;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <div style="max-width:420px;margin:64px auto;padding:0 20px;">
    <div style="background:#0c1120;border:1px solid {accent};border-radius:12px;padding:36px 28px;text-align:center;">
      <div style="color:{accent};font-size:11px;font-weight:600;letter-spacing:0.2em;text-transform:uppercase;margin-bottom:14px;">Pirates Wifi</div>
      <h1 style="margin:0 0 12px;color:#f5efe0;font-size:20px;">{html.escape(heading)}</h1>
      <p style="margin:0;color:#9aa3b8;font-size:14px;line-height:1.6;">{html.escape(message)}</p>
      {form}
    </div>
  </div>
</body></html>
"""


def _masked(phone: str | None) -> str:
    return f"{phone[:5]}•••••{phone[-3:]}" if phone and len(phone) > 8 else "your phone"


def _pay_customer(db: Session, username: str, token: str) -> Customer | None:
    customer = db.scalar(select(Customer).where(Customer.pppoe_username == username))
    if customer is None or not secrets.compare_digest(customer.pay_token, token):
        return None
    return customer


def _not_found() -> HTMLResponse:
    return HTMLResponse(_pay_page("Link not found", "This payment link is invalid.", ok=False), status_code=404)


@router.get("/pay/{username}/{token}/mpesa")
def public_pay_page(username: str, token: str, db: Session = Depends(get_db)) -> HTMLResponse:
    """
    Landing page for the "Pay with M-Pesa" email link. Opening it changes
    nothing - email security scanners open links automatically, so the M-Pesa
    request is only sent when the customer presses the button (a POST).
    """
    customer = _pay_customer(db, username, token)
    if customer is None:
        return _not_found()
    return HTMLResponse(
        _pay_page(
            f"Pay KES {int(customer.plan.price_kes)}",
            f"Account {customer.pppoe_username}. We'll send an M-Pesa payment request to {_masked(customer.phone_number)} "
            "for you to approve.",
            ok=True,
            button="Send M-Pesa request",
        ),
        headers={"Cache-Control": "no-store"},
    )


@router.post("/pay/{username}/{token}/mpesa")
def public_mpesa_prompt(username: str, token: str, db: Session = Depends(get_db)) -> HTMLResponse:
    """
    Sends the STK push. `token` is the customer's unguessable pay_token, so
    this only ever charges the customer the link was sent to, and the
    cooldown stops the link being used to flood their phone with prompts.
    """
    customer = _pay_customer(db, username, token)
    if customer is None:
        return _not_found()
    recent = db.scalar(
        select(Payment).where(
            Payment.customer_id == customer.id,
            Payment.status == PaymentStatus.pending,
            Payment.created_at > datetime.now(timezone.utc) - PROMPT_COOLDOWN,
        )
    )
    if recent is not None:
        return HTMLResponse(_pay_page(
            "Request already sent",
            f"Check {_masked(customer.phone_number)} for the M-Pesa request. If it didn't arrive, wait a minute and try again.",
            ok=True,
        ))
    try:
        services.request_mpesa_charge(db, customer)
    except PaystackError as exc:
        print(f"Pay link M-Pesa request for {customer.pppoe_username} failed: {exc}")
        return HTMLResponse(
            _pay_page("Couldn't send the request", "Please try again in a few minutes, or contact us.", ok=False),
            status_code=502,
        )
    return HTMLResponse(
        _pay_page(
            "Check your phone",
            f"An M-Pesa payment request has been sent to {_masked(customer.phone_number)}. Approve it to complete "
            "payment - your internet reconnects automatically within about a minute.",
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
    if payment.status != PaymentStatus.pending:
        # Paystack retries/duplicates the same event - already handled, and
        # confirming again would extend the subscription a second time.
        return {"status": "duplicate"}

    if result["event"] == "charge.success" and result["status"] == "success":
        # Queues the reconnect - the router applies it on its next sync (within a minute).
        gw = router_sync.gateway(db)
        payment = services.confirm_payment(
            db,
            gw.ppp,
            payment,
            mpesa_receipt=str(result["paystack_transaction_id"]),
            raw_callback=payload,
            static_mgr=gw.static,
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
