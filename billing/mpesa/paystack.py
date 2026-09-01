"""Thin client for Paystack's Charge API, used for the Kenya M-Pesa mobile money channel."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

import httpx

from billing.config import settings

_BASE_URL = "https://api.paystack.co"


class PaystackError(RuntimeError):
    pass


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {settings.paystack_secret_key}"}


def initiate_mpesa_charge(*, email: str, phone_number: str, amount_kes: int, reference: str) -> dict[str, Any]:
    """
    Push an M-Pesa STK prompt to the customer's phone via Paystack.

    `reference` is ours, not Paystack's - generate a unique one per attempt
    and pass it through; the webhook echoes it back so we can match the
    result to this payment without waiting on a synchronous response.
    Paystack wants amount in the currency's subunit (cents), hence the *100.
    """
    payload = {
        "email": email,
        "amount": amount_kes * 100,
        "currency": "KES",
        "reference": reference,
        "mobile_money": {"phone": phone_number, "provider": "mpesa"},
    }
    response = httpx.post(f"{_BASE_URL}/charge", json=payload, headers=_headers(), timeout=15)
    try:
        data = response.json()
    except ValueError:
        response.raise_for_status()
        raise PaystackError(f"Unexpected non-JSON response ({response.status_code})") from None

    if not data.get("status"):
        raise PaystackError(data.get("message", f"Charge initiation failed ({response.status_code})"))
    return data["data"]


def initiate_paybill_charge(*, email: str, amount_kes: int, reference: str) -> dict[str, Any]:
    """
    Generate a one-time Paystack paybill code for a customer to pay manually.

    No push to any phone - the customer dials *334# (or uses the M-Pesa app)
    and pays into Paystack's shared paybill (`account_number`) using the
    one-time `account_reference` Paystack generates (not customizable -
    it ignores anything passed in `mobile_money.account`). `reference` is
    ours and is what the webhook echoes back, same as the STK push flow.
    """
    payload = {
        "email": email,
        "amount": amount_kes * 100,
        "currency": "KES",
        "reference": reference,
        "mobile_money": {"provider": "mpesa_offline"},
    }
    response = httpx.post(f"{_BASE_URL}/charge", json=payload, headers=_headers(), timeout=15)
    try:
        data = response.json()
    except ValueError:
        response.raise_for_status()
        raise PaystackError(f"Unexpected non-JSON response ({response.status_code})") from None

    if not data.get("status"):
        raise PaystackError(data.get("message", f"Charge initiation failed ({response.status_code})"))
    return data["data"]


def verify_signature(raw_body: bytes, signature: str) -> bool:
    """Confirm a webhook actually came from Paystack: HMAC-SHA512 over the raw body, hex-encoded."""
    expected = hmac.new(settings.paystack_secret_key.encode(), raw_body, hashlib.sha512).hexdigest()
    return hmac.compare_digest(expected, signature)


def parse_webhook_event(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize a Paystack webhook body into a flat dict."""
    data = payload.get("data", {})
    return {
        "event": payload.get("event"),
        "reference": data.get("reference"),
        "status": data.get("status"),  # "success", "failed", "abandoned", ...
        "amount_kes": (data.get("amount") or 0) / 100,
        # Paystack's own transaction id, not necessarily Safaricom's native
        # M-Pesa receipt number - that's not consistently exposed here.
        "paystack_transaction_id": data.get("id"),
        # The MSISDN that actually paid - confirmed present (as "2547...",
        # no '+') even for the mpesa_offline/paybill channel, not just STK
        # push. Used as a fallback match when the customer didn't use the
        # exact paybill account code we generated for them.
        "payer_phone": (data.get("authorization") or {}).get("mobile_money_number"),
    }
