"""Safaricom M-Pesa Daraja STK Push (M-Pesa Express) service for tenant ISP billing."""
from __future__ import annotations

import base64
import logging
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

import httpx

logger = logging.getLogger("saas.daraja")

_DARAJA_LIVE_BASE = "https://api.safaricom.co.ke"
_DARAJA_SANDBOX_BASE = "https://sandbox.safaricom.co.ke"


class DarajaError(RuntimeError):
    """Raised when Daraja API rejects an operation or returns an error."""
    pass


class DarajaAuthError(DarajaError):
    """Raised when Daraja credentials fail authentication."""
    pass


def _get_daraja_base_url(is_sandbox: bool = False) -> str:
    return _DARAJA_SANDBOX_BASE if is_sandbox else _DARAJA_LIVE_BASE


def format_phone_number(phone: str) -> str:
    """Normalize phone number to 2547XXXXXXXX or 2541XXXXXXXX format."""
    clean = phone.strip().replace(" ", "").replace("-", "").replace("+", "")
    if clean.startswith("0") and len(clean) == 10:
        return "254" + clean[1:]
    if clean.startswith("7") and len(clean) == 9:
        return "254" + clean
    if clean.startswith("1") and len(clean) == 9:
        return "254" + clean
    if clean.startswith("254") and len(clean) == 12:
        return clean
    return clean


def get_oauth_token(
    consumer_key: str,
    consumer_secret: str,
    is_sandbox: bool = False,
) -> str:
    """Generate OAuth bearer access token from Safaricom Daraja."""
    if not consumer_key or not consumer_secret:
        raise DarajaAuthError("M-Pesa consumer key or consumer secret is missing.")

    base_url = _get_daraja_base_url(is_sandbox)
    url = f"{base_url}/oauth/v1/generate?grant_type=client_credentials"

    try:
        response = httpx.get(
            url,
            auth=(consumer_key.strip(), consumer_secret.strip()),
            headers={"Accept": "application/json"},
            timeout=15.0,
        )
    except httpx.RequestError as exc:
        raise DarajaError(f"Network error connecting to M-Pesa Daraja: {exc}") from exc

    if response.status_code == 401 or response.status_code == 400:
        raise DarajaAuthError(f"Daraja authentication failed ({response.status_code}): {response.text}")

    try:
        data = response.json()
    except ValueError:
        response.raise_for_status()
        raise DarajaError(f"Invalid non-JSON response from Daraja OAuth ({response.status_code})") from None

    token = data.get("access_token")
    if not token:
        raise DarajaAuthError(f"Daraja OAuth response missing access_token: {data}")

    return str(token)


def generate_stk_password(shortcode: str, passkey: str, timestamp_str: str) -> str:
    """Computes base64(Shortcode + Passkey + Timestamp)."""
    raw = f"{shortcode.strip()}{passkey.strip()}{timestamp_str.strip()}"
    return base64.b64encode(raw.encode("utf-8")).decode("utf-8")


def initiate_stk_push(
    *,
    consumer_key: str,
    consumer_secret: str,
    passkey: str,
    shortcode: str,
    phone_number: str,
    amount_kes: int | Decimal,
    callback_url: str,
    account_reference: str = "COwen Hotspot",
    transaction_desc: str = "Hotspot Internet Access",
    is_till: bool = False,
    is_sandbox: bool = False,
) -> dict[str, Any]:
    """Initiates an STK Push (M-Pesa Express) request to customer's mobile phone."""
    token = get_oauth_token(consumer_key, consumer_secret, is_sandbox)
    base_url = _get_daraja_base_url(is_sandbox)
    url = f"{base_url}/mpesa/stkpush/v1/processrequest"

    now = datetime.now(timezone.utc)
    timestamp_str = now.strftime("%Y%m%d%H%M%S")
    password = generate_stk_password(shortcode, passkey, timestamp_str)
    formatted_phone = format_phone_number(phone_number)
    amount_int = int(Decimal(str(amount_kes)))

    # Paybill uses CustomerPayBillOnline; Till uses CustomerBuyGoodsOnline
    transaction_type = "CustomerBuyGoodsOnline" if is_till else "CustomerPayBillOnline"

    payload: dict[str, Any] = {
        "BusinessShortCode": shortcode.strip(),
        "Password": password,
        "Timestamp": timestamp_str,
        "TransactionType": transaction_type,
        "Amount": amount_int,
        "PartyA": formatted_phone,
        "PartyB": shortcode.strip(),
        "PhoneNumber": formatted_phone,
        "CallBackURL": callback_url.strip(),
        "AccountReference": account_reference[:12].strip(),
        "TransactionDesc": transaction_desc[:12].strip(),
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    try:
        response = httpx.post(url, json=payload, headers=headers, timeout=20.0)
    except httpx.RequestError as exc:
        raise DarajaError(f"Network error initiating M-Pesa STK Push: {exc}") from exc

    try:
        data = response.json()
    except ValueError:
        response.raise_for_status()
        raise DarajaError(f"Invalid non-JSON response from Daraja STK Push ({response.status_code})") from None

    response_code = str(data.get("ResponseCode", ""))
    if response_code != "0":
        error_msg = data.get("ResponseDescription") or data.get("errorMessage") or f"STK push failed ({response_code})"
        raise DarajaError(error_msg)

    return {
        "merchant_request_id": data.get("MerchantRequestID"),
        "checkout_request_id": data.get("CheckoutRequestID"),
        "response_code": response_code,
        "response_description": data.get("ResponseDescription"),
        "customer_message": data.get("CustomerMessage"),
    }


def parse_stk_callback(callback_data: dict[str, Any]) -> dict[str, Any]:
    """Parses and validates Daraja STK callback payload.

    Extracts ResultCode, ResultDesc, MpesaReceiptNumber, Amount, and PhoneNumber.
    """
    body = callback_data.get("Body", {})
    stk_cb = body.get("stkCallback", {})

    result_code = stk_cb.get("ResultCode")
    result_desc = stk_cb.get("ResultDesc", "")
    merchant_request_id = stk_cb.get("MerchantRequestID")
    checkout_request_id = stk_cb.get("CheckoutRequestID")

    is_success = (result_code == 0)

    extracted: dict[str, Any] = {
        "is_success": is_success,
        "result_code": result_code,
        "result_desc": result_desc,
        "merchant_request_id": merchant_request_id,
        "checkout_request_id": checkout_request_id,
        "receipt_number": None,
        "amount": None,
        "phone_number": None,
        "transaction_date": None,
    }

    if is_success:
        meta_items = stk_cb.get("CallbackMetadata", {}).get("Item", [])
        for item in meta_items:
            name = item.get("Name")
            val = item.get("Value")
            if name == "MpesaReceiptNumber":
                extracted["receipt_number"] = str(val)
            elif name == "Amount":
                extracted["amount"] = Decimal(str(val))
            elif name == "PhoneNumber":
                extracted["phone_number"] = str(val)
            elif name == "TransactionDate":
                extracted["transaction_date"] = str(val)

    return extracted


def query_stk_status(
    *,
    consumer_key: str,
    consumer_secret: str,
    passkey: str,
    shortcode: str,
    checkout_request_id: str,
    is_sandbox: bool = False,
) -> dict[str, Any]:
    """Queries Daraja STK Push transaction status via /mpesa/stkpushquery/v1/query.

    Used for out-of-band verification when callbacks are delayed or ambiguous.
    """
    token = get_oauth_token(consumer_key, consumer_secret, is_sandbox)
    base_url = _get_daraja_base_url(is_sandbox)
    url = f"{base_url}/mpesa/stkpushquery/v1/query"

    now = datetime.now(timezone.utc)
    timestamp_str = now.strftime("%Y%m%d%H%M%S")
    password = generate_stk_password(shortcode, passkey, timestamp_str)

    payload = {
        "BusinessShortCode": shortcode.strip(),
        "Password": password,
        "Timestamp": timestamp_str,
        "CheckoutRequestID": checkout_request_id.strip(),
    }
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    try:
        response = httpx.post(url, json=payload, headers=headers, timeout=15.0)
    except httpx.RequestError as exc:
        raise DarajaError(f"Network error querying STK status: {exc}") from exc

    try:
        data = response.json()
    except ValueError:
        response.raise_for_status()
        raise DarajaError(f"Invalid non-JSON response from STK status query ({response.status_code})") from None

    result_code = data.get("ResultCode")
    return {
        "response_code": data.get("ResponseCode"),
        "response_description": data.get("ResponseDescription"),
        "merchant_request_id": data.get("MerchantRequestID"),
        "checkout_request_id": data.get("CheckoutRequestID"),
        "result_code": int(result_code) if result_code is not None else None,
        "result_desc": data.get("ResultDesc"),
        "is_successful": (result_code == "0" or result_code == 0),
    }
