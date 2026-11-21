"""Paystack API client for Platform Owner SaaS subscription billing."""
from __future__ import annotations

import hashlib
import hmac
from decimal import Decimal
from typing import Any

import httpx

from saas.config import saas_settings

_PAYSTACK_API_BASE = "https://api.paystack.co"


class PaystackPlatformError(RuntimeError):
    """Raised when Paystack API rejects an operation or returns an error."""
    pass


def _get_secret_key(override_key: str | None = None) -> str:
    key = override_key or saas_settings.platform_paystack_secret_key
    if not key:
        raise PaystackPlatformError("PLATFORM_PAYSTACK_SECRET_KEY is not configured.")
    return key


def _headers(secret_key: str | None = None) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {_get_secret_key(secret_key)}",
        "Content-Type": "application/json",
    }


def initialize_transaction(
    *,
    email: str,
    amount_kes: Decimal | int,
    reference: str,
    callback_url: str | None = None,
    metadata: dict[str, Any] | None = None,
    secret_key: str | None = None,
) -> dict[str, Any]:
    """
    Initializes a Paystack transaction for platform subscription onboarding.
    Amounts in Paystack KES are denominated in subunits (cents: KES * 100).
    """
    amount_subunits = int(Decimal(str(amount_kes)) * 100)
    cb_url = callback_url or saas_settings.platform_paystack_callback_url

    payload: dict[str, Any] = {
        "email": email,
        "amount": amount_subunits,
        "currency": "KES",
        "reference": reference,
        "callback_url": cb_url,
    }
    if metadata:
        payload["metadata"] = metadata

    try:
        response = httpx.post(
            f"{_PAYSTACK_API_BASE}/transaction/initialize",
            json=payload,
            headers=_headers(secret_key),
            timeout=20.0,
        )
    except httpx.RequestError as exc:
        raise PaystackPlatformError(f"Network error connecting to Paystack: {exc}") from exc

    try:
        data = response.json()
    except ValueError:
        response.raise_for_status()
        raise PaystackPlatformError(f"Invalid non-JSON response from Paystack ({response.status_code})") from None

    if not data.get("status"):
        raise PaystackPlatformError(data.get("message", f"Paystack initialization failed ({response.status_code})"))

    return data["data"]


def verify_transaction(reference: str, secret_key: str | None = None) -> dict[str, Any]:
    """
    Directly queries Paystack's server-side verification endpoint to confirm transaction status.
    GET https://api.paystack.co/transaction/verify/:reference
    """
    try:
        response = httpx.get(
            f"{_PAYSTACK_API_BASE}/transaction/verify/{reference}",
            headers=_headers(secret_key),
            timeout=20.0,
        )
    except httpx.RequestError as exc:
        raise PaystackPlatformError(f"Network error verifying Paystack transaction: {exc}") from exc

    try:
        data = response.json()
    except ValueError:
        response.raise_for_status()
        raise PaystackPlatformError(f"Invalid non-JSON response from Paystack verification ({response.status_code})") from None

    if not data.get("status"):
        raise PaystackPlatformError(data.get("message", f"Verification request failed ({response.status_code})"))

    return data["data"]


def verify_signature(
    raw_body: bytes,
    signature: str | None,
    secret_key: str | None = None,
) -> bool:
    """
    Safeguard 1: Validates incoming Paystack webhook HMAC-SHA512 signature against raw request bytes.
    Handles standard 'x-paystack-signature', legacy variants, whitespace trimming, and constant-time comparison.
    """
    if not signature or not signature.strip():
        return False

    try:
        key = _get_secret_key(secret_key)
    except PaystackPlatformError:
        return False

    clean_signature = signature.strip().lower()

    # Paystack standard is HMAC-SHA512 of the exact request body bytes
    expected = hmac.new(key.encode("utf-8"), raw_body, hashlib.sha512).hexdigest().lower()
    return hmac.compare_digest(expected, clean_signature)
