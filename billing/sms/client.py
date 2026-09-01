"""Thin wrapper around Africa's Talking's SMS API for welcome/renewal texts."""

from __future__ import annotations

import africastalking

from billing.config import settings

_initialized = False


class SmsError(RuntimeError):
    pass


def _ensure_initialized() -> None:
    global _initialized
    if _initialized:
        return
    if not settings.africastalking_username or not settings.africastalking_api_key:
        raise SmsError("AFRICASTALKING_USERNAME / AFRICASTALKING_API_KEY are not configured")
    africastalking.initialize(settings.africastalking_username, settings.africastalking_api_key)
    _initialized = True


def send_sms(phone_number: str, message: str) -> None:
    """Send a single SMS. Raises SmsError on failure - callers decide whether that's fatal."""
    _ensure_initialized()
    if not phone_number.startswith("+"):
        phone_number = f"+{phone_number}"

    kwargs = {}
    if settings.africastalking_sender_id:
        kwargs["sender_id"] = settings.africastalking_sender_id

    response = africastalking.SMS.send(message, [phone_number], **kwargs)
    recipients = response.get("SMSMessageData", {}).get("Recipients", [])
    if not recipients:
        raise SmsError(f"No recipient result in Africa's Talking response: {response}")
    if recipients[0].get("status") != "Success":
        raise SmsError(f"Africa's Talking rejected the message: {recipients[0]}")
