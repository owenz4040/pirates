"""Thin wrapper around Resend's email API for the welcome/renewal message."""

from __future__ import annotations

import resend

from billing.config import settings

_initialized = False


class EmailError(RuntimeError):
    pass


def _ensure_initialized() -> None:
    global _initialized
    if _initialized:
        return
    if not settings.resend_api_key:
        raise EmailError("RESEND_API_KEY is not configured")
    resend.api_key = settings.resend_api_key
    _initialized = True


def send_email(to: str, subject: str, html: str, text: str | None = None) -> None:
    """
    Send a single email. Raises EmailError on failure - callers decide
    whether that's fatal.

    Always pass `text` when you have one: an HTML-only message (no plain-text
    part) is itself a spam signal most filters weigh heavily, on top of
    whatever content/reputation scoring already applies.

    Note: until a domain is verified in the Resend dashboard, Resend only
    delivers to the account's own registered email address, regardless of
    what `to` is set to here - everything else silently gets rejected.
    """
    _ensure_initialized()
    payload = {
        "from": settings.resend_from_address,
        "to": [to],
        "subject": subject,
        "html": html,
    }
    if text:
        payload["text"] = text
    try:
        response = resend.Emails.send(payload)
    except Exception as exc:  # noqa: BLE001 - Resend's SDK exception types aren't documented; normalize all of them
        raise EmailError(str(exc)) from exc

    if not isinstance(response, dict) or not response.get("id"):
        raise EmailError(f"Unexpected Resend response: {response}")
