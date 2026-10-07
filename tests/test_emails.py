from __future__ import annotations

import re
from datetime import datetime, timezone
from decimal import Decimal

import pytest

from billing import services
from billing.config import settings
from billing.email import client as email_client
from billing.models import Customer, Payment, Plan

PAYBILL = {"amount_kes": 1500, "paybill": "4000123", "account_number": "PW8812"}
# Phrases that make filters read an M-Pesa notice as phishing or marketing.
SPAMMY = re.compile(r"\bPIN\b|unlimited|ahoy|!|act now|urgent|click here|free", re.IGNORECASE)


@pytest.fixture
def customer(monkeypatch):
    monkeypatch.setattr(settings, "public_base_url", "https://pirates.colinowen.online")
    plan = Plan(id=1, name="isp-9m", rate_limit="9M/9M", marketing_speed="10mbps", price_kes=Decimal("1500"), duration_days=30)
    return Customer(
        id=1, pppoe_username="alice", full_name="Alice <Wanjiru>", phone_number="254712345678",
        pay_token="tok123", plan=plan, plan_id=1, expires_at=datetime(2030, 1, 15, 15, 0, tzinfo=timezone.utc),
    )


def _emails(customer):
    payment = Payment(id=9, amount_kes=Decimal("1500"), mpesa_receipt="QWE123", phone_number="254712345678")
    return {
        "welcome": services.compose_welcome_email(customer, PAYBILL),
        "receipt": services.compose_receipt_email(customer, payment),
        "reminder": services.compose_reminder_email(customer, PAYBILL, 2),
    }


def test_every_email_is_a_complete_document_with_text_part(customer):
    for name, (subject, html, text) in _emails(customer).items():
        assert html.startswith("<!doctype html>"), name
        assert '<html lang="en">' in html and f"<title>" in html, name
        assert text.strip(), name
        assert "service message about your account" in html and "service message about your account" in text, name


def test_no_spam_trigger_wording(customer):
    for name, (subject, html, text) in _emails(customer).items():
        visible = re.sub(r"<[^>]+>", " ", html)
        assert not SPAMMY.search(subject), (name, subject)
        assert not SPAMMY.search(visible), (name, SPAMMY.search(visible).group())
        assert not SPAMMY.search(text), (name, SPAMMY.search(text).group())


def test_links_only_point_to_our_domain(customer):
    for name, (_, html, text) in _emails(customer).items():
        for url in re.findall(r'href="([^"]+)"', html) + re.findall(r"https?://\S+", text):
            assert url.startswith("https://pirates.colinowen.online/"), (name, url)


def test_customer_values_are_escaped(customer):
    _, html, _ = _emails(customer)["welcome"]
    assert "Alice &lt;Wanjiru&gt;" in html and "<Wanjiru>" not in html


def test_dates_shown_in_kenya_time(customer):
    _, html, text = _emails(customer)["receipt"]
    assert "15 Jan 2030, 18:00 EAT" in html and "15 Jan 2030, 18:00 EAT" in text


def test_reply_to_is_sent_when_configured(monkeypatch):
    sent = {}
    monkeypatch.setattr(settings, "resend_api_key", "re_test")
    monkeypatch.setattr(settings, "email_reply_to", "support@example.com")
    monkeypatch.setattr(email_client.resend.Emails, "send", lambda payload: sent.update(payload) or {"id": "1"})
    email_client.send_email("a@example.com", "s", "<p>h</p>", "t")
    assert sent["reply_to"] == "support@example.com"
    assert sent["text"] == "t"
