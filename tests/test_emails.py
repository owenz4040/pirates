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


# --- emails must not depend on Paystack ------------------------------------------


@pytest.fixture
def client_and_db(monkeypatch):
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from billing.db import Base, get_db
    from billing.main import app
    from billing.mpesa import paystack

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db():
        s = factory()
        try:
            yield s
        finally:
            s.close()

    def bad_key(**kwargs):
        raise paystack.PaystackError("Invalid key")

    sent = []
    monkeypatch.setattr(settings, "admin_password", "pw")
    monkeypatch.setattr(paystack, "initiate_paybill_charge", bad_key)
    monkeypatch.setattr(email_client, "send_email", lambda to, subject, html, text=None: sent.append((to, subject, text)))
    app.dependency_overrides[get_db] = override_db
    client = TestClient(app)
    client.post("/login", data={"username": settings.admin_username, "password": "pw"})
    db = factory()
    db.add(Plan(name="10mbps", rate_limit="10M/10M", price_kes=Decimal("1500"), duration_days=30))
    db.commit()
    yield client, db, sent
    db.close()
    app.dependency_overrides.clear()


def test_welcome_email_sent_even_when_paystack_rejects_key(client_and_db):
    client, db, sent = client_and_db
    resp = client.post(
        "/dashboard/customers",
        data={"pppoe_username": "bob", "pppoe_password": "pw", "full_name": "Bob", "phone_number": "0711111111",
              "email": "bob@example.com", "plan_id": "1"},
        follow_redirects=False,
    )
    assert "sent+welcome+email+without+a+paybill+code" in resp.headers["location"]
    assert len(sent) == 1 and sent[0][0] == "bob@example.com"
    assert "Amount: KES 1500" in sent[0][2] and "Paybill" not in sent[0][2]

    resp = client.post("/dashboard/customers/bob/welcome", follow_redirects=False)
    assert "Sent+to+bob%40example.com" in resp.headers["location"] and len(sent) == 2


def test_reminders_still_sent_when_paystack_fails(client_and_db):
    from datetime import timedelta

    from billing.models import CustomerStatus

    _, db, sent = client_and_db
    db.add(Customer(pppoe_username="carol", full_name="Carol", phone_number="+254722222222", email="c@example.com",
                    plan_id=1, status=CustomerStatus.active,
                    expires_at=datetime.now(timezone.utc) + timedelta(hours=36)))
    db.commit()
    assert services.send_expiry_reminders(db) == (1, 0)
    assert len(sent) == 1 and "ends in 2 days" in sent[0][1]
