from __future__ import annotations

from decimal import Decimal

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from billing.config import settings
from billing.db import Base, get_db
from billing.models import Customer, Payment, Plan


@pytest.fixture
def env(monkeypatch):
    from billing.main import app

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db():
        s = factory()
        try:
            yield s
        finally:
            s.close()

    monkeypatch.setattr(settings, "admin_password", "correct-horse")
    app.dependency_overrides[get_db] = override_db
    db = factory()
    db.add(Plan(name="10mbps", rate_limit="10M/10M", price_kes=Decimal("1500"), duration_days=30))
    db.add(Customer(pppoe_username="alice", full_name="Alice", phone_number="+254712345678", plan_id=1, pay_token="tok"))
    db.commit()
    yield TestClient(app), db
    db.close()
    app.dependency_overrides.clear()


def _login(client, password, ip="1.2.3.4"):
    return client.post(
        "/login", data={"username": settings.admin_username, "password": password},
        headers={"X-Forwarded-For": ip}, follow_redirects=False,
    )


# --- login -------------------------------------------------------------------------


def test_lockout_after_five_failures_even_with_right_password(env):
    client, _ = env
    for _ in range(5):
        assert "error=1" in _login(client, "wrong").headers["location"]
    locked = _login(client, "correct-horse")
    assert "error=locked" in locked.headers["location"]
    assert client.get("/dashboard", follow_redirects=False).headers["location"].startswith("/login")
    assert "Too many failed attempts" in client.get(locked.headers["location"]).text


def test_lockout_is_per_ip(env):
    client, _ = env
    for _ in range(5):
        _login(client, "wrong", ip="6.6.6.6")
    assert _login(client, "correct-horse", ip="1.2.3.4").headers["location"] == "/dashboard"


def test_success_clears_failures(env):
    client, _ = env
    for _ in range(4):
        _login(client, "wrong")
    assert _login(client, "correct-horse").headers["location"] == "/dashboard"
    client.post("/logout")
    for _ in range(4):
        _login(client, "wrong")
    assert _login(client, "correct-horse").headers["location"] == "/dashboard"  # counter was reset


def test_login_never_redirects_off_site(env):
    client, _ = env
    resp = client.post(
        "/login", data={"username": settings.admin_username, "password": "correct-horse", "next": "//evil.example"},
        follow_redirects=False,
    )
    assert resp.headers["location"] == "/dashboard"


# --- app-wide protections -------------------------------------------------------------


def test_api_docs_are_not_public(env):
    client, _ = env
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_security_headers(env):
    client, _ = env
    headers = client.get("/login").headers
    assert headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["cache-control"] == "no-store"


def test_cross_site_form_post_is_blocked(env):
    client, db = env
    _login(client, "correct-horse")
    blocked = client.post("/dashboard/customers/alice/suspend", headers={"Origin": "https://evil.example"})
    assert blocked.status_code == 403
    allowed = client.post(
        "/dashboard/customers/alice/suspend", headers={"Origin": "http://testserver"}, follow_redirects=False
    )
    assert allowed.status_code == 303


def test_machine_endpoints_are_not_origin_checked(env):
    client, _ = env
    # Still rejected - but by their own token/signature check, not the browser guard.
    assert client.post("/api/router/sync", headers={"Origin": "https://x.example"}).status_code == 401
    assert client.post("/paystack/webhook", headers={"Origin": "https://x.example"}, content=b"{}").status_code == 401


# --- public pay link -------------------------------------------------------------------


def test_opening_pay_link_sends_nothing(env, monkeypatch):
    from billing.mpesa import paystack

    calls = []
    monkeypatch.setattr(paystack, "initiate_mpesa_charge", lambda **kw: calls.append(kw) or {})
    client, db = env
    page = client.get("/pay/alice/tok/mpesa")
    assert page.status_code == 200 and "Send M-Pesa request" in page.text
    assert "+2547•••••678" in page.text and "+254712345678" not in page.text
    assert calls == []

    assert "Check your phone" in client.post("/pay/alice/tok/mpesa").text
    assert "Request already sent" in client.post("/pay/alice/tok/mpesa").text  # cooldown
    assert len(calls) == 1
    assert len(db.scalars(select(Payment)).all()) == 1


def test_pay_link_hides_provider_errors(env, monkeypatch):
    from billing.mpesa import paystack

    def fail(**kw):
        raise paystack.PaystackError("Invalid key <script>")

    monkeypatch.setattr(paystack, "initiate_mpesa_charge", fail)
    client, _ = env
    resp = client.post("/pay/alice/tok/mpesa")
    assert resp.status_code == 502
    assert "Invalid key" not in resp.text and "<script>" not in resp.text


def test_bad_pay_token(env):
    client, _ = env
    assert client.get("/pay/alice/wrong/mpesa").status_code == 404
    assert client.post("/pay/alice/wrong/mpesa").status_code == 404
