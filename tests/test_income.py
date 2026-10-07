from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from billing import services
from billing.db import Base, get_db
from billing.models import Customer, Payment, PaymentStatus, Plan, RouterCommand


@pytest.fixture
def session_factory():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@pytest.fixture
def db(session_factory):
    session = session_factory()
    yield session
    session.close()


@pytest.fixture
def customer(db):
    db.add(Plan(name="10mbps", rate_limit="10M/10M", price_kes=Decimal("1500"), duration_days=30))
    db.commit()
    c = Customer(pppoe_username="alice", full_name="Alice", phone_number="+254700000001", plan_id=1)
    db.add(c)
    db.commit()
    return c


@pytest.fixture
def client(session_factory, monkeypatch):
    from billing.config import settings
    from billing.main import app

    monkeypatch.setattr(settings, "admin_password", "pw")

    def override_db():
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_db
    client = TestClient(app)
    client.post("/login", data={"username": settings.admin_username, "password": "pw"})
    yield client
    app.dependency_overrides.clear()


def _pay(db, customer, amount, confirmed_at, status=PaymentStatus.confirmed):
    db.add(Payment(customer_id=customer.id, amount_kes=Decimal(amount), status=status,
                   phone_number="+254700000001", confirmed_at=confirmed_at))
    db.commit()


# --- monthly income -------------------------------------------------------------


def test_monthly_income_groups_by_kenya_month(db, customer):
    now = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
    _pay(db, customer, "1500", datetime(2026, 10, 2, 9, 0, tzinfo=timezone.utc))
    _pay(db, customer, "2000", datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc))
    # 30 Sep 22:30 UTC is already 1 Oct 01:30 in Kenya -> counts for October.
    _pay(db, customer, "500", datetime(2026, 9, 30, 22, 30, tzinfo=timezone.utc))
    _pay(db, customer, "1000", datetime(2026, 9, 10, 9, 0, tzinfo=timezone.utc))
    _pay(db, customer, "9999", datetime(2026, 10, 5, 9, 0, tzinfo=timezone.utc), status=PaymentStatus.failed)
    _pay(db, customer, "7777", datetime(2025, 10, 5, 9, 0, tzinfo=timezone.utc))  # older than 12 months

    months = services.monthly_income(db, now=now)
    assert len(months) == 12
    assert (months[0].label, months[-1].label) == ("Nov 2025", "Oct 2026")
    assert (months[-1].total_kes, months[-1].payments) == (Decimal("4000"), 3)
    assert (months[-2].total_kes, months[-2].payments) == (Decimal("1000"), 1)
    assert sum(m.total_kes for m in months) == Decimal("5000")


def test_year_boundary(db, customer):
    months = services.monthly_income(db, months=3, now=datetime(2026, 1, 20, tzinfo=timezone.utc))
    assert [m.label for m in months] == ["Nov 2025", "Dec 2025", "Jan 2026"]
    assert all(m.total_kes == 0 for m in months)


def test_dashboard_shows_income(client, db, customer):
    assert "No payments recorded in the last 12 months yet" in client.get("/dashboard").text
    _pay(db, customer, "1500", datetime.now(timezone.utc))
    page = client.get("/dashboard").text
    assert "Income per month" in page
    assert "KES 1,500" in page
    assert page.count('class="bar"') == 1  # only the month with income gets a bar
    assert "Show as table" in page


def test_nice_chart_axis():
    from billing.routers.dashboard import _income_chart

    months = [services.MonthIncome(2026, m, f"M{m}", Decimal(v), 1) for m, v in enumerate([0, 4300, 12000], 1)]
    chart = _income_chart(months)
    assert [t["value"] for t in chart["ticks"]] == [0, 5000, 10000, 15000]
    assert chart["bars"][0]["path"] == ""  # zero month: no mark


# --- creating a customer with a phone that's taken --------------------------------


def test_duplicate_phone_shows_message_not_500(client, db, customer):
    resp = client.post(
        "/dashboard/customers",
        data={"pppoe_username": "Pirate20", "pppoe_password": "pw", "full_name": "Colin",
              "phone_number": "0700000001", "plan_id": "1"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "already+belongs+to+alice" in resp.headers["location"]
    assert db.scalar(select(Customer).where(Customer.pppoe_username == "Pirate20")) is None
    assert db.scalars(select(RouterCommand)).all() == []  # nothing queued for the router


def test_database_conflict_is_caught(client, db, customer, monkeypatch):
    from sqlalchemy.exc import IntegrityError

    def boom(*args, **kwargs):
        raise IntegrityError("INSERT", {}, Exception("unique"))

    monkeypatch.setattr(services, "create_customer", boom)
    resp = client.post(
        "/dashboard/customers",
        data={"pppoe_username": "bob", "pppoe_password": "pw", "full_name": "Bob",
              "phone_number": "0711111111", "plan_id": "1"},
        follow_redirects=False,
    )
    assert resp.status_code == 303 and "already+in+use" in resp.headers["location"]
