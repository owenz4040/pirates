from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from billing import router_sync, services
from billing.db import Base, get_db
from billing.models import ConnectionType, Customer, CustomerStatus, Plan, RouterCommand


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
    plan = Plan(name="10mbps", rate_limit="10M/10M", price_kes=Decimal("1500"), duration_days=30)
    db.add(plan)
    db.commit()
    customer = Customer(
        pppoe_username="alice", full_name="Alice", phone_number="254700000001", plan_id=plan.id,
        status=CustomerStatus.expired, expires_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    db.add(customer)
    db.commit()
    return customer


def _descriptions(db) -> list[str]:
    return [c.description for c in db.scalars(select(RouterCommand).order_by(RouterCommand.id))]


def test_future_expiry_reactivates_and_reconnects(db, customer):
    customer.reminder_1_day_sent = True
    gw = router_sync.gateway(db)
    services.set_expiry(db, gw.ppp, customer, datetime.now(timezone.utc) + timedelta(days=3), static_mgr=gw.static)
    assert customer.status == CustomerStatus.active
    assert customer.reminder_1_day_sent is False
    assert _descriptions(db) == ["Move alice to profile 10mbps", "Enable PPPoE user alice"]


def test_manually_suspended_customer_is_reconnected(db, customer):
    customer.status = CustomerStatus.suspended
    db.commit()
    gw = router_sync.gateway(db)
    services.set_expiry(db, gw.ppp, customer, None, static_mgr=gw.static)
    assert customer.status == CustomerStatus.active
    assert customer.expires_at is None
    assert "Enable PPPoE user alice" in _descriptions(db)


def test_moving_active_customer_forward_queues_nothing(db, customer):
    customer.status = CustomerStatus.active
    db.commit()
    gw = router_sync.gateway(db)
    services.set_expiry(db, gw.ppp, customer, datetime.now(timezone.utc) + timedelta(days=60), static_mgr=gw.static)
    assert _descriptions(db) == []


def test_past_expiry_disconnects_active_customer(db, customer):
    customer.status = CustomerStatus.active
    customer.connection_type = ConnectionType.static
    customer.static_ip = "10.0.0.5"
    db.commit()
    gw = router_sync.gateway(db)
    services.set_expiry(db, gw.ppp, customer, datetime.now(timezone.utc) - timedelta(hours=1), static_mgr=gw.static)
    assert customer.status == CustomerStatus.expired
    assert _descriptions(db) == ["Suspend static IP 10.0.0.5"]


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


def _expiry(db) -> datetime:
    db.expire_all()
    value = db.scalar(select(Customer)).expires_at
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def test_set_date_is_read_as_kenya_time(client, db, customer):
    resp = client.post(
        "/dashboard/customers/alice/expiry", data={"mode": "set", "expires_at": "2030-01-15T18:00"},
        follow_redirects=False,
    )
    assert resp.status_code == 303 and "EAT" in resp.headers["location"]
    assert _expiry(db) == datetime(2030, 1, 15, 15, 0, tzinfo=timezone.utc)

    page = client.get("/dashboard/customers/alice").text
    assert "15 Jan 2030, 18:00 EAT" in page
    assert 'value="2030-01-15T18:00"' in page


def test_add_days_counts_from_now_when_already_expired(client, db, customer):
    client.post("/dashboard/customers/alice/expiry", data={"mode": "add", "days": "7"})
    assert abs(_expiry(db) - (datetime.now(timezone.utc) + timedelta(days=7))) < timedelta(minutes=1)


def test_add_days_stacks_on_remaining_time(client, db, customer):
    future = datetime.now(timezone.utc) + timedelta(days=10)
    customer.expires_at, customer.status = future, CustomerStatus.active
    db.commit()
    client.post("/dashboard/customers/alice/expiry", data={"mode": "add", "days": "5"})
    assert abs(_expiry(db) - (future + timedelta(days=5))) < timedelta(seconds=1)


def test_invalid_date_is_rejected(client, db, customer):
    resp = client.post(
        "/dashboard/customers/alice/expiry", data={"mode": "set", "expires_at": "nope"}, follow_redirects=False
    )
    assert "flash_kind=error" in resp.headers["location"]
