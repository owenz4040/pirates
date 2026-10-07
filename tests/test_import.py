from __future__ import annotations

from decimal import Decimal

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from billing import router_sync
from billing.db import Base, get_db
from billing.models import Customer, CustomerStatus, Plan, RouterCommand


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


def _report(client, token: str, *chunks: str) -> None:
    for chunk in chunks:
        assert client.post("/api/router/secrets", headers={"X-Pirates-Token": token}, content=chunk).status_code == 200


ROUTER_EXPORT = (
    "part=0\n"
    "P\tdefault\t\n"
    "P\tisp-9m\t9M/9M\n"
    "P\tisp-4m\t4M/4M\n"
    "S\tjohn\tisp-9m\tfalse\tpppoe\tJohn Kamau\n"
    "S\tmary\tisp-4m\ttrue\tpppoe\t\n",
    "part=1\nend\n"
    "S\tvpn-office\tdefault\tfalse\tl2tp\t\n"
    "S\talready\tisp-9m\tfalse\tpppoe\t\n",
)


def test_export_script_sends_chunks_and_never_passwords():
    script = router_sync.export_script("https://billing.example/", "tok")
    assert 'url="https://billing.example/api/router/secrets"' in script
    assert f"$n >= {router_sync.EXPORT_CHUNK}" in script
    assert "password" not in script
    assert script.count("{") == script.count("}")


def test_chunks_are_assembled_and_finish_on_end(db):
    device = router_sync.get_or_create_device(db)
    router_sync.ingest_secrets(db, device, ROUTER_EXPORT[0])
    assert device.secrets_reported_at is None  # not finished yet
    router_sync.ingest_secrets(db, device, ROUTER_EXPORT[1])
    assert [s["name"] for s in device.router_secrets] == ["john", "mary", "vpn-office", "already"]
    assert device.router_secrets[1]["disabled"] is True
    assert device.router_secrets[0]["comment"] == "John Kamau"
    assert device.secrets_reported_at is not None
    # A new export (part 0) replaces the old snapshot rather than appending.
    router_sync.ingest_secrets(db, device, "part=0\nend\nS\tsolo\tisp-9m\tfalse\tpppoe\t\n")
    assert [s["name"] for s in device.router_secrets] == ["solo"]


def test_request_queues_export_command(client, db):
    client.post("/dashboard/router/import/request")
    cmd = db.scalar(select(RouterCommand))
    assert cmd.description == "Send PPPoE users to billing for import"
    assert "Waiting for the router" in client.get("/dashboard/router/import").text


def test_full_import_flow(client, db):
    db.add(Plan(name="isp-9m", rate_limit="9M/9M", price_kes=Decimal("2000"), duration_days=30))
    db.add(Customer(pppoe_username="already", full_name="A", phone_number="+254700000099", plan_id=1))
    db.commit()
    device = router_sync.get_or_create_device(db)
    _report(client, device.token, *ROUTER_EXPORT)

    page = client.get("/dashboard/router/import").text
    assert "john" in page and "mary" in page
    assert "vpn-office" not in page  # l2tp, not PPPoE
    assert "1 already imported" in page
    assert "<strong>isp-4m</strong> (4M/4M)" in page  # no plan for this profile yet

    client.post("/dashboard/router/import/plans")
    plan_4m = db.scalar(select(Plan).where(Plan.name == "isp-4m"))
    assert plan_4m.rate_limit == "4M/4M" and plan_4m.price_kes == 0

    form = {
        "pick": ["john", "mary"],
        "name::john": "John Kamau", "phone::john": "0712345678", "plan::john": "1", "expires::john": "2030-01-15T18:00",
        "name::mary": "Mary", "phone::mary": "0700000099", "plan::mary": str(plan_4m.id),
    }
    # Mary's phone belongs to an existing customer: nothing is imported, the row is flagged.
    resp = client.post("/dashboard/router/import", data=form)
    assert resp.status_code == 400 and "already used by another customer" in resp.text
    assert 'value="John Kamau"' in resp.text  # typed values survive the error
    assert db.scalar(select(Customer).where(Customer.pppoe_username == "john")) is None

    form["phone::mary"] = ""
    resp = client.post("/dashboard/router/import", data=form, follow_redirects=False)
    assert "Imported+2+customers" in resp.headers["location"]

    db.expire_all()
    john = db.scalar(select(Customer).where(Customer.pppoe_username == "john"))
    mary = db.scalar(select(Customer).where(Customer.pppoe_username == "mary"))
    assert john.status == CustomerStatus.active and john.phone_number == "+254712345678"
    assert john.expires_at.strftime("%Y-%m-%d %H:%M") == "2030-01-15 15:00"  # 18:00 EAT
    assert mary.status == CustomerStatus.expired and mary.phone_number is None  # disabled on the router
    # Importing never touches the router - only the earlier export request would be queued.
    assert db.scalars(select(RouterCommand)).all() == []
    assert "Every PPPoE user on the router is already in billing" in client.get("/dashboard/router/import").text


def test_customer_without_phone_gets_clear_mpesa_error(client, db):
    db.add(Plan(name="p", rate_limit="1M/1M", price_kes=Decimal("100"), duration_days=30))
    db.add(Customer(pppoe_username="nophone", full_name="N", phone_number=None, plan_id=1))
    db.commit()
    assert client.get("/dashboard/customers/nophone").status_code == 200
    resp = client.post("/dashboard/customers/nophone/mpesa/charge", follow_redirects=False)
    assert "Add+a+phone+number+first" in resp.headers["location"]
