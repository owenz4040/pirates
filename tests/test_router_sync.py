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
from billing.models import ConnectionType, Customer, CustomerStatus, Plan, RouterCommand, RouterCommandStatus
from mikrotik.script import ScriptPPPoEManager, ScriptStaticUserManager, quote


class ListSink:
    def __init__(self) -> None:
        self.items: list[tuple[str, str]] = []

    def add(self, description: str, script: str) -> None:
        self.items.append((description, script))


@pytest.fixture
def session_factory():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@pytest.fixture
def db(session_factory):
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def plan(db):
    plan = Plan(name="10mbps", rate_limit="10M/10M", price_kes=Decimal("1500"), duration_days=30)
    db.add(plan)
    db.commit()
    return plan


def _commands(db) -> list[RouterCommand]:
    return list(db.scalars(select(RouterCommand).order_by(RouterCommand.id)))


# --- script generation -------------------------------------------------------


def test_quote_escapes_routeros_specials():
    assert quote('a"b') == '"a\\"b"'
    assert quote("cost $5") == '"cost \\$5"'
    assert quote("back\\slash") == '"back\\\\slash"'
    assert quote("line\nbreak") == '"line break"'


def test_disable_user_disables_secret_and_kicks_session():
    sink = ListSink()
    ScriptPPPoEManager(sink).disable_user("alice")
    _, script = sink.items[0]
    assert '/ppp secret set [find where name="alice"] disabled=yes' in script
    assert '/ppp active remove [find where name="alice"]' in script


def test_create_secret_is_upsert():
    sink = ListSink()
    ScriptPPPoEManager(sink).create_secret("alice", "pw", profile="10mbps", comment="Alice")
    _, script = sink.items[0]
    assert script.startswith(':if ([:len [/ppp secret find where name="alice"]] = 0)')
    assert 'add name="alice" service=pppoe password="pw" profile="10mbps" comment="Alice"' in script
    assert 'else={/ppp secret set [find where name="alice"] password="pw" profile="10mbps"' in script


def test_static_suspend_is_idempotent_and_strips_host_mask():
    sink = ListSink()
    ScriptStaticUserManager(sink).suspend_user("10.0.0.5/32", comment="Bob")
    _, script = sink.items[0]
    assert 'address="10.0.0.5"' in script
    assert script.startswith(":if ([:len [/ip firewall address-list find where")


# --- services queue commands in the same transaction -------------------------


def test_create_customer_queues_secret_and_disable(db, plan):
    gw = router_sync.gateway(db)
    services.create_customer(
        db, gw.ppp, pppoe_username="alice", pppoe_password="pw", full_name="Alice",
        phone_number="254700000001", plan=plan, static_mgr=gw.static,
    )
    assert [c.description for c in _commands(db)] == ["Create PPPoE account alice", "Disable PPPoE user alice"]


def test_failed_customer_insert_leaves_no_orphan_commands(db, plan):
    db.add(Customer(pppoe_username="taken", full_name="X", phone_number="254700000009", plan_id=plan.id))
    db.commit()
    gw = router_sync.gateway(db)
    with pytest.raises(Exception):
        services.create_customer(
            db, gw.ppp, pppoe_username="other", pppoe_password="pw", full_name="Y",
            phone_number="254700000009", plan=plan, static_mgr=gw.static,  # duplicate phone
        )
    db.rollback()
    assert _commands(db) == []


def test_record_payment_queues_reconnect(db, plan):
    customer = Customer(
        pppoe_username="alice", full_name="Alice", phone_number="254700000001",
        plan_id=plan.id, status=CustomerStatus.expired,
    )
    db.add(customer)
    db.commit()
    gw = router_sync.gateway(db)
    services.record_payment(
        db, gw.ppp, customer=customer, amount_kes=Decimal("1500"), mpesa_receipt=None,
        phone_number=None, static_mgr=gw.static,
    )
    db.expire_all()  # prove the commands were committed, not just pending in the session
    assert [c.description for c in _commands(db)] == ["Move alice to profile 10mbps", "Enable PPPoE user alice"]


def test_resync_covers_plans_and_customers(db, plan):
    db.add_all([
        Customer(pppoe_username="a", full_name="A", phone_number="1", plan_id=plan.id, status=CustomerStatus.active),
        Customer(
            pppoe_username="s", full_name="S", phone_number="2", plan_id=plan.id, status=CustomerStatus.expired,
            connection_type=ConnectionType.static, static_ip="10.0.0.9",
        ),
    ])
    db.commit()
    assert router_sync.enqueue_full_resync(db) == 5  # profile + (profile, enable) + (queue, suspend)


# --- batching and acknowledgement ---------------------------------------------


def _queue(db, n: int) -> None:
    for i in range(n):
        db.add(RouterCommand(description=f"cmd {i}", script=f":log info {i}"))
    db.commit()


def test_batch_waits_for_ack_before_sending_more(db):
    device = router_sync.get_or_create_device(db)
    _queue(db, 3)
    first = router_sync.next_batch(db, device)
    assert [c.description for c in first] == ["cmd 0", "cmd 1", "cmd 2"]
    _queue(db, 1)
    assert router_sync.next_batch(db, device) == []  # previous batch still in flight

    router_sync.acknowledge(db, ok=f"{first[0].id},{first[1].id},", failed=f"{first[2].id},")
    statuses = [c.status for c in _commands(db)]
    assert statuses == [RouterCommandStatus.done, RouterCommandStatus.done, RouterCommandStatus.failed, RouterCommandStatus.pending]
    # Acked, so the command queued after the first batch goes out next.
    assert [c.id for c in router_sync.next_batch(db, device)] == [_commands(db)[3].id]


def test_unacknowledged_batch_is_resent_then_abandoned(db):
    device = router_sync.get_or_create_device(db)
    _queue(db, 1)
    for attempt in range(1, router_sync.MAX_ATTEMPTS + 1):
        batch = router_sync.next_batch(db, device)
        assert len(batch) == 1 and batch[0].attempts == attempt
        batch[0].sent_at = datetime.now(timezone.utc) - router_sync.ACK_TIMEOUT - timedelta(seconds=1)
        db.commit()
    assert router_sync.next_batch(db, device) == []
    assert _commands(db)[0].status == RouterCommandStatus.failed


def test_batch_respects_routeros6_size_cap(db):
    device = router_sync.get_or_create_device(db)
    for i in range(10):
        db.add(RouterCommand(description=str(i), script=":log info " + "x" * 600))
    db.commit()
    batch = router_sync.next_batch(db, device)
    assert 1 < len(batch) < 10
    assert len(router_sync.render_batch(batch, "https://x/api/router/ack", device.token)) < 4096


def test_render_batch_wraps_each_command_and_acks():
    cmd = RouterCommand(id=7, description="d", script="/ppp secret set [find where name=\"a\"] disabled=no")
    script = router_sync.render_batch([cmd], "https://pirates.example/api/router/ack", "tok")
    assert ':do {/ppp secret set [find where name="a"] disabled=no; :set ok ($ok . "7,")}' in script
    assert 'url="https://pirates.example/api/router/ack"' in script
    assert 'http-header-field="X-Pirates-Token: tok"' in script


# --- HTTP endpoints -------------------------------------------------------------


@pytest.fixture
def client(session_factory):
    from billing.main import app

    def override_db():
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_db
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_sync_endpoint_round_trip(client, db, plan):
    device = router_sync.get_or_create_device(db)
    gw = router_sync.gateway(db)
    gw.ppp.enable_user("alice")
    db.commit()

    assert client.post("/api/router/sync", headers={"X-Pirates-Token": "wrong"}).status_code == 401

    resp = client.post(
        "/api/router/sync",
        headers={"X-Pirates-Token": device.token},
        content="version=7.15 (stable)&board=hAP lite&uptime=1d02:03:04&cpu=4&active=alice,bob,",
    )
    assert resp.status_code == 200
    assert 'disabled=no; :set ok ($ok . "1,")' in resp.text

    db.expire_all()
    device = router_sync.get_or_create_device(db)
    assert device.version == "7.15 (stable)"
    assert device.active_usernames == ["alice", "bob"]
    assert router_sync.active_usernames(db) == {"alice", "bob"}

    ack = client.post("/api/router/ack", headers={"X-Pirates-Token": device.token}, content="ok=1,&failed=")
    assert ack.json() == {"done": 1, "failed": 0}

    # Nothing left: the router gets an empty body and stops looping.
    resp = client.post("/api/router/sync", headers={"X-Pirates-Token": device.token}, content="active=")
    assert resp.text == ""


def test_sync_runs_expiry_sweep(client, db, plan):
    device = router_sync.get_or_create_device(db)
    db.add(Customer(
        pppoe_username="late", full_name="Late", phone_number="254700000002", plan_id=plan.id,
        status=CustomerStatus.active, expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
    ))
    db.commit()
    resp = client.post("/api/router/sync", headers={"X-Pirates-Token": device.token}, content="")
    assert '/ppp secret set [find where name="late"] disabled=yes' in resp.text
    db.expire_all()
    assert db.scalar(select(Customer).where(Customer.pppoe_username == "late")).status == CustomerStatus.expired


def test_cron_requires_secret(client, monkeypatch):
    from billing.config import settings

    monkeypatch.setattr(settings, "cron_secret", "s3cret")
    assert client.get("/api/cron/daily").status_code == 401
    assert client.get("/api/cron/daily", headers={"Authorization": "Bearer nope"}).status_code == 401
    resp = client.get("/api/cron/daily", headers={"Authorization": "Bearer s3cret"})
    assert resp.status_code == 200
    assert resp.json()["expired"] == []
