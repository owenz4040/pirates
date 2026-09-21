from __future__ import annotations

from decimal import Decimal
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from billing.db import Base
from billing.models import ConnectionType, Customer, CustomerStatus, Plan
from billing import services
from mikrotik.static_user import StaticUserManager
from tests.fake_router import FakeApi


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def sample_plan(db_session):
    plan = Plan(name="4mbps", rate_limit="4M/4M", price_kes=Decimal("1500.00"), duration_days=30)
    db_session.add(plan)
    db_session.commit()
    db_session.refresh(plan)
    return plan


def test_create_static_customer_sets_up_queue_and_suspends(db_session, sample_plan):
    api = FakeApi()
    static_mgr = StaticUserManager(api)

    customer = services.create_customer(
        db_session,
        ppp=None,
        pppoe_username="static-alice",
        full_name="Alice Smith",
        phone_number="+254712345678",
        plan=sample_plan,
        connection_type=ConnectionType.static,
        static_ip="192.168.88.50",
        no_expiry=False,
        static_mgr=static_mgr,
    )

    assert customer.status == CustomerStatus.expired
    assert customer.connection_type == ConnectionType.static
    assert customer.static_ip == "192.168.88.50"

    # Verify queue was created
    queue = static_mgr.get_queue("static-alice")
    assert queue is not None
    assert queue.max_limit == "4M/4M"

    # Verify suspended on router
    assert static_mgr.is_suspended("192.168.88.50") is True


def test_record_payment_static_customer_restores_and_updates_queue(db_session, sample_plan):
    api = FakeApi()
    static_mgr = StaticUserManager(api)

    customer = services.create_customer(
        db_session,
        ppp=None,
        pppoe_username="static-alice",
        full_name="Alice Smith",
        phone_number="+254712345678",
        plan=sample_plan,
        connection_type=ConnectionType.static,
        static_ip="192.168.88.50",
        no_expiry=False,
        static_mgr=static_mgr,
    )
    assert static_mgr.is_suspended("192.168.88.50") is True

    # Record payment
    payment = services.record_payment(
        db_session,
        ppp=None,
        customer=customer,
        amount_kes=Decimal("1500.00"),
        mpesa_receipt="RC123456",
        phone_number="+254712345678",
        static_mgr=static_mgr,
    )

    assert customer.status == CustomerStatus.active
    assert customer.expires_at is not None
    assert static_mgr.is_suspended("192.168.88.50") is False


def test_expire_overdue_static_customers(db_session, sample_plan):
    api = FakeApi()
    static_mgr = StaticUserManager(api)

    customer = services.create_customer(
        db_session,
        ppp=None,
        pppoe_username="static-bob",
        full_name="Bob Jones",
        phone_number="+254712345679",
        plan=sample_plan,
        connection_type=ConnectionType.static,
        static_ip="192.168.88.51",
        no_expiry=True,
        static_mgr=static_mgr,
    )
    assert customer.status == CustomerStatus.active
    assert static_mgr.is_suspended("192.168.88.51") is False

    # Simulate expiry in the past
    from datetime import datetime, timedelta, timezone
    customer.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    db_session.add(customer)
    db_session.commit()

    overdue = services.expire_overdue_customers(db_session, ppp=None, static_mgr=static_mgr)
    assert len(overdue) == 1
    assert overdue[0].pppoe_username == "static-bob"
    assert overdue[0].status == CustomerStatus.expired
    assert static_mgr.is_suspended("192.168.88.51") is True


def test_repeater_pool_customer_lifecycle(db_session, sample_plan):
    api = FakeApi()
    static_mgr = StaticUserManager(api)
    cidr = "192.168.88.48/29"

    # Create repeater customer with /29 subnet pool
    customer = services.create_customer(
        db_session,
        ppp=None,
        pppoe_username="repeater-family",
        full_name="Family HG8546M",
        phone_number="+254700112233",
        plan=sample_plan,
        connection_type=ConnectionType.static,
        static_ip=cidr,
        no_expiry=False,
        static_mgr=static_mgr,
    )

    assert customer.status == CustomerStatus.expired
    assert customer.static_ip == cidr

    # Queue created with CIDR target
    queue = static_mgr.get_queue("repeater-family")
    assert queue is not None
    assert queue.target == cidr
    assert queue.max_limit == "4M/4M"

    # Subnet is suspended on router
    assert static_mgr.is_suspended(cidr) is True

    # Record payment activates and restores subnet
    services.record_payment(
        db_session,
        ppp=None,
        customer=customer,
        amount_kes=Decimal("1500.00"),
        mpesa_receipt="RC987654",
        phone_number="+254700112233",
        static_mgr=static_mgr,
    )

    assert customer.status == CustomerStatus.active
    assert static_mgr.is_suspended(cidr) is False

    # Simulate expiry in the past
    from datetime import datetime, timedelta, timezone
    customer.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    db_session.add(customer)
    db_session.commit()

    overdue = services.expire_overdue_customers(db_session, ppp=None, static_mgr=static_mgr)
    assert len(overdue) == 1
    assert overdue[0].pppoe_username == "repeater-family"
    assert overdue[0].status == CustomerStatus.expired
    assert static_mgr.is_suspended(cidr) is True
