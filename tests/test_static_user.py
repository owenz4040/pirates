from __future__ import annotations

import pytest

from mikrotik.static_user import StaticUserManager
from tests.fake_router import FakeApi


def make_manager(queues=None, address_list=None) -> tuple[StaticUserManager, FakeApi]:
    api = FakeApi()
    api.seed("queue", "simple", rows=queues or [])
    api.seed("ip", "firewall", "address-list", rows=address_list or [])
    return StaticUserManager(api), api


def test_create_simple_queue_with_default_slash_32():
    manager, _ = make_manager()
    queue = manager.create_or_update_queue("Pirate-Static-01", "192.168.88.50", "4M/4M", comment="John Doe")
    assert queue.name == "Pirate-Static-01"
    assert queue.target == "192.168.88.50/32"
    assert queue.max_limit == "4M/4M"
    assert queue.comment == "John Doe"


def test_update_existing_simple_queue_rate_limit():
    manager, _ = make_manager(
        queues=[{"name": "Pirate-Static-01", "target": "192.168.88.50/32", "max-limit": "4M/4M"}]
    )
    updated = manager.create_or_update_queue("Pirate-Static-01", "192.168.88.50", "8M/8M")
    assert updated.max_limit == "8M/8M"


def test_set_bandwidth():
    manager, _ = make_manager(
        queues=[{"name": "Pirate-Static-01", "target": "192.168.88.50/32", "max-limit": "4M/4M"}]
    )
    manager.set_bandwidth("Pirate-Static-01", "10M/10M")
    queue = manager.get_queue("Pirate-Static-01")
    assert queue is not None
    assert queue.max_limit == "10M/10M"


def test_set_bandwidth_missing_queue_raises():
    manager, _ = make_manager()
    with pytest.raises(LookupError):
        manager.set_bandwidth("nobody", "10M/10M")


def test_delete_queue():
    manager, _ = make_manager(
        queues=[{"name": "Pirate-Static-01", "target": "192.168.88.50/32", "max-limit": "4M/4M"}]
    )
    manager.delete_queue("Pirate-Static-01")
    assert manager.get_queue("Pirate-Static-01") is None


def test_suspend_user_adds_to_address_list_and_is_idempotent():
    manager, api = make_manager()
    assert manager.is_suspended("192.168.88.50") is False

    manager.suspend_user("192.168.88.50", comment="Expired")
    assert manager.is_suspended("192.168.88.50") is True

    # Idempotency check: suspending again shouldn't add duplicate entries
    manager.suspend_user("192.168.88.50")
    entries = [
        row for row in api.path("ip", "firewall", "address-list")
        if row.get("address") == "192.168.88.50" and row.get("list") == "suspended-users"
    ]
    assert len(entries) == 1


def test_restore_user_removes_from_address_list_and_is_idempotent():
    manager, _ = make_manager(
        address_list=[{"list": "suspended-users", "address": "192.168.88.50"}]
    )
    assert manager.is_suspended("192.168.88.50") is True

    manager.restore_user("192.168.88.50")
    assert manager.is_suspended("192.168.88.50") is False

    # Calling restore again shouldn't raise
    manager.restore_user("192.168.88.50")
    assert manager.is_suspended("192.168.88.50") is False


def test_create_simple_queue_with_cidr_subnet():
    manager, _ = make_manager()
    queue = manager.create_or_update_queue("Pirate-Repeater-01", "192.168.88.48/29", "4M/4M", comment="HG8546M Household")
    assert queue.name == "Pirate-Repeater-01"
    assert queue.target == "192.168.88.48/29"
    assert queue.max_limit == "4M/4M"
    assert queue.comment == "HG8546M Household"


def test_suspend_and_restore_cidr_subnet():
    manager, api = make_manager()
    cidr = "192.168.88.48/29"
    assert manager.is_suspended(cidr) is False

    manager.suspend_user(cidr, comment="HG8546M Household Expired")
    assert manager.is_suspended(cidr) is True

    # Check that the address-list entry preserved the /29
    entries = [
        row for row in api.path("ip", "firewall", "address-list")
        if row.get("address") == cidr and row.get("list") == "suspended-users"
    ]
    assert len(entries) == 1

    # Idempotency check: suspending again shouldn't duplicate
    manager.suspend_user(cidr)
    entries = [
        row for row in api.path("ip", "firewall", "address-list")
        if row.get("address") == cidr and row.get("list") == "suspended-users"
    ]
    assert len(entries) == 1

    # Restore
    manager.restore_user(cidr)
    assert manager.is_suspended(cidr) is False
