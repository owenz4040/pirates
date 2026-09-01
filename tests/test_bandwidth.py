from __future__ import annotations

import pytest

from mikrotik.bandwidth import BandwidthProfileManager
from tests.fake_router import FakeApi


def make_manager(profiles=None) -> tuple[BandwidthProfileManager, FakeApi]:
    api = FakeApi()
    api.seed("ppp", "profile", rows=profiles or [])
    return BandwidthProfileManager(api), api


def test_ensure_profile_creates_when_missing():
    manager, _ = make_manager()
    profile = manager.ensure_profile("10mbps", "10M/10M")
    assert profile.name == "10mbps"
    assert profile.rate_limit == "10M/10M"


def test_ensure_profile_updates_existing_rate_limit():
    manager, _ = make_manager(profiles=[{"name": "10mbps", "rate-limit": "5M/5M"}])
    profile = manager.ensure_profile("10mbps", "10M/10M")
    assert profile.rate_limit == "10M/10M"
    assert len(manager.list_profiles()) == 1


def test_ensure_profile_is_noop_when_unchanged():
    manager, api = make_manager(profiles=[{"name": "10mbps", "rate-limit": "10M/10M"}])
    manager.ensure_profile("10mbps", "10M/10M")
    assert len(api.tables[("ppp", "profile")]) == 1


def test_set_rate_limit_updates_matching_profile():
    manager, _ = make_manager(profiles=[{"name": "10mbps", "rate-limit": "10M/10M"}])
    manager.set_rate_limit("10mbps", "20M/20M")
    assert manager.get_profile("10mbps").rate_limit == "20M/20M"


def test_set_rate_limit_missing_profile_raises():
    manager, _ = make_manager()
    with pytest.raises(LookupError):
        manager.set_rate_limit("nope", "1M/1M")


def test_delete_profile_removes_it():
    manager, _ = make_manager(profiles=[{"name": "10mbps", "rate-limit": "10M/10M"}])
    manager.delete_profile("10mbps")
    assert manager.get_profile("10mbps") is None


def test_delete_profile_missing_raises():
    manager, _ = make_manager()
    with pytest.raises(LookupError):
        manager.delete_profile("nope")
