from __future__ import annotations

import pytest

from mikrotik.pppoe import PPPoEManager
from tests.fake_router import FakeApi


def make_manager(secrets=None, active=None) -> tuple[PPPoEManager, FakeApi]:
    api = FakeApi()
    api.seed("ppp", "secret", rows=secrets or [])
    api.seed("ppp", "active", rows=active or [])
    return PPPoEManager(api), api


def test_list_secrets_parses_disabled_flag():
    manager, _ = make_manager(
        secrets=[
            {"name": "alice", "profile": "10mbps", "disabled": "false"},
            {"name": "bob", "profile": "default", "disabled": "true"},
        ]
    )
    secrets = {s.name: s for s in manager.list_secrets()}
    assert secrets["alice"].disabled is False
    assert secrets["bob"].disabled is True


def test_get_secret_missing_raises():
    manager, _ = make_manager()
    with pytest.raises(LookupError):
        manager.get_secret("nobody")


def test_disable_user_disables_secret_and_drops_active_session():
    manager, _ = make_manager(
        secrets=[{"name": "alice", "profile": "10mbps", "disabled": "false"}],
        active=[{"name": "alice", "address": "10.0.0.5"}],
    )

    manager.disable_user("alice")

    assert manager.get_secret("alice").disabled is True
    assert manager.is_online("alice") is False


def test_disable_user_without_active_session_does_not_raise():
    manager, _ = make_manager(secrets=[{"name": "alice", "profile": "10mbps", "disabled": "false"}])
    manager.disable_user("alice")
    assert manager.get_secret("alice").disabled is True


def test_enable_user_clears_disabled_flag():
    manager, _ = make_manager(secrets=[{"name": "alice", "profile": "10mbps", "disabled": "true"}])
    manager.enable_user("alice")
    assert manager.get_secret("alice").disabled is False


def test_set_profile_updates_secret_and_kicks_active_session():
    manager, _ = make_manager(
        secrets=[{"name": "alice", "profile": "5mbps", "disabled": "false"}],
        active=[{"name": "alice", "address": "10.0.0.5"}],
    )

    manager.set_profile("alice", "20mbps")

    assert manager.get_secret("alice").profile == "20mbps"
    assert manager.is_online("alice") is False


def test_set_profile_without_force_reconnect_keeps_session_alive():
    manager, _ = make_manager(
        secrets=[{"name": "alice", "profile": "5mbps", "disabled": "false"}],
        active=[{"name": "alice", "address": "10.0.0.5"}],
    )

    manager.set_profile("alice", "20mbps", force_reconnect=False)

    assert manager.is_online("alice") is True


def test_create_secret_then_get_secret_round_trips():
    manager, _ = make_manager()
    manager.create_secret("carol", "hunter2", profile="5mbps", comment="new signup")
    secret = manager.get_secret("carol")
    assert secret.profile == "5mbps"
    assert secret.comment == "new signup"
    assert secret.disabled is False


def test_delete_secret_removes_secret_and_active_session():
    manager, _ = make_manager(
        secrets=[{"name": "alice", "profile": "10mbps", "disabled": "false"}],
        active=[{"name": "alice", "address": "10.0.0.5"}],
    )

    manager.delete_secret("alice")

    with pytest.raises(LookupError):
        manager.get_secret("alice")
    assert manager.is_online("alice") is False
