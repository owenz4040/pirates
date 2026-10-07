"""
RouterOS script generators with the same interface as the live managers.

The billing app runs on Vercel, which can't hold a connection to the router.
Instead of calling the RouterOS API, these managers turn each action into a
small RouterOS script line and hand it to a sink (the billing app's command
queue). The router pulls and runs those lines itself - see billing/router_sync.

Every generated line is idempotent (`find`-based, add-if-missing), so running
it twice - e.g. the router ran it but its acknowledgement got lost - is safe.
"""

from __future__ import annotations

import re
from typing import Protocol

from mikrotik.static_user import _clean_address, _normalize_target


class ScriptSink(Protocol):
    def add(self, description: str, script: str) -> None: ...


_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def quote(value: str) -> str:
    """Quote a value as a RouterOS string literal. `$` must be escaped or RouterOS expands it as a variable."""
    text = _CONTROL_CHARS.sub(" ", str(value))
    text = text.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
    return f'"{text}"'


def _upsert(path: str, key: str, key_value: str, add_args: str, set_args: str) -> str:
    match = f"{key}={quote(key_value)}"
    return (
        f":if ([:len [{path} find where {match}]] = 0) "
        f"do={{{path} add {match} {add_args}}} "
        f"else={{{path} set [find where {match}] {set_args}}}"
    )


class ScriptPPPoEManager:
    """Queues /ppp secret changes. Mirrors mikrotik.pppoe.PPPoEManager."""

    def __init__(self, sink: ScriptSink) -> None:
        self._sink = sink

    def create_secret(
        self,
        username: str,
        password: str,
        profile: str = "default",
        *,
        service: str = "pppoe",
        comment: str | None = None,
    ) -> None:
        common = f"profile={quote(profile)}"
        if password:
            common = f"password={quote(password)} {common}"
        if comment is not None:
            common += f" comment={quote(comment)}"
        self._sink.add(
            f"Create PPPoE account {username}",
            _upsert("/ppp secret", "name", username, f"service={service} {common}", common),
        )

    def delete_secret(self, username: str) -> None:
        name = quote(username)
        self._sink.add(
            f"Delete PPPoE account {username}",
            f"/ppp active remove [find where name={name}]; /ppp secret remove [find where name={name}]",
        )

    def disable_user(self, username: str) -> None:
        name = quote(username)
        self._sink.add(
            f"Disable PPPoE user {username}",
            f"/ppp secret set [find where name={name}] disabled=yes; /ppp active remove [find where name={name}]",
        )

    def enable_user(self, username: str) -> None:
        self._sink.add(
            f"Enable PPPoE user {username}",
            f"/ppp secret set [find where name={quote(username)}] disabled=no",
        )

    def set_profile(self, username: str, profile: str, *, force_reconnect: bool = True) -> None:
        name = quote(username)
        script = f"/ppp secret set [find where name={name}] profile={quote(profile)}"
        if force_reconnect:
            # Profile changes only apply on the next session, so kick the live one.
            script += f"; /ppp active remove [find where name={name}]"
        self._sink.add(f"Move {username} to profile {profile}", script)


class ScriptStaticUserManager:
    """Queues simple-queue and address-list changes. Mirrors mikrotik.static_user.StaticUserManager."""

    def __init__(self, sink: ScriptSink) -> None:
        self._sink = sink

    def create_or_update_queue(
        self,
        name: str,
        target_ip: str,
        rate_limit: str,
        *,
        comment: str | None = None,
    ) -> None:
        args = f"target={quote(_normalize_target(target_ip))} max-limit={quote(rate_limit)}"
        if comment is not None:
            args += f" comment={quote(comment)}"
        self._sink.add(f"Set up queue {name} ({target_ip}, {rate_limit})", _upsert("/queue simple", "name", name, args, args))

    def delete_queue(self, name: str) -> None:
        self._sink.add(f"Delete queue {name}", f"/queue simple remove [find where name={quote(name)}]")

    def set_bandwidth(self, name: str, rate_limit: str) -> None:
        self._sink.add(
            f"Set queue {name} to {rate_limit}",
            f"/queue simple set [find where name={quote(name)}] max-limit={quote(rate_limit)}",
        )

    def suspend_user(
        self,
        target_ip: str,
        *,
        list_name: str = "suspended-users",
        comment: str | None = None,
    ) -> None:
        addr = _clean_address(target_ip)
        match = f"list={quote(list_name)} address={quote(addr)}"
        add = f"/ip firewall address-list add {match}"
        if comment:
            add += f" comment={quote(comment)}"
        self._sink.add(
            f"Suspend static IP {addr}",
            f":if ([:len [/ip firewall address-list find where list={quote(list_name)} and address={quote(addr)}]] = 0) do={{{add}}}",
        )

    def restore_user(self, target_ip: str, *, list_name: str = "suspended-users") -> None:
        addr = _clean_address(target_ip)
        self._sink.add(
            f"Restore static IP {addr}",
            f"/ip firewall address-list remove [find where list={quote(list_name)} and address={quote(addr)}]",
        )


class ScriptBandwidthProfileManager:
    """Queues /ppp profile changes. Mirrors mikrotik.bandwidth.BandwidthProfileManager."""

    def __init__(self, sink: ScriptSink) -> None:
        self._sink = sink

    def ensure_profile(self, name: str, rate_limit: str) -> None:
        args = f"rate-limit={quote(rate_limit)}"
        self._sink.add(f"Set up profile {name} ({rate_limit})", _upsert("/ppp profile", "name", name, args, args))

    def set_rate_limit(self, name: str, rate_limit: str) -> None:
        self._sink.add(
            f"Set profile {name} to {rate_limit}",
            f"/ppp profile set [find where name={quote(name)}] rate-limit={quote(rate_limit)}",
        )

    def rename_profile(self, name: str, new_name: str) -> None:
        self._sink.add(
            f"Rename profile {name} to {new_name}",
            f"/ppp profile set [find where name={quote(name)}] name={quote(new_name)}",
        )

    def delete_profile(self, name: str) -> None:
        self._sink.add(f"Delete profile {name}", f"/ppp profile remove [find where name={quote(name)}]")
