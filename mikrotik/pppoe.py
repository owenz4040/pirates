"""Manage PPPoE accounts (secrets) and their live sessions on RouterOS."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class PPPoESecret:
    """A PPPoE account as configured under /ppp/secret."""

    id: str
    name: str
    profile: str
    disabled: bool
    comment: Optional[str] = None

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "PPPoESecret":
        return cls(
            id=row[".id"],
            name=row["name"],
            profile=row.get("profile", "default"),
            disabled=_as_bool(row.get("disabled", False)),
            comment=row.get("comment"),
        )


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "yes"}


class PPPoEManager:
    """
    Manage PPPoE secrets and their active sessions.

    Disabling a secret only blocks *future* dial-ins - a user who is already
    connected stays connected until their session drops on its own. So
    suspending someone always disables the secret *and* removes any matching
    row from /ppp/active to force an immediate disconnect.
    """

    def __init__(self, api: Any) -> None:
        self._secrets = api.path("ppp", "secret")
        self._active = api.path("ppp", "active")

    def list_secrets(self) -> list[PPPoESecret]:
        return [PPPoESecret.from_row(row) for row in self._secrets]

    def get_secret(self, username: str) -> PPPoESecret:
        for row in self._secrets:
            if row["name"] == username:
                return PPPoESecret.from_row(row)
        raise LookupError(f"No PPPoE secret named {username!r}")

    def create_secret(
        self,
        username: str,
        password: str,
        profile: str = "default",
        *,
        service: str = "pppoe",
        comment: str | None = None,
    ) -> PPPoESecret:
        kwargs: dict[str, Any] = {
            "name": username,
            "password": password,
            "profile": profile,
            "service": service,
        }
        if comment is not None:
            kwargs["comment"] = comment
        self._secrets.add(**kwargs)
        return self.get_secret(username)

    def delete_secret(self, username: str) -> None:
        """Permanently remove a PPPoE account (e.g. cancelled/test customers), dropping any live session first."""
        secret = self.get_secret(username)
        self._drop_active_session(username)
        self._secrets.remove(secret.id)

    def disable_user(self, username: str) -> None:
        """Suspend a user: disable their secret and drop any live session now."""
        secret = self.get_secret(username)
        self._secrets.update(**{".id": secret.id, "disabled": "yes"})
        self._drop_active_session(username)

    def enable_user(self, username: str) -> None:
        """Reinstate a suspended user so they can dial in again."""
        secret = self.get_secret(username)
        self._secrets.update(**{".id": secret.id, "disabled": "no"})

    def set_profile(self, username: str, profile: str, *, force_reconnect: bool = True) -> None:
        """
        Move a user to a different PPP profile, e.g. to change their bandwidth tier.

        A profile change only applies on the user's *next* session, so by
        default this also kicks any live session so the new rate-limit takes
        effect immediately (the client's PPPoE dialer normally redials on its
        own within seconds).
        """
        secret = self.get_secret(username)
        self._secrets.update(**{".id": secret.id, "profile": profile})
        if force_reconnect:
            self._drop_active_session(username)

    def is_online(self, username: str) -> bool:
        return self._find_active_id(username) is not None

    def list_active_sessions(self) -> list[dict[str, Any]]:
        return list(self._active)

    def _find_active_id(self, username: str) -> str | None:
        for row in self._active:
            if row["name"] == username:
                return row[".id"]
        return None

    def _drop_active_session(self, username: str) -> None:
        active_id = self._find_active_id(username)
        if active_id is not None:
            self._active.remove(active_id)
