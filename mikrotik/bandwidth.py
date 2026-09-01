"""Manage PPP profiles used as bandwidth tiers (e.g. "5mbps", "10mbps")."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class BandwidthProfile:
    id: str
    name: str
    rate_limit: Optional[str]

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "BandwidthProfile":
        return cls(id=row[".id"], name=row["name"], rate_limit=row.get("rate-limit"))


class BandwidthProfileManager:
    """
    Manage /ppp/profile entries used as bandwidth tiers.

    RouterOS rate-limit format is "rx-rate/tx-rate", where rx is the rate the
    router *receives from* the client (their upload) and tx is what it *sends
    to* the client (their download). A single value like "10M" applies to
    both directions. To change a specific user's speed, either point their
    secret at a different tier profile (PPPoEManager.set_profile) or, if the
    tier itself needs adjusting for everyone on it, use set_rate_limit here.
    """

    def __init__(self, api: Any) -> None:
        self._profiles = api.path("ppp", "profile")

    def list_profiles(self) -> list[BandwidthProfile]:
        return [BandwidthProfile.from_row(row) for row in self._profiles]

    def get_profile(self, name: str) -> BandwidthProfile | None:
        for row in self._profiles:
            if row["name"] == name:
                return BandwidthProfile.from_row(row)
        return None

    def ensure_profile(self, name: str, rate_limit: str) -> BandwidthProfile:
        """Create the tier if missing, or update its rate-limit if it already exists."""
        existing = self.get_profile(name)
        if existing is None:
            self._profiles.add(name=name, **{"rate-limit": rate_limit})
        elif existing.rate_limit != rate_limit:
            self._profiles.update(**{".id": existing.id, "rate-limit": rate_limit})
        profile = self.get_profile(name)
        assert profile is not None
        return profile

    def set_rate_limit(self, name: str, rate_limit: str) -> None:
        profile = self.get_profile(name)
        if profile is None:
            raise LookupError(f"No PPP profile named {name!r}")
        self._profiles.update(**{".id": profile.id, "rate-limit": rate_limit})

    def rename_profile(self, name: str, new_name: str) -> None:
        """
        Rename a profile in place (same internal .id). RouterOS secrets that
        reference it by name are resolved via that internal id, so they keep
        working under the new name automatically - verified live.
        """
        profile = self.get_profile(name)
        if profile is None:
            raise LookupError(f"No PPP profile named {name!r}")
        self._profiles.update(**{".id": profile.id, "name": new_name})

    def delete_profile(self, name: str) -> None:
        profile = self.get_profile(name)
        if profile is None:
            raise LookupError(f"No PPP profile named {name!r}")
        self._profiles.remove(profile.id)
