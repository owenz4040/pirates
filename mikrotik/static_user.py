"""Manage static IP users via RouterOS Simple Queues and Firewall Address Lists."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class SimpleQueue:
    """A bandwidth queue under /queue/simple."""

    id: str
    name: str
    target: str
    max_limit: str
    disabled: bool
    comment: Optional[str] = None

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "SimpleQueue":
        return cls(
            id=row[".id"],
            name=row["name"],
            target=row.get("target", ""),
            max_limit=row.get("max-limit", ""),
            disabled=_as_bool(row.get("disabled", False)),
            comment=row.get("comment"),
        )


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "yes"}


def _normalize_target(ip_address: str) -> str:
    """Ensure target IP has a /32 mask if no CIDR is specified."""
    ip = ip_address.strip()
    if "/" not in ip:
        return f"{ip}/32"
    return ip


def _clean_address(target: str) -> str:
    """Normalize address for firewall address-list: keep CIDR intact (e.g. 192.168.88.48/29), or plain IP (e.g. 192.168.88.51)."""
    addr = target.strip()
    if addr.endswith("/32"):
        return addr[:-3]
    return addr


def _matches_address(entry_addr: str, target: str) -> bool:
    clean_target = _clean_address(target)
    clean_entry = _clean_address(entry_addr)
    return clean_entry == clean_target


class StaticUserManager:
    """
    Manage static subscribers on RouterOS.

    Static users do not dial in over PPPoE, so they don't have secrets or dynamic
    sessions. Instead:
    - Bandwidth is shaped using Simple Queues (/queue/simple).
    - Suspension/expiry is enforced by adding their IP or subnet to a Firewall Address List
      (/ip/firewall/address-list) named 'suspended-users' (which has a corresponding
      'chain=forward action=drop' filter rule on the router).
    """

    def __init__(self, api: Any) -> None:
        self._queues = api.path("queue", "simple")
        self._address_list = api.path("ip", "firewall", "address-list")

    def list_queues(self) -> list[SimpleQueue]:
        return [SimpleQueue.from_row(row) for row in self._queues]

    def get_queue(self, name: str) -> SimpleQueue | None:
        for row in self._queues:
            if row["name"] == name:
                return SimpleQueue.from_row(row)
        return None

    def create_or_update_queue(
        self,
        name: str,
        target_ip: str,
        rate_limit: str,
        *,
        comment: str | None = None,
    ) -> SimpleQueue:
        """Create the simple queue if missing, or update target/rate-limit if it already exists."""
        target = _normalize_target(target_ip)
        existing = self.get_queue(name)
        kwargs: dict[str, Any] = {
            "target": target,
            "max-limit": rate_limit,
        }
        if comment is not None:
            kwargs["comment"] = comment

        if existing is None:
            self._queues.add(name=name, **kwargs)
        else:
            self._queues.update(**{".id": existing.id, **kwargs})

        queue = self.get_queue(name)
        assert queue is not None
        return queue

    def delete_queue(self, name: str) -> None:
        """Remove a subscriber's simple queue."""
        queue = self.get_queue(name)
        if queue is not None:
            self._queues.remove(queue.id)

    def set_bandwidth(self, name: str, rate_limit: str) -> None:
        """Update the max-limit rate for an existing simple queue."""
        queue = self.get_queue(name)
        if queue is None:
            raise LookupError(f"No simple queue named {name!r}")
        self._queues.update(**{".id": queue.id, "max-limit": rate_limit})

    def suspend_user(
        self,
        target_ip: str,
        *,
        list_name: str = "suspended-users",
        comment: str | None = None,
    ) -> None:
        """
        Add the user's IP or subnet CIDR to the suspended firewall address-list.
        Idempotent - does nothing if the IP/subnet is already listed.
        """
        clean_addr = _clean_address(target_ip)
        for row in self._address_list:
            if row.get("list") == list_name and _matches_address(row.get("address", ""), clean_addr):
                return  # already in address list

        kwargs: dict[str, Any] = {"list": list_name, "address": clean_addr}
        if comment:
            kwargs["comment"] = comment
        self._address_list.add(**kwargs)

    def restore_user(self, target_ip: str, *, list_name: str = "suspended-users") -> None:
        """
        Remove the user's IP or subnet CIDR from the suspended firewall address-list so traffic is allowed.
        Idempotent - does nothing if the IP/subnet is not in the list.
        """
        clean_addr = _clean_address(target_ip)
        ids_to_remove = [
            row[".id"]
            for row in self._address_list
            if row.get("list") == list_name and _matches_address(row.get("address", ""), clean_addr)
        ]
        for item_id in ids_to_remove:
            self._address_list.remove(item_id)

    def is_suspended(self, target_ip: str, *, list_name: str = "suspended-users") -> bool:
        """Check if an IP or subnet CIDR is currently listed in the suspended address-list."""
        clean_addr = _clean_address(target_ip)
        return any(
            row.get("list") == list_name and _matches_address(row.get("address", ""), clean_addr)
            for row in self._address_list
        )

    def list_suspended_ips(self, *, list_name: str = "suspended-users") -> set[str]:
        """Fetch all suspended IPs/subnets in a single query."""
        return {
            _clean_address(row.get("address", ""))
            for row in self._address_list
            if row.get("list") == list_name and row.get("address")
        }
