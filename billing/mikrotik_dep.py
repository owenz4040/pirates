"""FastAPI dependency that opens one router connection per request."""

from __future__ import annotations

from collections.abc import Iterator

from librouteros.api import Api

from mikrotik.client import router_connection


def get_router_api() -> Iterator[Api]:
    with router_connection() as api:
        yield api
