"""
An in-memory stand-in for librouteros' Api/Path objects, covering just the
methods mikrotik.pppoe and mikrotik.bandwidth actually call (__iter__, add,
update, remove). Lets the manager classes be tested without a real router.
"""

from __future__ import annotations

import itertools
from typing import Any


class FakePath:
    def __init__(self, rows: list[dict[str, Any]], id_counter: itertools.count) -> None:
        self._rows = rows
        self._id_counter = id_counter

    def __iter__(self):
        return iter(list(self._rows))

    def add(self, **kwargs: Any) -> str:
        new_id = f"*{next(self._id_counter)}"
        self._rows.append({".id": new_id, **kwargs})
        return new_id

    def update(self, **kwargs: Any) -> None:
        row_id = kwargs.pop(".id")
        for row in self._rows:
            if row[".id"] == row_id:
                row.update(kwargs)
                return
        raise LookupError(row_id)

    def remove(self, *ids: str) -> None:
        self._rows[:] = [row for row in self._rows if row[".id"] not in ids]


class FakeApi:
    def __init__(self) -> None:
        self._id_counter = itertools.count(1)
        self.tables: dict[tuple[str, ...], list[dict[str, Any]]] = {}

    def seed(self, *path: str, rows: list[dict[str, Any]]) -> None:
        for row in rows:
            row.setdefault(".id", f"*{next(self._id_counter)}")
        self.tables[path] = rows

    def path(self, *path: str) -> FakePath:
        rows = self.tables.setdefault(path, [])
        return FakePath(rows, self._id_counter)
