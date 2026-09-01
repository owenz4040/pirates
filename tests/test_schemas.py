from __future__ import annotations

import pytest

from billing.schemas import _normalize_kenyan_phone


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("0703551813", "+254703551813"),
        ("254703551813", "+254703551813"),
        ("+254703551813", "+254703551813"),
        (" 0703551813 ", "+254703551813"),
    ],
)
def test_normalize_kenyan_phone_accepts_common_formats(raw, expected):
    assert _normalize_kenyan_phone(raw) == expected


def test_normalize_kenyan_phone_rejects_garbage():
    with pytest.raises(ValueError):
        _normalize_kenyan_phone("not-a-phone-number")
